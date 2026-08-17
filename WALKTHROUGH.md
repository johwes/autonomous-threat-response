# Incident Walkthrough: Specification Deviation Detection

This document walks through a real incident captured in `example-incident-log.json`,
explaining the attack, the detection logic, and why the outcome demonstrates something
beyond conventional threat detection.

The goal is to help a reader understand what "specification deviation signal" means —
and why the distinction matters for a class of attacks that conventional defenses are
structurally unable to detect.

---

## The Attack: Copy Fail (CVE-2026-31431)

The attacker is logged in as `cloud-user` — a low-privilege account — on the RHEL 9 host.
They run a Python exploit that abuses the Linux kernel's AF_ALG cryptographic interface.

The exploit does the following:

1. Opens an `AF_ALG` socket (the kernel's in-kernel crypto API)
2. Uses `splice()` to copy pages from `/usr/bin/su` into the crypto socket's buffer
3. Through a logic flaw in the kernel's page cache reference counting, the splice
   corrupts the in-memory (page cache) copy of `/usr/bin/su`
4. When the corrupted binary is next invoked, it `execve()`-replaces itself with `/bin/sh`
   running as root — because `su` is a setuid binary

**The critical detail**: the on-disk file `/usr/bin/su` is never touched. Two versions
of the binary coexist after the exploit runs:

- **On disk**: the clean, original binary — bytes unchanged, hash unchanged
- **In memory (kernel page cache)**: the corrupted version that spawns a root shell

The operating system serves the in-memory version when the binary is executed, because
the page cache is the kernel's read cache for files — it does not re-read from disk if
the page is already in memory. The exploit deliberately exploits this: corrupt the
cached copy, leave the on-disk copy untouched.

This design makes the attack invisible to any security tool that works by reading files
from disk — which is most of them.

---

## Why We Run sha256sum and rpm -V: Proving the Blindness

Before the agent classifies the alert or takes any remediation action, it runs three
checks that a typical security team would reach for when investigating a potential
privilege escalation:

```
stat /usr/bin/su && sha256sum /usr/bin/su
rpm -V shadow-utils
getenforce
```

These are not run to detect the attack. The attack has already been detected — by the
Falco rule firing. These checks are run to prove, with concrete evidence, that the
conventional approach to detection was structurally blind to this attack. The results
are recorded in the incident report as `conventional_methods_bypassed`.

Understanding why each check fails is essential to understanding what "specification
deviation" means and why it is a different kind of signal.

### Check 1: SHA256 hash of /usr/bin/su

```
sha256sum /usr/bin/su
→ 5caff5036909df3c2d8baca06c9d4039693fcba9d3aaf62a7be8b3b09a59acbf  /usr/bin/su
```

A SHA256 hash is the foundation of file integrity monitoring. The idea is: compute
the hash of a known-good binary, store it, and alarm if the hash changes. Tools like
AIDE, Tripwire, and most EDR products use this approach.

In this incident, the hash comes back matching the known-good binary. The on-disk file
is exactly what Red Hat shipped. The hash is clean.

**Why this fails here**: `sha256sum` reads from disk. The kernel page cache — the
in-memory version of the file — is not visible to `sha256sum`. The exploit corrupted
the page cache copy, not the disk copy. So the hash check reads the clean on-disk binary
and reports nothing wrong. File integrity monitoring is structurally incapable of
detecting page cache corruption — not because it is poorly implemented, but because it
reads the wrong copy of the file.

The SHA256 hash in the incident report is not a detection signal. It is evidence that
the standard detection mechanism had no signal to give.

### Check 2: RPM package verification

```
rpm -V shadow-utils
→ (no output, exit code 0)
```

`rpm -V` is a stronger check than a standalone hash. The RPM database records the
expected hash, size, permissions, ownership, and modification time for every file
in every installed package — as shipped by Red Hat. `rpm -V shadow-utils` checks
the actual on-disk files for the `shadow-utils` package (which owns `/usr/bin/su`)
against that database.

No output and exit code 0 means: every file in the package matches exactly what
Red Hat shipped. The on-disk binary is authenticated against the package maintainer's
own database.

**Why this fails here**: `rpm -V` also reads from disk. The RPM database contains the
expected hash of the on-disk file, and the on-disk file is correct. The exploit did not
touch the on-disk file, so the RPM database matches. `rpm -V` is the most authoritative
possible answer to the question "is this file what Red Hat shipped?" — and the answer
is yes. The attack still succeeded, because the attack never modified the file that
`rpm -V` checks.

The clean `rpm -V` result is the strongest possible statement that conventional
package-integrity verification is blind to this class of attack.

### Check 3: SELinux enforcement status

```
getenforce
→ Enforcing
```

SELinux is running in enforcing mode. This is the expected state on a hardened RHEL
system — SELinux enforcing mode means the kernel's Mandatory Access Control policy is
active and blocking unauthorized operations.

Many security teams would expect SELinux enforcing mode to catch or block a privilege
escalation of this kind.

**Why this fails here**: SELinux enforces policy at the syscall boundary — it intercepts
`execve()`, `open()`, `connect()`, and other syscalls, and checks them against the
declared policy. But the page cache corruption happens at the kernel memory management
layer, *before* `execve()` is called. By the time `execve()` fires and SELinux can
check the calling process, the corruption is already done. SELinux sees a legitimate
`execve()` of a binary with the correct SELinux label (`su_exec_t`). It has no
visibility into the fact that the in-memory binary has been tampered with.

SELinux enforcing mode did not block this attack because the attack happened below
the layer where SELinux operates.

### What these three results mean together

At the moment the exploit runs:

| Check | Result | Why |
|-------|--------|-----|
| `sha256sum /usr/bin/su` | Hash matches — clean | Reads on-disk binary; exploit only corrupted page cache |
| `rpm -V shadow-utils` | All files match — clean | Reads on-disk binary against RPM database; same reason |
| `getenforce` | Enforcing | SELinux active but operates above the layer the exploit targets |

Three green lights. No signal from any conventional defense. If the investigation had
stopped here, the conclusion would be: the system is clean.

This is the structural blind spot. Not a misconfiguration, not a missing patch, not a
gap that a better tool would close. These three checks are fundamentally incapable of
detecting page cache corruption, because they all read on-disk state and the attack
never touched on-disk state.

---

## The Specification That Detected It

While the conventional checks return clean, Falco fires a CRITICAL alert at the
moment the root shell spawns:

```
Root shell spawned directly by user shell — RHEL process ancestry invariant violated
(user=root uid=0 pid=3665 ppid=3423 comm=sh parent=bash cmdline=sh pcmdline=bash)
```

This rule does not check files. It does not compute hashes. It does not look for
known-bad signatures. It encodes a **behavioral invariant** — a fact about how RHEL
processes are supposed to be related to each other:

> In a correctly operating RHEL environment, privilege elevation always interposes
> `su` or `sudo` between a user shell and a root shell. A uid=0 shell whose direct
> parent is a user-level interactive shell is architecturally impossible.

This invariant is derived from the declared specification of the RHEL software stack.
`su` and `sudo` are the two sanctioned privilege elevation paths. Both of them, by
design, become the direct parent of any root shell they spawn. There is no legitimate
operation in RHEL that produces a root shell whose parent is a plain user shell.

When a user legitimately runs `su`, the process tree looks like this:

```
bash (cloud-user, uid=1000)
  └── su (root, uid=0)          ← su always interposes here
        └── sh (root, uid=0)    ← root shell's parent is su, not bash
```

What the exploit produces is:

```
bash (cloud-user, uid=1000)
  └── sh (root, uid=0)          ← root shell's parent is bash — this cannot happen
```

The corrupted `su` binary skips the normal privilege escalation path and spawns `sh`
directly via `execve()`. The parent of the root shell is the user's `bash` process.
This is the invariant violation — and it is the only signal that fired in this incident.

The rule fires not because Copy Fail is a known CVE, but because the process tree is
in a state that the RHEL specification declares impossible. Any exploit that achieves
root via the same execve()-replacement mechanism — including future CVEs with no
existing signature — would produce the same invariant violation and fire the same rule.

This is what **specification deviation detection** means: define the correct behavioral
envelope, instrument to detect deviations from it, and treat any deviation as a
high-confidence signal regardless of how the deviation was caused.

---

## Walking Through the Incident Log

With that context, every field in `example-incident-log.json` has a clear meaning.

---

```json
"incident_id": "510fdef5",
"rule": "Root Shell Spawned Directly by User Shell",
"host": "rhel9-brown-loon-92",
"verdict": "confirmed_threat",
"cve_ids": ["CVE-2026-31431"]
```

Falco's webhook fires the agent pipeline with the rule name, host, and process PIDs.
The LLM classifier (Node 3) identifies the CVE from the process ancestry pattern and
the journal logs. Verdict is `confirmed_threat`.

---

```json
"detection_method": "behavioral_specification_violation"
```

The agent records that detection came from a behavioral specification — not a signature,
not a hash, not a known-bad pattern. This field is always set by the spec_verify node
regardless of what the conventional checks find, because the Falco rule is always the
source of the detection signal.

---

```json
"conventional_methods_bypassed": [
  "File integrity check (/usr/bin/su): on-disk binary is present and readable — page cache corruption leaves no on-disk trace. File: /usr/bin/su\n  Size: 56936...\n5caff5036909df3c2d8baca06c9d4039693fcba9d3aaf62a7be8b3b09a59acbf  /usr/bin/su",
  "RPM package verification (rpm -V shadow-utils): all package files match the RPM database — on-disk binary is clean",
  "SELinux: enforcing mode active — but page cache corruption occurs before execve() fires, so the corruption is below the syscall layer SELinux monitors"
]
```

This is the output of Node 1b (`spec_verify`), which runs the three checks described
above via direct SSH to the host. The full `stat` output is included in the first entry —
inode, size, permissions, timestamps, SELinux file context — so that an analyst can
see exactly what the on-disk binary looks like: pristine, with correct ownership and
the correct SELinux label (`system_u:object_r:su_exec_t:s0`).

The SHA256 hash (`5caff503...`) embedded in that entry is the actual hash of the
on-disk binary at the time of the incident. It is not a detection signal. Its presence
in the report is a statement: *the hash check ran, returned this value, and found
nothing wrong*. The attack was invisible to it.

These three entries together answer the question a reviewer would ask: "Did you check
the file? Did you verify the package? Was SELinux running?" The answer to all three
is yes, and none of them produced a signal. The only signal came from the behavioral
specification.

---

```json
"evidence": [
  "Falco: ...Critical Root shell spawned directly by user shell...",
  "Root shell process: PID 3665, user=root, comm=sh, elapsed=00:05",
  "Parent process: PID 3423, user=cloud-user, comm=bash, elapsed=02:22"
]
```

Node 1 (`process_inspect`) retrieves the process details via linux-mcp-server.
PID 3665 is `sh` running as root (`uid=0`). Its parent, PID 3423, is `bash` running
as `cloud-user` (`uid=1000`). The parent has been alive for 2 minutes and 22 seconds —
this is the user's interactive login shell, not a transient subprocess. The process
ancestry invariant violation is confirmed directly in the live process table.

---

```json
"summary": "...Conventional integrity checks, including file hash
(5caff5036909df3c2d8baca06c9d4039693fcba9d3aaf62a7be8b3b09a59acbf for /usr/bin/su)
and RPM verification (rpm -V shadow-utils), returned clean, indicating that detection
was achieved exclusively via behavioral specification violation. The violated invariant,
enforced by the RHEL process ancestry, dictates that a root shell should never spawn
directly from a user shell without the intermediary of a su or sudo binary..."
```

The LLM (Node 5) is explicitly instructed to name both the clean conventional checks
and the violated invariant in its summary. The SHA256 hash of the on-disk binary
appears here — not as evidence of a problem, but as evidence of the absence of a
problem detectable by conventional means. The contrast is the point: the hash is clean,
`rpm -V` is clean, SELinux is enforcing, and detection was achieved exclusively via
the process ancestry specification.

---

```json
"actions_taken": [
  "drop_page_cache (job_id=48)",
  "kill_session (job_id=50)",
  "lock_user (job_id=51)"
]
```

Node 4 (`remediate`) deterministically launches three Ansible Automation Platform
playbooks — no LLM discretion involved:

- **drop_page_cache** (job 48): flushes the kernel page cache
  (`echo 3 > /proc/sys/vm/drop_caches`), forcing a reload of the clean on-disk binary.
  The in-memory corruption is neutralized — the next invocation of `/usr/bin/su` will
  load the clean binary from disk.
- **kill_session** (job 50): terminates the root shell process (PID 3665).
- **lock_user** (job 51): writes an audit record to `/var/log/security-incidents/`.

All three actions are pre-approved playbooks with known blast radius. The agent cannot
construct or execute arbitrary commands — every write action goes through AAP.

---

```json
"recommended_next_steps": [
  "Apply kernel patch for CVE-2026-31431 (Copy Fail page cache corruption)",
  "Review /var/log/security-incidents/ for the audit record written by lock_user playbook",
  "Rotate SSH keys and credentials for cloud-user",
  "Monitor host for re-exploitation attempts",
  "File incident ticket with forensic artifacts"
]
```

Deterministic next steps assembled by Python based on verdict and CVE IDs. These are
human-action items — the automated response has already neutralized the immediate threat.

---

## Why This Matters: The Two Detection Models

Every defense in this incident can be placed into one of two models.

**Open-world model** (conventional): everything is permitted unless it is known-bad.
A tool in this model maintains a list of bad signatures, bad hashes, or bad patterns,
and alarms when something matches. File integrity monitoring, antivirus, and EDR
signature scanning all work this way. The structural weakness is that anything not
yet on the list — a new CVE, a novel technique, a variant of a known attack — is
permitted through.

The three checks that returned clean in this incident are all open-world. They looked
for a changed file hash. The file hash did not change. No alarm.

**Closed-world model** (specification deviation): everything is denied unless it is
declared correct. A tool in this model maintains a specification of permitted behavior,
and alarms when observed behavior falls outside it. The structural strength is that
the specification covers all future attacks that produce the same behavioral deviation
— including ones that do not exist yet.

The Falco rule is closed-world. The RHEL process ancestry invariant is always true for
legitimate operations. Any violation — by any attack technique, known or unknown — fires
the rule.

The demo makes this contrast concrete: three open-world defenses, all clean; one
closed-world specification, violated. The incident report carries both results side
by side in `conventional_methods_bypassed` and `detection_method`, so that the
distinction is visible in the output, not just implicit in the architecture.

### Academic Foundations

This approach has a 30-year academic pedigree. The terminology and formal framework
were established in two foundational papers from the UC Davis research group:

- **Ko, Ruschitzka, Levitt** — *Automated Detection of Vulnerabilities in Privileged Programs by Execution Monitoring* (ACSAC 1994): established execution monitoring of setuid programs as a security primitive. The specific focus on setuid binaries — precisely the class of program exploited by Copy Fail — was the starting point of the formal model.

- **Ko, Fraser, Blackledge, Levitt** — *Execution Monitoring of Security-Critical Programs in Distributed Systems: A Specification-Based Approach* (IEEE S&P 1997): coined the term **specification-based intrusion detection** and distinguished it formally from two other models:
  - *Misuse detection* — match against signatures of known-bad behavior (what EDR does)
  - *Anomaly detection* — flag statistical deviation from learned normal (what ML-based tools do)
  - *Specification-based detection* — flag any deviation from a formal specification of correct behavior, regardless of whether the deviation matches any known attack

The 1997 paper's key insight: specification-based detection is independent of attacker
knowledge. A specification does not describe attacks. It describes correct operation.
Anything outside correct operation is flagged — including attacks that did not exist
when the specification was written.

This demo is a direct implementation of that 1997 model: the Falco rule is the
specification, the Falco alert is the deviation event, and the agent pipeline is
the response layer the paper described but could not fully implement in 1997.

**What changed between 1997 and now**: the practical barrier was always the
specification itself. The 1997 paper assumed specifications existed and focused on
the detection and response machinery. In practice, writing and maintaining accurate
behavioral specifications for general-purpose software was intractable — too expensive,
too brittle, too incomplete. The approach remained academically compelling but
operationally marginal.

Red Hat's position in 2026 is that the specifications now exist — not as hand-written
security artifacts, but as the natural output of the platform: SELinux policy is the
syscall and file-path specification. systemd unit files are the process ancestry
specification. RPM metadata is the file-integrity specification. NetworkPolicy is the
network socket specification. These were written to describe correct operation, not
to enable security monitoring. The security application is a consequence of their
existence and precision.

---

## Red Hat's Position

The reason the closed-world model is viable on RHEL and OpenShift is that Red Hat
ships the specifications. SELinux policy declares the permitted syscall profile for
every confined domain. systemd unit files declare the permitted filesystem, network,
and capability envelope for every service. RPM metadata declares the expected content
and integrity of every installed file. The process ancestry invariant is a consequence
of how `su`, `sudo`, and PAM are specified to behave.

These specifications already exist. They are not new artifacts created for security.
They are the formal descriptions of what the platform is supposed to do. Deviation
from them is a signal regardless of what caused the deviation.

The SELinux precedent is instructive. Red Hat shipped SELinux in permissive mode in
RHEL 4 — the policy was incomplete and noisy. Over several releases, investment in
tooling (`audit2allow`, policy generators, audit infrastructure) made enforcing mode
viable at scale. The methodology was: start with high-confidence invariants, tune the
policy using real workload data, and graduate to enforcement when false positives are
under control. The same methodology applies to behavioral specification detection.

The demo is a proof of concept for the response layer: a confirmed specification
violation triggers an autonomous agent that investigates, classifies, remediates, and
records — without human intervention, and without needing to know what attack produced
the violation.
