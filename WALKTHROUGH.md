# Incident Walkthrough: Specification Deviation Detection

This document walks through a real incident captured in `example-incident-log.json`,
explaining the attack, the detection logic, and why the outcome demonstrates something
beyond conventional threat detection.

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
of the binary exist simultaneously:

- **On disk**: the clean, original binary — bytes unchanged, hash matches the RPM database
- **In memory (kernel page cache)**: the corrupted version that spawns a root shell

This is what makes the attack invisible to an entire class of defenses.

---

## What Conventional Defenses See

When the exploit runs, three conventional defenses are checked. All three return clean.

### 1. File integrity check

```
stat /usr/bin/su && sha256sum /usr/bin/su
```

```
File: /usr/bin/su
  Size: 56936       Blocks: 112        IO Block: 4096   regular file
Device: fc04h/64516d  Inode: 16909316  Links: 1
Access: (4755/-rwsr-xr-x)  Uid: (0/root)   Gid: (0/root)
Context: system_u:object_r:su_exec_t:s0
Modify: 2026-01-19 05:52:55.000000000 -0500

5caff5036909df3c2d8baca06c9d4039693fcba9d3aaf62a7be8b3b09a59acbf  /usr/bin/su
```

The on-disk binary is intact. Correct size, correct permissions (`4755` = setuid root),
correct SELinux context (`su_exec_t`), unmodified timestamp. The SHA256 hash matches
the known-good binary. File integrity monitoring sees nothing wrong — because nothing
is wrong, on disk.

### 2. RPM package verification

```
rpm -V shadow-utils
```

No output, exit code 0. `rpm -V` checks every file in the `shadow-utils` package
against the RPM database — size, hash, permissions, ownership. Everything matches.
The on-disk binary is identical to what Red Hat shipped.

### 3. SELinux

SELinux is running in enforcing mode (`getenforce` returns `Enforcing`). The file
has the correct SELinux label (`su_exec_t`). SELinux enforces policy at the syscall
boundary — it intercepts `execve()`, `open()`, `connect()`, and similar calls. But
the page cache corruption happens *before* `execve()` fires, at the kernel memory
management layer, which is below where SELinux operates. SELinux never sees the
corruption. It cannot block what it cannot observe.

**Summary: three defenses checked. Three clean results. The attack is completely
invisible to all of them.**

---

## The Specification That Detected It

While the conventional checks return clean, Falco fires a CRITICAL alert:

```
Root shell spawned directly by user shell — RHEL process ancestry invariant violated
(user=root uid=0 pid=3665 ppid=3423 comm=sh parent=bash cmdline=sh pcmdline=bash)
```

This rule encodes a **RHEL process ancestry invariant** — a behavioral fact that is
always true in a correctly operating RHEL system:

> A root shell (uid=0) whose direct parent is a user-level interactive shell
> is architecturally impossible under normal operation.

When a user legitimately elevates privileges using `su` or `sudo`, the process tree
looks like this:

```
bash (cloud-user, uid=1000)
  └── su (root, uid=0)          ← su/sudo always interposes here
        └── sh (root, uid=0)    ← root shell's parent is su, not bash
```

What the exploit produces is:

```
bash (cloud-user, uid=1000)
  └── sh (root, uid=0)          ← root shell's parent is bash — impossible
```

The exploit's `execve()` replacement causes the corrupted `su` binary to spawn `sh`
directly — so `sh`'s parent process is `bash`, not `su`. This is the invariant violation.
The rule fires not because Copy Fail is a known attack, but because the process tree
is in a state that the RHEL specification declares impossible.

This is **specification deviation detection**: the system knows what correct behavior
looks like, and fires when observed behavior diverges — regardless of *how* the
divergence was caused.

---

## Walking Through the Incident Log

```json
"incident_id": "510fdef5",
"rule": "Root Shell Spawned Directly by User Shell",
"host": "rhel9-brown-loon-92",
"verdict": "confirmed_threat",
"cve_ids": ["CVE-2026-31431"]
```

Falco's webhook fires the agent pipeline. The rule name, host, and process PIDs are
extracted from the alert payload.

---

```json
"detection_method": "behavioral_specification_violation"
```

The agent records that detection came from a behavioral specification — not a signature,
not a hash, not a known-bad pattern.

---

```json
"conventional_methods_bypassed": [
  "File integrity check (/usr/bin/su): on-disk binary is present and readable — page cache corruption leaves no on-disk trace...",
  "RPM package verification (rpm -V shadow-utils): all package files match the RPM database — on-disk binary is clean",
  "SELinux: enforcing mode active — but page cache corruption occurs before execve() fires, so the corruption is below the syscall layer SELinux monitors"
]
```

Node 1b (`spec_verify`) runs these three checks via direct SSH and records that all
returned clean. This is not incidental — it is the point. The incident report carries
explicit proof that every conventional defense was bypassed, alongside proof that the
behavioral specification fired. The contrast is the argument.

---

```json
"evidence": [
  "Falco: ...Critical Root shell spawned directly by user shell...",
  "Root shell process: PID 3665, user=root, comm=sh, elapsed=00:05",
  "Parent process: PID 3423, user=cloud-user, comm=bash, elapsed=02:22"
]
```

Node 1 (`process_inspect`) retrieves the process details via linux-mcp-server. PID 3665
is `sh` running as root. Its parent, PID 3423, is `bash` running as `cloud-user`
(uid=1000). The parent has been alive for over two minutes — this is the user's
interactive login shell, not a transient process. The process ancestry invariant
violation is confirmed in the process table.

---

```json
"summary": "...Conventional integrity checks, including file hash
(5caff5036909df3c2d8baca06c9d4039693fcba9d3aaf62a7be8b3b09a59acbf for /usr/bin/su)
and RPM verification (rpm -V shadow-utils), returned clean, indicating that detection
was achieved exclusively via behavioral specification violation. The violated invariant,
enforced by the RHEL process ancestry, dictates that a root shell should never spawn
directly from a user shell without the intermediary of a su or sudo binary..."
```

The LLM (Node 5) writes a summary paragraph instructed to explicitly name both
the clean conventional checks and the violated invariant. The SHA256 hash appearing
in the summary is the actual hash of the on-disk binary — clean, matching the RPM
database — included to underscore that file integrity monitoring had no signal.

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
  The corruption is neutralized.
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

Deterministic next steps assembled by Python based on verdict and CVE IDs.

---

## Why This Matters

The conventional security model is **open-world**: block what is known-bad. This works
well against known attacks, and poorly against novel ones. The entire class of page cache
corruption exploits — any future CVE that achieves LPE via the same mechanism — is
invisible to file integrity monitoring, RPM verification, and antivirus by construction.
They read on-disk state. Page cache attacks happen in memory.

The specification deviation model is **closed-world**: declare what correct behavior
looks like, and treat any deviation as a signal. The Falco rule encoding the RHEL process
ancestry invariant would fire on Copy Fail, Fragnesia, and any future exploit that
produces a root shell via the same execve() replacement pattern — including ones that
don't exist yet and have no CVE number.

Red Hat's position in this model is that it ships the specifications: SELinux policy,
systemd unit files, RPM metadata, NetworkPolicy. These are the declared behavioral
envelopes for every component on the platform. Deviation from those specifications is
detectable regardless of the novelty of the attack technique used to cause the deviation.

The SELinux precedent is instructive: Red Hat shipped SELinux in permissive mode in
RHEL 4, with an incomplete policy that was difficult to tune. Over several releases,
investment in tooling (`audit2allow`, policy generators, UX improvements) made
enforcing mode viable at scale. The same methodology applies to behavioral specification
detection: start with the invariants that are well-understood and high-confidence
(like process ancestry), expand the specification coverage over time, and hand off
confirmed signals to an automated response layer.

The demo is a proof of concept for that last step: a confirmed specification violation
triggers an autonomous agent that investigates, remediates, and records — without
human intervention, and without needing to know what the attack was.
