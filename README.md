# autonomous-threat-response

An autonomous defensive AI agent that detects and responds to active Linux privilege escalation attacks in real time — without human intervention.

The demo uses two recent kernel local privilege escalation (LPE) vulnerabilities as the attack scenario:

- **Copy Fail (CVE-2026-31431)** — Logic flaw in the `AF_ALG` cryptographic interface allowing unprivileged page cache writes to gain root via splice + execve replacement of a setuid binary.
- **Fragnesia (CVE-2026-46300)** — ESP-in-TCP XFRM subsystem flaw causing in-place AES-GCM decryption over page-cache-backed frags, yielding root via the same setuid corruption pattern.

Both attacks corrupt setuid binaries (e.g. `/usr/bin/su`) in the page cache **without touching the on-disk file** — bypassing file integrity monitoring, antivirus, and `rpm -V`. Only behavioral/runtime detection catches them.

## Architecture

```
Attacker (low-priv user on RHEL host)
         │
         │  runs exploit.py (Copy Fail PoC)
         ▼
┌──────────────────────────────────────────┐
│               RHEL Host (KubeVirt VM)    │
│                                          │
│  Falco 0.44.1 (modern eBPF driver)       │
│    - Copy Fail Splice into AF_ALG Socket │
│    - Root Shell Spawned by User Shell    │  ← CRITICAL alert
└──────────────────────┬───────────────────┘
                       │ HTTP webhook (JSON)
                       ▼
┌──────────────────────────────────────────┐
│         Threat Response Agent            │
│         (FastAPI + LangGraph)            │
│                                          │
│  Node 1: process_inspect  (pure Python)  │
│    get_process_info(root_pid)            │
│    get_process_info(parent_pid)          │
│                                          │
│  Node 2: host_triage      (pure Python)  │
│    get_journal_logs(since="-15m")        │
│    get_network_connections()             │
│                                          │
│  Node 3: classify         (LLM only)     │
│    structured output → verdict + CVE     │
│                                          │
│  Node 4: remediate        (pure Python)  │
│    AAP: drop_page_cache  (job_id=10)     │
│    AAP: kill_session     (job_id=8)      │
│    AAP: lock_user        (job_id=11)     │
│                                          │
│  Node 5: report           (LLM only)     │
│    plain-text summary paragraph          │
│    → IncidentReport JSON (assembled      │
│      in Python, not by the LLM)          │
└──────────────────────┬───────────────────┘
                       │ AAP MCP (streamable-HTTP)
                       ▼
┌──────────────────────────────────────────┐
│  Ansible Automation Platform 2.6         │
│  + AAP MCP Server                        │
│                                          │
│  Playbooks run against rhel9-brown-loon  │
│  via stable K8s Service DNS              │
└──────────────────────────────────────────┘
```

## Why a deterministic pipeline instead of a ReAct agent

The agent runs on a small model (llama-scout-17b via MaaS). Open-ended ReAct loops on sub-20B models are unreliable: the model exits early, selects wrong tools, mis-formats tool arguments, or fabricates remediation actions in its report. The pipeline eliminates model discretion entirely:

| Node | Who drives it | What can go wrong |
|------|--------------|-------------------|
| 1 process_inspect | Pure Python | Nothing — tool calls are hardcoded |
| 2 host_triage | Pure Python | Nothing — tool calls are hardcoded |
| 3 classify | LLM (structured output) | Only classification quality; falls back to rule-based |
| 4 remediate | Pure Python | Nothing — template IDs are constants; args are `json.dumps()` |
| 5 report | LLM (plain text) | Only prose quality; no JSON output required |

The LLM never selects tools, never formats arguments, never decides what step comes next, and never writes the `IncidentReport` JSON — Python assembles it from the pipeline's typed outputs.

## Components

| Component | Technology | Role |
|-----------|-----------|------|
| Target host | RHEL 9 (KubeVirt VM `rhel9-brown-loon-92`) | Attack surface |
| Runtime detection | Falco 0.44.1 (modern eBPF) | Behavioral anomaly detection, webhook trigger |
| System telemetry | [linux-mcp-server](https://github.com/rhel-lightspeed/linux-mcp-server) | Read-only RHEL introspection via MCP (SSH stdio) |
| AI agent | LangGraph pipeline + llama-scout-17b (MaaS) | Threat classification and summary |
| Remediation | Ansible Automation Platform 2.6 + AAP MCP Server | Auditable, pre-approved playbook execution |
| Deployment | OpenShift (same namespace as AAP) | Agent pod, image build via BuildConfig |

## Exploit Code

The Copy Fail PoC used in the demo is at **https://github.com/xeloxa/copyfail-exploit**.

Clone it onto the target RHEL 9 host as a low-privilege user. The exploit requires Python 3.11 — install it first:

```bash
sudo dnf install python3.11 -y
git clone https://github.com/xeloxa/copyfail-exploit
cd copyfail-exploit
```

## Demo Flow

1. **SSH in as cloud-user** on `rhel9-brown-loon-92`.
2. **Run the exploit**: `python3.11 exploit.py` — corrupts `/usr/bin/su` in the page cache via AF_ALG socket + splice, then execve-replaces it with a root shell.
3. **Falco fires** the `Root Shell Spawned Directly by User Shell` rule (CRITICAL priority) and POSTs a JSON webhook to the agent.
4. **Agent pipeline runs**:
   - Looks up the root `sh` process and its `bash` parent via `get_process_info`
   - Pulls journal logs and network connections from the host
   - LLM classifies: `confirmed_threat`, `CVE-2026-31431`
   - Python deterministically launches all three AAP playbooks
   - LLM writes a one-paragraph summary
5. **Webhook response** returns a structured `IncidentReport` with real AAP job IDs in `actions_taken`.

## Falco Rules

Custom rules are in `falco-rules/` (deployed to `/etc/falco/rules.d/` on the VM):

| File | Rules |
|------|-------|
| `copy_fail.yaml` | AF_ALG socket creation (disabled/informational), splice into algif fd (ERROR), root shell spawned by user shell (CRITICAL) |
| `fragnesia.yaml` | CLONE_NEWUSER unshare, ESP module load, GRO UDP socket, same root shell rule |

The CRITICAL rule that triggers the demo:
```yaml
- rule: Root Shell Spawned Directly by User Shell
  condition: >
    spawned_process and not container and
    user.uid = 0 and
    proc.name in (bash, sh, dash, zsh, ...) and
    proc.pname in (bash, sh, dash, zsh, ...)
  priority: CRITICAL
```

This fires when a root shell's direct parent is a user shell — the execve() replacement fingerprint of both CVEs. Legitimate su/sudo never produce this parent relationship.

## Remediation Playbooks

Located in `playbooks/`, executed via AAP job templates:

| Playbook | AAP Template ID | Action |
|----------|----------------|--------|
| `drop_page_cache.yml` | 10 | Flushes page cache (`echo 3 > /proc/sys/vm/drop_caches`), forcing reload of the clean on-disk binary |
| `kill_session.yml` | 8 | Terminates the escalated root shell process by PID |
| `lock_user.yml` | 11 | Writes audit record to `/var/log/security-incidents/` (non-destructive for demo — a real deployment would lock the account) |

Extra vars are passed as JSON strings. The target host is always `rhel9-brown-loon-92-ssh` (stable K8s Service DNS, same namespace as AAP).

## Deployment

```bash
# Build and push image
oc start-build threat-response-agent --from-dir=. --follow

# Roll out new image (imagePullPolicy: Always ensures latest is used)
oc rollout restart deployment/threat-response-agent

# Watch logs
oc logs -f deployment/threat-response-agent
```

Secrets required:
- `threat-response-agent-secrets` — keys: `OPENAI_API_KEY`, `AAP_TOKEN`, `LANGCHAIN_API_KEY` (optional)
- `agent-ssh-privkey` — key: `id_rsa` (mounted at `/ssh/id_rsa`)

## Why behavioral detection matters

Both CVEs leave on-disk files untouched. Standard defenses that miss this:

- **File integrity monitoring** (AIDE, Tripwire) — hashes the on-disk file, which is clean
- **Antivirus / EDR signature scanning** — no malicious binary written to disk
- **`rpm -V` package verification** — package files unchanged

Falco watches syscall behavior at runtime, catching the moment a setuid binary spawns a root shell regardless of whether the on-disk binary was modified.

## References

- [CVE-2026-31431 — Copy Fail (Palo Alto Unit42)](https://unit42.paloaltonetworks.com/cve-2026-31431-copy-fail/)
- [CVE-2026-31431 — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/)
- [CVE-2026-46300 — Fragnesia (Help Net Security)](https://www.helpnetsecurity.com/2026/05/14/fragnesia-cve-2026-46300-linux-lpe-vulnerability/)
- [CVE-2026-46300 — Tenable FAQ](https://www.tenable.com/blog/fragnesia-cve-2026-46300-faq-about-new-linux-kernel-xfrm-esp-in-tcp-priv-esc)
- [linux-mcp-server](https://github.com/rhel-lightspeed/linux-mcp-server)
- [AAP MCP Server](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.6/extend-assembly_deploying_ansible_mcp_server)
- [Falco](https://falco.org/)
