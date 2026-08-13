# autonomous-threat-response

> **WIP** — Work in progress. Demo design and implementation in progress.

An autonomous defensive AI agent that detects and responds to active attacks on a RHEL host in real time.

## Overview

This project demonstrates an agentic security operations workflow triggered by real CVEs. When an attack is detected, a Claude AI agent investigates the threat using live system telemetry and triggers remediation via Ansible Automation Platform — without human intervention.

The demo uses two recent Linux local privilege escalation (LPE) vulnerabilities as the attack scenario:

- **Copy Fail (CVE-2026-31431)** — Logic flaw in the Linux kernel `AF_ALG` cryptographic interface allowing unprivileged page cache writes to gain root
- **Fragnesia (CVE-2026-46300)** — ESP-in-TCP XFRM subsystem flaw causing in-place AES-GCM decryption over page-cache-backed frags, yielding root via setuid binary corruption

Both attacks corrupt setuid binaries (e.g. `/usr/bin/su`) in the page cache without touching the on-disk file — bypassing traditional file integrity monitoring. Only behavioral/runtime detection catches them.

## Architecture

```
Attacker (low-priv user on RHEL host)
         │
         │  runs exploit (Copy Fail or Fragnesia PoC)
         ▼
┌─────────────────────────────┐
│         RHEL Host           │
│                             │
│  Falco (runtime detection)  │
│    - AF_ALG + splice rule   │
│    - CLONE_NEWUSER rule     │
│    - setuid shell spawn     │
└────────────┬────────────────┘
             │ webhook (alert + context)
             ▼
┌─────────────────────────────┐
│       Claude AI Agent       │
│                             │
│  Receives Falco alert       │
│  Investigates via MCP:      │
│    - get_audit_logs         │
│    - get_process_info       │
│    - get_network_connections│
│  Reasons about threat       │
│  Decides on response        │
└────────────┬────────────────┘
             │ trigger job template
             ▼
┌─────────────────────────────┐
│  Ansible Automation Platform│
│       + MCP Server          │
│                             │
│  Runs remediation playbook: │
│    - Kill root shell process│
│    - Blacklist kernel module│
│    - Drop page cache        │
│    - Lock compromised user  │
└────────────┬────────────────┘
             │ SSH
             ▼
┌─────────────────────────────┐
│         RHEL Host           │
│      (remediated)           │
└─────────────────────────────┘
```

## Components

| Component | Technology | Role |
|-----------|-----------|------|
| Target host | RHEL (VM or bare metal) | Attack surface |
| Runtime detection | [Falco](https://falco.org/) | Behavioral anomaly detection, webhook trigger |
| System telemetry | [linux-mcp-server](https://github.com/rhel-lightspeed/linux-mcp-server) | Read-only RHEL introspection via MCP |
| AI agent | Claude (claude-sonnet-4-6 or later) | Threat reasoning and response decisions |
| Remediation | [Ansible Automation Platform 2.6](https://www.redhat.com/en/technologies/management/ansible) + MCP Server | Auditable, pre-approved playbook execution |
| AAP hosting | OpenShift Developer Sandbox | AAP + MCP server deployment |

## Demo Flow

1. **Initial foothold** — attacker authenticates as a low-privilege user (e.g. via SSH)
2. **Exploit** — attacker runs Copy Fail or Fragnesia PoC, corrupting a setuid binary in the page cache
3. **Detection** — Falco fires on the behavioral signature (setuid binary spawning unexpected root shell) and sends a webhook to the agent
4. **Investigation** — Claude agent queries the RHEL host via `linux-mcp-server`:
   - Confirms process tree and parent-child relationship
   - Checks active network connections for C2 indicators
   - Reads audit log for privilege escalation events
5. **Reasoning** — Agent identifies the CVE pattern, assesses blast radius, and selects the appropriate response playbook
6. **Remediation** — Agent triggers AAP job template with relevant parameters (PID, username, module to blacklist)
7. **Report** — Agent outputs a structured incident summary: what was detected, what was done, and what patch is required

## Why behavioral detection matters

Both CVEs leave on-disk files untouched. Standard defenses that miss this:

- File integrity monitoring (AIDE, Tripwire) — hashes the on-disk file, which is clean
- Antivirus / EDR signature scanning — no malicious binary written to disk
- `rpm -V` package verification — package files unchanged

Falco watches **syscall behavior at runtime**, catching the moment a setuid binary spawns a root shell regardless of whether the binary was modified on disk.

## Remediation Playbooks

| Playbook | Action |
|----------|--------|
| `block_module.yml` | Blacklists `algif_aead` (Copy Fail) or `esp4`/`esp6` (Fragnesia) |
| `drop_page_cache.yml` | Flushes page cache (`echo 3 > /proc/sys/vm/drop_caches`) forcing reload from clean disk |
| `kill_session.yml` | Terminates the escalated root shell process |
| `lock_user.yml` | Locks the compromised user account pending investigation |

## References

- [CVE-2026-31431 — Copy Fail (Palo Alto Unit42)](https://unit42.paloaltonetworks.com/cve-2026-31431-copy-fail/)
- [CVE-2026-31431 — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/)
- [CVE-2026-46300 — Fragnesia (Help Net Security)](https://www.helpnetsecurity.com/2026/05/14/fragnesia-cve-2026-46300-linux-lpe-vulnerability/)
- [CVE-2026-46300 — Tenable FAQ](https://www.tenable.com/blog/fragnesia-cve-2026-46300-faq-about-new-linux-kernel-xfrm-esp-in-tcp-priv-esc)
- [linux-mcp-server](https://github.com/rhel-lightspeed/linux-mcp-server)
- [AAP MCP Server docs](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.6/extend-assembly_deploying_ansible_mcp_server)
- [Falco](https://falco.org/)
