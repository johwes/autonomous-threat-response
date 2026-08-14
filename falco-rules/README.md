# Falco Detection Rules

Custom Falco rules for detecting CVE-2026-31431 (Copy Fail) and CVE-2026-46300 (Fragnesia) — two local privilege escalation (LPE) vulnerabilities that corrupt the Linux page cache to gain root.

Both rule files are deployed to `/etc/falco/rules.d/` on the target host, either manually or via the `setup_falco.yml` playbook (see below).

---

## Installing Falco and deploying these rules

The fastest way to get a RHEL 9 host fully configured is the setup playbook:

```bash
ansible-playbook -i <target-ip>, playbooks/setup_falco.yml \
  -e agent_webhook_url=http://<agent-route>/webhook \
  --private-key ~/.ssh/id_rsa \
  -u cloud-user
```

The trailing comma after the IP is required — it tells Ansible to treat the value as an inline inventory rather than a file path.

The playbook:
1. Imports the Falcosecurity GPG key and RPM repo
2. Installs Falco via `dnf`
3. Writes `/etc/falco/falco.yaml` with `modern_ebpf` engine, JSON output enabled, and HTTP output pointed at your agent webhook
4. Deploys both rule files from this directory to `/etc/falco/rules.d/`
5. Enables and starts `falco-modern-bpf.service`

To verify Falco is running and loaded your rules after the playbook completes:

```bash
systemctl status falco-modern-bpf
journalctl -u falco-modern-bpf -f
```

---

## Rule files

### `copy_fail.yaml` — CVE-2026-31431

Three rules covering the Copy Fail exploit chain:

| Rule | Priority | What it detects |
|---|---|---|
| Copy Fail AF_ALG Socket Created by Unprivileged Process | WARNING | `socket()` call by non-root host process — broad early indicator; **disabled by default** |
| Copy Fail Splice into AF_ALG Socket | ERROR | `splice()` into an `algif` fd — the core exploitation primitive (attacker writes to AF_ALG socket to corrupt page cache) |
| Root Shell Spawned Directly by User Shell | CRITICAL | Root shell whose direct parent is a user shell — reliable post-exploitation fingerprint for both CVEs |

The CRITICAL rule is the main trigger for the autonomous response pipeline. In a legitimate `su`/`sudo` flow the root shell's parent is `su` or `sudo`, not the user's own `bash`. In Copy Fail and Fragnesia the corrupted setuid binary `execve()`s a root shell directly, leaving the attacker's shell as the parent.

### `fragnesia.yaml` — CVE-2026-46300

Three rules covering the Fragnesia exploit chain:

| Rule | Priority | What it detects |
|---|---|---|
| Fragnesia User Namespace Creation by Unprivileged Process | WARNING | `unshare()`/`clone()` with `CLONE_NEWUSER` — Fragnesia uses user namespaces to gain `CAP_NET_ADMIN` |
| Fragnesia ESP Module Loaded or Used by Unprivileged Process | ERROR | Loading of `esp4`/`esp6` modules — required by the XFRM ESP subsystem that triggers page-cache corruption |
| Fragnesia GRO UDP Splice Pattern | WARNING | Large UDP datagrams (>65 000 bytes) from non-root — heuristic for the GRO variant; tune threshold for your environment |

---

## Agent webhook format

Falco POSTs alerts as JSON to the configured `http_output.url`. The agent expects the standard Falco JSON envelope:

```json
{
  "rule": "Root Shell Spawned Directly by User Shell",
  "priority": "Critical",
  "hostname": "rhel9-brown-loon-92",
  "output_fields": {
    "proc.pid": 4821,
    "proc.ppid": 4800,
    "proc.name": "bash",
    "proc.pname": "bash",
    "proc.cmdline": "bash",
    "proc.pcmdline": "bash exploit.sh",
    "user.name": "jdoe",
    "user.uid": 1001,
    "container.name": "host"
  },
  "tags": ["CVE-2026-31431", "CVE-2026-46300", "copy_fail", "fragnesia", "lpe"]
}
```

`proc.ppid` must be present in the alert for the agent's triage node to identify the parent process. It is included via `ppid=%proc.ppid` in the `output` template of the CRITICAL rule — do not remove it.

`container.name` will be `"host"` for non-container events. The agent filters this sentinel value out when resolving the target hostname.
