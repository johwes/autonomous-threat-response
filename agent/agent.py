"""
Autonomous Threat Response Agent — deterministic StateGraph pipeline.

Five nodes, each with a single responsibility:
  1. process_inspect  — pure Python: get_process_info on root shell + parent
  2. host_triage      — pure Python: get_journal_logs + get_network_connections
  3. classify         — LLM-only (no tools): structured verdict + CVE
  4. remediate        — pure Python: deterministic AAP playbook dispatch
  5. report           — LLM: write one plain-text summary paragraph

The LLM is only consulted in nodes 3 and 5, and only given a narrow prompt
with a single concrete few-shot trajectory. It never selects tools, never
formats JSON, never decides what to do next. All control flow is Python.

Investigation tools: linux-mcp-server via SSH stdio.
Remediation tools:   AAP MCP server via streamable-HTTP.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Literal, Optional

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from pydantic import BaseModel, Field

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

AGENT_MODEL    = os.getenv("AGENT_MODEL",    "gpt-oss-120b")
AGENT_BASE_URL = os.getenv("AGENT_BASE_URL", "https://maas-rhdp.apps.maas.redhatworkshops.io/v1")

LINUX_MCP_SSH_HOST = os.getenv("LINUX_MCP_SSH_HOST", "rhel-host")
LINUX_MCP_SSH_USER = os.getenv("LINUX_MCP_SSH_USER", "root")
LINUX_MCP_SSH_KEY  = os.getenv("LINUX_MCP_SSH_KEY_PATH", "/ssh/id_rsa")
LINUX_MCP_CMD      = os.getenv("LINUX_MCP_CMD", "linux-mcp-server")

AAP_MCP_URL = os.getenv(
    "AAP_MCP_URL",
    "https://sandbox-aap-mcp-rhn-sa-jwesterl-dev.apps.rm3.7wse.p1.openshiftapps.com/mcp",
)
AAP_TOKEN = os.getenv("AAP_TOKEN", "")

AAP_TARGET_HOST  = "rhel9-brown-loon-92-ssh"
AAP_TEMPLATE_IDS = {
    "drop_page_cache":       10,
    "kill_session":           8,
    "lock_user":             11,
    "write_incident_report":  12,
}

LINUX_TOOLS = {
    "get_process_info",
    "get_journal_logs",
    "get_network_connections",
    "get_file_info",
    "run_command",
}
AAP_TOOLS = {
    "job_templates_launch_create",
    "jobs_retrieve",
}

# ---------------------------------------------------------------------------
# Public output schema (returned from ainvoke)
# ---------------------------------------------------------------------------

class IncidentReport(BaseModel):
    incident_id: str
    rule: str
    host: str
    verdict: Literal["confirmed_threat", "likely_threat", "false_positive", "inconclusive"]
    cve_ids: list[str] = Field(default_factory=list)
    summary: str
    evidence: list[str] = Field(default_factory=list)
    actions_taken: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal LLM output schemas (structured output — no JSON parsing needed)
# ---------------------------------------------------------------------------

class ClassifyResult(BaseModel):
    verdict: Literal["confirmed_threat", "likely_threat", "false_positive", "inconclusive"]
    cve_ids: list[str] = Field(default_factory=list)
    confidence_notes: str


# ---------------------------------------------------------------------------
# LLM factory
# ---------------------------------------------------------------------------

def _build_llm():
    provider = os.getenv("AGENT_PROVIDER", "anthropic").lower()

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=AGENT_MODEL,
            max_tokens=8000,
            thinking={"type": "adaptive"},
            streaming=True,
        )

    if provider in ("openai", "openai_compatible"):
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=AGENT_MODEL,
            base_url=AGENT_BASE_URL,
            streaming=True,
        )

    if provider == "azure":
        from langchain_openai import AzureChatOpenAI
        return AzureChatOpenAI(azure_deployment=AGENT_MODEL, streaming=True)

    if provider == "bedrock":
        from langchain_aws import ChatBedrock
        return ChatBedrock(model_id=AGENT_MODEL, streaming=True)

    raise ValueError(f"Unknown AGENT_PROVIDER: {provider}")


# ---------------------------------------------------------------------------
# Tool host-param stripper  (linux-mcp-server runs locally on the VM)
# ---------------------------------------------------------------------------

def _strip_host_param(tool):
    """Wrap a linux MCP tool to drop 'host' and fix ISO 'since' timestamps."""
    tool_name = tool.name
    original_ainvoke = tool.ainvoke
    original_invoke  = tool.invoke

    def _clean(inp):
        if not isinstance(inp, dict):
            return inp
        cleaned = {k: v for k, v in inp.items() if k != "host"}
        if "since" in cleaned and isinstance(cleaned["since"], str) and "T" in cleaned["since"]:
            cleaned["since"] = cleaned["since"].replace("T", " ").rstrip("Z")
        return cleaned

    async def _ainvoke(inp, config=None, **kw):
        return await original_ainvoke(_clean(inp), config=config, **kw)

    def _invoke(inp, config=None, **kw):
        return original_invoke(_clean(inp), config=config, **kw)

    object.__setattr__(tool, "ainvoke", _ainvoke)
    object.__setattr__(tool, "invoke",  _invoke)
    return tool


# ---------------------------------------------------------------------------
# Helper: call a single MCP tool, return string output
# ---------------------------------------------------------------------------

async def _call_tool(tool, args: dict, ilog, label: str) -> str:
    ilog.info("tool.call", tool=tool.name, label=label, args=str(args)[:200])
    try:
        result = await tool.ainvoke(args)
        text = str(result)[:4000]
        ilog.info("tool.result", tool=tool.name, label=label, preview=text[:300])
        return text
    except Exception as exc:
        ilog.error("tool.error", tool=tool.name, label=label, error=str(exc))
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# Node 1 — Process Inspector (pure Python, no LLM)
# ---------------------------------------------------------------------------

async def _node_process_inspect(
    tools: dict[str, Any],
    alert,
    ilog,
) -> dict[str, Any]:
    """
    Call get_process_info on the root shell PID from the alert, then on its
    parent PID. Returns raw text from both calls.

    No LLM involved — we deterministically call the tool with the PID
    extracted from the Falco output_fields.
    """
    gpi = tools.get("get_process_info")
    if not gpi:
        ilog.warning("node1.missing_tool", msg="get_process_info not available")
        return {"proc_root": "", "proc_parent": "", "root_pid": None}

    # Extract PID from Falco output_fields (try several field names)
    root_pid = (
        alert.output_fields.get("proc.pid")
        or alert.output_fields.get("pid")
        or _extract_pid_from_output(alert.output)
    )
    ilog.info("node1.root_pid", pid=root_pid)

    proc_root = ""
    proc_parent = ""
    # Prefer proc.ppid from output_fields (added to Falco rule output);
    # fall back to regex extraction from the get_process_info result.
    ppid = alert.output_fields.get("proc.ppid") or alert.output_fields.get("ppid")

    if root_pid:
        proc_root = await _call_tool(gpi, {"pid": str(root_pid)}, ilog, "root_shell")
        if not ppid:
            ppid = _extract_ppid(proc_root)
        ilog.info("node1.ppid", ppid=ppid, source="output_fields" if alert.output_fields.get("proc.ppid") else "proc_text")

    if ppid:
        proc_parent = await _call_tool(gpi, {"pid": str(ppid)}, ilog, "parent_shell")
    else:
        # Falco fired "Root Shell Spawned Directly by User Shell" — the alert
        # output already contains parent info; we don't need a second call if
        # the parent PID can't be extracted from proc output.
        ilog.info("node1.no_ppid", msg="Could not extract PPID from proc_root; relying on alert output")

    return {
        "proc_root":   proc_root,
        "proc_parent": proc_parent,
        "root_pid":    root_pid,
        "ppid":        ppid,
    }


def _extract_pid_from_output(output: str) -> Optional[str]:
    """Pull PID from Falco output string like '... pid=2538 ...'"""
    m = re.search(r"\bpid=(\d+)", output)
    return m.group(1) if m else None


def _extract_ppid(proc_text: str) -> Optional[str]:
    """Pull PPID from get_process_info output."""
    for pattern in (r"ppid[=:\s]+(\d+)", r"parent.*?pid[=:\s]+(\d+)", r"PPID[=:\s]+(\d+)"):
        m = re.search(pattern, proc_text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Node 2 — Host Triage (pure Python, no LLM)
# ---------------------------------------------------------------------------

async def _node_host_triage(
    tools: dict[str, Any],
    ilog,
) -> dict[str, Any]:
    """
    Call get_journal_logs (last 15 min) and get_network_connections.
    Pure Python — no model involvement.
    """
    gjl = tools.get("get_journal_logs")
    gnc = tools.get("get_network_connections")

    journal = ""
    network = ""

    if gjl:
        journal = await _call_tool(gjl, {"since": "-15m"}, ilog, "journal_triage")
    else:
        ilog.warning("node2.missing_tool", msg="get_journal_logs not available")

    if gnc:
        network = await _call_tool(gnc, {}, ilog, "network_triage")
    else:
        ilog.warning("node2.missing_tool", msg="get_network_connections not available")

    return {"journal": journal, "network": network}


# ---------------------------------------------------------------------------
# Node 3 — Threat Classifier (LLM only, structured output)
# ---------------------------------------------------------------------------

CLASSIFY_SYSTEM = """\
You are a Linux security analyst. You will receive evidence from a RHEL host that
triggered a Falco "Root Shell Spawned Directly by User Shell" alert.

Your ONLY job is to classify the incident using the evidence.
Do NOT suggest additional tool calls. Do NOT write a report.
Output ONLY the structured classification — nothing else.

CVE reference patterns:
- CVE-2026-31431 (Copy Fail): AF_ALG socket + splice() corrupts page cache of a setuid
  binary via execve() replacement. Post-exploitation fingerprint: root shell (uid=0) whose
  DIRECT parent is a non-root user shell (bash/sh running as uid=1000). The parent is NOT
  su or sudo — it is the attacker's interactive session shell.
- CVE-2026-46300 (Fragnesia): user namespace + XFRM ESP page cache corruption. Similar
  post-exploitation fingerprint, but preceded by unshare(CLONE_NEWUSER) in journal.

EXAMPLE:
Evidence:
  [proc_root]  PID 2538  uid=0   comm=sh   PPID=2480
  [proc_parent] PID 2480 uid=1000 comm=bash user=cloud-user
  [journal]    splice, algif socket operations visible around alert time
  [network]    no unexpected outbound connections

Classification:
  verdict: confirmed_threat
  cve_ids: ["CVE-2026-31431"]
  confidence_notes: Root shell uid=0 (sh) with direct parent uid=1000 (bash/cloud-user).
    Matches execve() replacement pattern of Copy Fail. Journal confirms splice+algif activity.
"""


async def _node_classify(
    llm,
    alert,
    proc_root: str,
    proc_parent: str,
    journal: str,
    network: str,
    ilog,
) -> ClassifyResult:
    """
    Ask the LLM to classify the threat.

    Strategy (most-to-least reliable):
    1. with_structured_output (function-calling / JSON schema mode) — best for
       models that support tool calling.
    2. Plain LLM call → parse JSON from response — fallback for models that
       don't support structured output but can emit JSON in chat mode.
    3. Rule-based classify — if LLM is unavailable or produces garbage.
    """
    verdict_hint = (
        "The Falco rule that fired ('Root Shell Spawned Directly by User Shell') "
        "is specifically designed to detect this pattern."
        if "Root Shell Spawned Directly by User Shell" in alert.rule else ""
    )

    evidence_block = (
        f"FALCO ALERT:\n"
        f"  rule:   {alert.rule}\n"
        f"  output: {alert.output}\n"
        f"  fields: {json.dumps(alert.output_fields)}\n\n"
        f"[proc_root (root shell)]:\n{proc_root or '(not retrieved)'}\n\n"
        f"[proc_parent (parent of root shell)]:\n{proc_parent or '(not retrieved)'}\n\n"
        f"[journal (last 15 min)]:\n{journal[:2000] or '(not retrieved)'}\n\n"
        f"[network connections]:\n{network[:1000] or '(not retrieved)'}\n"
        + (f"\nHINT: {verdict_hint}" if verdict_hint else "")
    )

    messages = [
        SystemMessage(content=CLASSIFY_SYSTEM),
        HumanMessage(content=evidence_block),
    ]

    ilog.info("node3.classify_start")

    # Attempt 1: structured output (function-calling)
    try:
        classify_llm = llm.with_structured_output(ClassifyResult)
        result: ClassifyResult = await classify_llm.ainvoke(messages)
        ilog.info("node3.classify_done", method="structured_output",
                  verdict=result.verdict, cves=result.cve_ids,
                  notes=result.confidence_notes[:120])
        return result
    except Exception as exc:
        ilog.warning("node3.structured_output_failed", error=str(exc),
                     msg="Falling back to JSON-from-chat")

    # Attempt 2: plain chat call, parse JSON from response
    # Ask the model to emit JSON matching the ClassifyResult schema
    JSON_SUFFIX = (
        "\n\nRespond with ONLY a JSON object matching this schema (no preamble):\n"
        '{"verdict": "confirmed_threat|likely_threat|false_positive|inconclusive", '
        '"cve_ids": ["CVE-..."], "confidence_notes": "..."}'
    )
    try:
        raw_response = await llm.ainvoke([
            SystemMessage(content=CLASSIFY_SYSTEM),
            HumanMessage(content=evidence_block + JSON_SUFFIX),
        ])
        raw = raw_response.content if hasattr(raw_response, "content") else str(raw_response)
        if isinstance(raw, list):
            raw = "\n".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in raw)
        if "<|message|>" in raw:
            raw = raw.split("<|message|>", 1)[-1].strip()
        # Parse the JSON
        m = re.search(r"\{[\s\S]+\}", raw)
        if m:
            obj = json.loads(m.group())
            result = ClassifyResult(**obj)
            ilog.info("node3.classify_done", method="json_from_chat",
                      verdict=result.verdict, cves=result.cve_ids)
            return result
    except Exception as exc:
        ilog.warning("node3.json_parse_failed", error=str(exc),
                     msg="Falling back to rule-based classification")

    raise RuntimeError("All LLM classify strategies failed")


# ---------------------------------------------------------------------------
# Node 4 — AAP Remediation (pure Python, deterministic dispatch)
# ---------------------------------------------------------------------------

async def _launch_aap_playbook(
    launch_tool,
    retrieve_tool,
    name: str,
    template_id: int,
    extra_vars: str,
    ilog,
) -> Optional[str]:
    """Launch one AAP playbook and return a human-readable action string, or None on failure."""
    if template_id == 0:
        ilog.warning("node4.skip_playbook", playbook=name, msg="Template ID not configured (0)")
        return None
    try:
        ilog.info("node4.launch", playbook=name, template_id=template_id)
        launch_result = await launch_tool.ainvoke(
            {"id": str(template_id), "requestBody": {"extra_vars": extra_vars}}
        )
        result_text = str(launch_result)
        m = re.search(r'"id":\s*(\d+)', result_text)
        job_id = m.group(1) if m else None
        if job_id:
            ilog.info("node4.launched", playbook=name, job_id=job_id)
            retrieve_result = await retrieve_tool.ainvoke({"id": job_id})
            ilog.info("node4.retrieved", playbook=name, job_id=job_id,
                      preview=str(retrieve_result)[:200])
            return f"{name} (job_id={job_id})"
        else:
            ilog.warning("node4.no_job_id", playbook=name, result=result_text[:300])
            return f"{name} (launched, no job_id in response)"
    except Exception as exc:
        ilog.error("node4.launch_failed", playbook=name, error=str(exc))
        return None


async def _node_remediate(
    aap_tools: dict[str, Any],
    verdict: str,
    root_pid,
    ilog,
) -> list[str]:
    """
    Deterministically launch the three remediation playbooks if verdict warrants it.
    No LLM involved. write_incident_report is called separately after the report
    is assembled, so it can include the full IncidentReport JSON.

    Playbooks:
      drop_page_cache (id=10) — purges corrupted page cache entries
      kill_session    (id=8)  — terminates the root shell process
      lock_user       (id=11) — writes audit log (non-destructive for demo)
    """
    if verdict not in ("confirmed_threat", "likely_threat"):
        ilog.info("node4.skip", verdict=verdict, msg="No remediation needed")
        return []

    launch_tool   = aap_tools.get("job_templates_launch_create")
    retrieve_tool = aap_tools.get("jobs_retrieve")
    if not launch_tool or not retrieve_tool:
        ilog.warning("node4.missing_tools", msg="AAP tools not available")
        return []

    playbooks = [
        ("drop_page_cache", AAP_TEMPLATE_IDS["drop_page_cache"],
         json.dumps({"target_host": AAP_TARGET_HOST})),
        ("kill_session", AAP_TEMPLATE_IDS["kill_session"],
         json.dumps({"target_pid": str(root_pid) if root_pid else "0",
                     "target_host": AAP_TARGET_HOST})),
        ("lock_user", AAP_TEMPLATE_IDS["lock_user"],
         json.dumps({"compromised_user": "cloud-user",
                     "target_host": AAP_TARGET_HOST})),
    ]

    actions: list[str] = []
    for name, template_id, extra_vars in playbooks:
        result = await _launch_aap_playbook(
            launch_tool, retrieve_tool, name, template_id, extra_vars, ilog
        )
        if result:
            actions.append(result)
    return actions


async def _write_report_to_host(
    aap_tools: dict[str, Any],
    incident_id: str,
    report: "IncidentReport",
    ilog,
) -> None:
    """Ship the assembled IncidentReport JSON to the host via AAP playbook."""
    template_id = AAP_TEMPLATE_IDS.get("write_incident_report", 0)
    if template_id == 0:
        ilog.warning("write_report.skip", msg="write_incident_report template ID not configured")
        return

    launch_tool   = aap_tools.get("job_templates_launch_create")
    retrieve_tool = aap_tools.get("jobs_retrieve")
    if not launch_tool or not retrieve_tool:
        ilog.warning("write_report.missing_tools")
        return

    extra_vars = json.dumps({
        "target_host":          AAP_TARGET_HOST,
        "incident_id":          incident_id,
        "incident_report_json": report.model_dump_json(indent=2),
    })
    await _launch_aap_playbook(
        launch_tool, retrieve_tool,
        "write_incident_report", template_id, extra_vars, ilog,
    )


# ---------------------------------------------------------------------------
# Node 5 — Report Writer (LLM: plain text summary only)
# ---------------------------------------------------------------------------

REPORT_SYSTEM = """\
You are a security analyst writing the summary section of an incident report.
Write exactly ONE paragraph (4-6 sentences) summarizing what happened, what was
confirmed, and what remediation was taken. Be specific — reference the process names,
PIDs, CVE ID, and playbook names from the evidence. Do not use bullet points.
Do not write JSON. Do not write headers. Just the paragraph.
"""


async def _node_report(
    llm,
    alert,
    host: str,
    proc_root: str,
    proc_parent: str,
    journal: str,
    network: str,
    classify: ClassifyResult,
    actions_taken: list[str],
    ilog,
) -> str:
    """Ask the LLM to write a one-paragraph plain-text summary."""
    evidence_block = (
        f"Alert rule: {alert.rule}\n"
        f"Host: {host}\n"
        f"Verdict: {classify.verdict}\n"
        f"CVEs: {', '.join(classify.cve_ids) or 'none identified'}\n"
        f"Classifier notes: {classify.confidence_notes}\n\n"
        f"Process findings (root shell): {proc_root[:600] or '(none)'}\n"
        f"Process findings (parent): {proc_parent[:400] or '(none)'}\n"
        f"Journal excerpt: {journal[:600] or '(none)'}\n"
        f"Network excerpt: {network[:300] or '(none)'}\n"
        f"Remediation actions taken: {', '.join(actions_taken) or 'none'}\n"
    )

    ilog.info("node5.report_start")
    response = await llm.ainvoke([
        SystemMessage(content=REPORT_SYSTEM),
        HumanMessage(content=evidence_block),
    ])
    content = response.content if hasattr(response, "content") else str(response)
    if isinstance(content, list):
        content = "\n".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
    # Strip model channel tokens
    if "<|message|>" in content:
        after = content.split("<|message|>", 1)[-1].strip()
        content = after if after else content.split("<|channel|>")[0].strip()
    content = str(content).strip()
    ilog.info("node5.report_done", length=len(content), preview=content[:200])
    return content


# ---------------------------------------------------------------------------
# Main agent class
# ---------------------------------------------------------------------------

class ThreatResponseAgent:
    def __init__(
        self,
        linux_tools: dict[str, Any],
        aap_tools: dict[str, Any],
        llm,
    ):
        self._linux_tools = linux_tools
        self._aap_tools   = aap_tools
        self._llm         = llm

    async def ainvoke(self, alert, incident_id: str) -> IncidentReport:
        container_name = alert.output_fields.get("container.name", "")
        host = (
            # "host" is Falco's sentinel meaning "not a container" — ignore it
            (container_name if container_name and container_name != "host" else None)
            or alert.hostname
            or AAP_TARGET_HOST
        )
        ilog = log.bind(incident_id=incident_id, host=host, rule=alert.rule)
        ilog.info("agent.start")

        # ── Node 1: inspect root shell + parent process ──────────────────────
        ilog.info("pipeline.node1", step="process_inspect")
        n1 = await _node_process_inspect(self._linux_tools, alert, ilog)
        proc_root   = n1["proc_root"]
        proc_parent = n1["proc_parent"]
        root_pid    = n1["root_pid"]

        # ── Node 2: journal + network triage ─────────────────────────────────
        ilog.info("pipeline.node2", step="host_triage")
        n2 = await _node_host_triage(self._linux_tools, ilog)
        journal = n2["journal"]
        network = n2["network"]

        # ── Node 3: LLM classifier (structured output) ───────────────────────
        ilog.info("pipeline.node3", step="classify")
        try:
            classify = await _node_classify(
                self._llm, alert,
                proc_root, proc_parent, journal, network,
                ilog,
            )
        except Exception as exc:
            ilog.error("node3.classify_failed", error=str(exc))
            # Fall back to rule-based classification if LLM fails
            classify = _rule_based_classify(alert, proc_root, proc_parent)
            ilog.info("node3.classify_fallback", verdict=classify.verdict)

        # ── Node 4: deterministic AAP remediation ────────────────────────────
        ilog.info("pipeline.node4", step="remediate", verdict=classify.verdict)
        actions_taken = await _node_remediate(
            self._aap_tools, classify.verdict, root_pid, ilog
        )

        # ── Node 5: LLM summary paragraph ────────────────────────────────────
        ilog.info("pipeline.node5", step="report")
        try:
            summary = await _node_report(
                self._llm, alert, host,
                proc_root, proc_parent, journal, network,
                classify, actions_taken,
                ilog,
            )
        except Exception as exc:
            ilog.error("node5.report_failed", error=str(exc))
            summary = (
                f"Automated investigation confirmed {classify.verdict} "
                f"({', '.join(classify.cve_ids) or 'unknown CVE'}). "
                f"Remediation actions: {', '.join(actions_taken) or 'none'}."
            )

        # ── Assemble final report (pure Python) ──────────────────────────────
        evidence = _build_evidence(alert, proc_root, proc_parent, journal, network)
        next_steps = _recommended_next_steps(classify.verdict, classify.cve_ids)

        report = IncidentReport(
            incident_id=incident_id,
            rule=alert.rule,
            host=host,
            verdict=classify.verdict,
            cve_ids=classify.cve_ids,
            summary=summary,
            evidence=evidence,
            actions_taken=actions_taken,
            recommended_next_steps=next_steps,
        )
        ilog.info(
            "incident.report",
            verdict=report.verdict,
            cves=report.cve_ids,
            actions=len(report.actions_taken),
        )

        # ── Write report to host via AAP playbook ────────────────────────────
        # Done after assembly so the full report (including summary and
        # actions_taken with real job IDs) is persisted to the host.
        await _write_report_to_host(self._aap_tools, incident_id, report, ilog)

        return report


# ---------------------------------------------------------------------------
# Pure-Python helpers for classification fallback, evidence, next steps
# ---------------------------------------------------------------------------

def _rule_based_classify(alert, proc_root: str, proc_parent: str) -> ClassifyResult:
    """Deterministic fallback if the LLM classifier fails."""
    combined = (proc_root + proc_parent + alert.output).lower()
    is_root_shell = "uid=0" in combined or "user=root" in combined
    has_user_parent = any(u in combined for u in ("uid=1000", "cloud-user", "cloud-u"))
    copy_fail_tags = "copy_fail" in " ".join(alert.tags).lower()

    if is_root_shell and has_user_parent and "Root Shell" in alert.rule:
        return ClassifyResult(
            verdict="confirmed_threat",
            cve_ids=["CVE-2026-31431"],
            confidence_notes="Rule-based: root shell (uid=0) with non-root parent matches Copy Fail fingerprint.",
        )
    if copy_fail_tags or is_root_shell:
        return ClassifyResult(
            verdict="likely_threat",
            cve_ids=["CVE-2026-31431"] if copy_fail_tags else [],
            confidence_notes="Rule-based: suspicious signals present but parent process not confirmed.",
        )
    return ClassifyResult(
        verdict="inconclusive",
        cve_ids=[],
        confidence_notes="Rule-based: insufficient evidence for classification.",
    )


def _build_evidence(alert, proc_root: str, proc_parent: str, journal: str, network: str) -> list[str]:
    items: list[str] = []
    if alert.output:
        items.append(f"Falco: {alert.output[:300]}")
    if proc_root:
        items.append(f"Root shell process: {proc_root[:300]}")
    if proc_parent:
        items.append(f"Parent process: {proc_parent[:300]}")
    if journal and "algif" in journal.lower():
        items.append("Journal: AF_ALG (algif) socket activity detected near alert time")
    elif journal:
        items.append(f"Journal: {journal[:200]}")
    if network and network.strip() and "ERROR" not in network:
        items.append(f"Network: {network[:200]}")
    return items or ["No tool output captured"]


def _recommended_next_steps(verdict: str, cve_ids: list[str]) -> list[str]:
    steps = []
    if "CVE-2026-31431" in cve_ids:
        steps.append("Apply kernel patch for CVE-2026-31431 (Copy Fail page cache corruption)")
    if verdict in ("confirmed_threat", "likely_threat"):
        steps.extend([
            "Review /var/log/security-incidents/ for the audit record written by lock_user playbook",
            "Rotate SSH keys and credentials for cloud-user",
            "Monitor host for re-exploitation attempts",
            "File incident ticket with forensic artifacts",
        ])
    else:
        steps.append("Monitor host — alert may be a false positive")
    return steps


# ---------------------------------------------------------------------------
# Agent factory (called once at startup)
# ---------------------------------------------------------------------------

async def build_agent() -> ThreatResponseAgent:
    log.info("agent.build", model=AGENT_MODEL)

    mcp_client = MultiServerMCPClient(
        {
            "linux": {
                "transport": "stdio",
                "command": "ssh",
                "args": [
                    "-i", LINUX_MCP_SSH_KEY,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    f"{LINUX_MCP_SSH_USER}@{LINUX_MCP_SSH_HOST}",
                    LINUX_MCP_CMD,
                ],
            },
            "aap": {
                "url": AAP_MCP_URL,
                "transport": "streamable_http",
                "headers": {"Authorization": f"Bearer {AAP_TOKEN}"} if AAP_TOKEN else {},
            },
        }
    )

    all_tools = await mcp_client.get_tools()

    linux_raw = {t.name: t for t in all_tools if t.name in LINUX_TOOLS}
    aap_raw   = {t.name: t for t in all_tools if t.name in AAP_TOOLS}

    # Strip host param from every linux tool
    linux_tools = {name: _strip_host_param(t) for name, t in linux_raw.items()}
    aap_tools   = dict(aap_raw)

    log.info(
        "agent.tools_loaded",
        linux=list(linux_tools.keys()),
        aap=list(aap_tools.keys()),
    )

    llm = _build_llm()

    return ThreatResponseAgent(linux_tools, aap_tools, llm)
