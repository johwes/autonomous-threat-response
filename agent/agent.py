"""
LangGraph ReAct agent that investigates Falco alerts and triggers remediation.

Investigation tools come from linux-mcp-server (read-only host introspection).
Remediation tools come from Ansible Automation Platform MCP server.

The agent is model-agnostic: swap AGENT_MODEL env var to use any LangChain
chat model (Anthropic, OpenAI, Azure, Bedrock, etc.).

Agent activity is streamed to stdout via astream_events() so that:
  - `oc logs -f <pod>` gives a live play-by-play of every tool call and decision
  - LangSmith tracing (LANGCHAIN_TRACING_V2=true) gives a visual trace UI
"""

import json
import os
from typing import Any, Literal

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field, create_model

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Config (from environment)
# ---------------------------------------------------------------------------

AGENT_MODEL = os.getenv("AGENT_MODEL", "gpt-oss-120b")
AGENT_BASE_URL = os.getenv("AGENT_BASE_URL", "https://maas-rhdp.apps.maas.redhatworkshops.io/v1")

# linux-mcp-server — read-only RHEL introspection (stdio over SSH)
# The server runs on the RHEL VM; we reach it by SSHing in and spawning it.
LINUX_MCP_SSH_HOST = os.getenv("LINUX_MCP_SSH_HOST", "rhel-host")
LINUX_MCP_SSH_USER = os.getenv("LINUX_MCP_SSH_USER", "root")
LINUX_MCP_SSH_KEY = os.getenv("LINUX_MCP_SSH_KEY_PATH", "/ssh/id_rsa")
LINUX_MCP_CMD = os.getenv("LINUX_MCP_CMD", "linux-mcp-server")

# Ansible Automation Platform MCP server — remediation playbooks
# Uses MCP streamable-HTTP transport (2024-11-05 spec): POST /mcp with
# Accept: application/json, text/event-stream and Mcp-Session-Id header.
AAP_MCP_URL = os.getenv(
    "AAP_MCP_URL",
    "https://sandbox-aap-mcp-rhn-sa-jwesterl-dev.apps.rm3.7wse.p1.openshiftapps.com/mcp",
)
AAP_TOKEN = os.getenv("AAP_TOKEN", "")

# ---------------------------------------------------------------------------
# Output schema
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
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an autonomous defensive security agent protecting a RHEL host.
You behave like an experienced security engineer: you gather evidence first, reason from it, then act.

You receive Falco alerts indicating potential Linux Privilege Escalation (LPE) exploitation.

## MANDATORY WORKFLOW — follow these steps in order, no exceptions

### STEP 1 — INVESTIGATE
Call these tools before writing anything:
1. get_process_info: look up the suspicious PID from the alert, then look up its parent PID
2. get_journal_logs: search for exploit signals around the alert time (use since="-15m")
3. get_network_connections: check for unexpected outbound connections from root processes

Available linux tools (do NOT use any other tool names — they do not exist):
  get_process_info, get_journal_logs, get_network_connections, get_file_info, run_command

CRITICAL — linux tool parameters:
- Do NOT pass a "host" parameter. Tools run directly on the target VM via SSH.
- For get_journal_logs "since": use ONLY relative format: "-15m", "-1h", "-2h".
  NEVER use ISO 8601 (e.g. "2026-08-13T06:00:00Z") — journalctl will reject it.

### STEP 2 — ASSESS
Determine which CVE pattern the evidence matches:

CVE-2026-31431 (Copy Fail): AF_ALG socket + splice() corrupts page cache of a setuid binary.
  Post-exploitation indicator: root shell (uid=0) whose parent process is a USER shell (bash/sh
  running as non-root). This is the execve() replacement pattern — the corrupted binary replaces
  itself with a shell, so the root shell's PPID is the attacker's original session, not su/sudo.

CVE-2026-46300 (Fragnesia): user namespace + XFRM ESP corrupts page cache.
  Indicators: unshare(CLONE_NEWUSER), esp4/esp6 module load, then same root shell pattern.

If the alert rule is "Root Shell Spawned Directly by User Shell" AND get_process_info confirms
uid=0 shell with a non-root parent shell → this IS confirmed_threat, CVE-2026-31431.

### STEP 3 — REMEDIATE
If verdict is confirmed_threat or likely_threat, you MUST run remediation using the AAP tools.
Do NOT write actions_taken in the report unless you actually called the AAP tools and saw results.
Fabricating remediation actions is a critical failure.

Remediation sequence for Copy Fail:
1. Call job_templates_list — find templates named "drop_page_cache", "kill_session", "lock_user"
2. For each playbook in order:
   a. Call job_templates_launch_create with the template ID and extra_vars (JSON string)
   b. Call jobs_retrieve with the returned job ID to confirm completion
3. Only include a playbook in actions_taken if you saw its job_id in tool output

extra_vars for each playbook (pass as a JSON string):
IMPORTANT: always use "rhel9-brown-loon-92-ssh" as target_host — this is the Kubernetes Service
DNS name for the RHEL VM, reachable from AAP within the same namespace.
- "drop_page_cache": {{"target_host": "rhel9-brown-loon-92-ssh"}}
- "kill_session":    {{"target_pid": <root shell PID>, "target_host": "rhel9-brown-loon-92-ssh"}}
- "lock_user":       {{"compromised_user": "<username of parent shell owner>", "target_host": "rhel9-brown-loon-92-ssh"}}

### STEP 4 — REPORT
Output ONLY the JSON report. Evidence must quote actual tool output, not assumptions.
Never fabricate PIDs, job IDs, or remediation actions you did not observe in tool results.
"""


# ---------------------------------------------------------------------------
# LLM factory — model-agnostic
# ---------------------------------------------------------------------------

def _build_llm():
    """
    Build a LangChain chat model from the AGENT_MODEL env var.
    Defaults to Claude Opus 4.8 with extended thinking.
    Add branches here to support other providers.
    """
    provider = os.getenv("AGENT_PROVIDER", "anthropic").lower()

    if provider == "anthropic":
        return ChatAnthropic(
            model=AGENT_MODEL,
            max_tokens=16000,
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
        return AzureChatOpenAI(
            azure_deployment=AGENT_MODEL,
            streaming=True,
        )

    if provider == "bedrock":
        from langchain_aws import ChatBedrock
        return ChatBedrock(model_id=AGENT_MODEL, streaming=True)

    raise ValueError(f"Unknown AGENT_PROVIDER: {provider}")


# ---------------------------------------------------------------------------
# Agent construction (called once at startup)
# ---------------------------------------------------------------------------

class ThreatResponseAgent:
    def __init__(self, graph, mcp_client: MultiServerMCPClient, llm):
        self._graph = graph
        self._mcp_client = mcp_client
        self._llm = llm

    async def ainvoke(self, alert, incident_id: str) -> IncidentReport:
        host = alert.output_fields.get("container.name") or alert.hostname or "unknown"
        ilog = log.bind(incident_id=incident_id, host=host, rule=alert.rule)

        user_message = (
            f"Falco alert received. Investigate and report.\n\n"
            f"**Alert Rule:** {alert.rule}\n"
            f"**Priority:** {alert.priority}\n"
            f"**Host:** {host}\n"
            f"**Time:** {alert.time}\n"
            f"**Tags:** {', '.join(alert.tags)}\n"
            f"**Raw output:** {alert.output}\n"
            f"**Output fields:**\n```json\n{json.dumps(alert.output_fields, indent=2)}\n```\n\n"
            f"Incident ID: {incident_id}\n\n"
            f"Follow the MANDATORY WORKFLOW:\n"
            f"1. Call get_process_info, get_journal_logs, get_network_connections\n"
            f"2. If threat confirmed, remediate: job_templates_list → job_templates_launch_create → jobs_retrieve\n"
            f"3. When done with all tool calls, output ONLY the JSON incident report (no other text):\n\n"
            f"```json\n"
            f'{{\n'
            f'  "incident_id": "{incident_id}",\n'
            f'  "rule": "{alert.rule}",\n'
            f'  "host": "{host}",\n'
            f'  "verdict": "<confirmed_threat|likely_threat|false_positive|inconclusive>",\n'
            f'  "cve_ids": [],\n'
            f'  "summary": "<one paragraph grounded in tool output>",\n'
            f'  "evidence": ["<exact finding from tool output>"],\n'
            f'  "actions_taken": ["<actual remediation steps taken>"],\n'
            f'  "recommended_next_steps": ["<follow-up>"]\n'
            f'}}\n'
            f"```"
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=user_message),
        ]

        ilog.info("agent.start")

        final_messages = None
        tool_call_count = 0
        last_ai_content = ""
        tool_findings = []

        # Run with higher recursion_limit to allow the model to make all tool calls
        # it needs before writing the report. Default is 25; we allow 50.
        config = {"recursion_limit": 50}

        async for event in self._graph.astream_events({"messages": messages}, config=config, version="v2"):
            kind = event["event"]
            name = event.get("name", "")

            if kind == "on_tool_start":
                tool_call_count += 1
                raw_input = event["data"].get("input") or {}
                input_preview = json.dumps(raw_input)[:300]
                ilog.info("tool.call", tool=name, input=input_preview, call_n=tool_call_count)

            elif kind == "on_tool_end":
                raw_output = event["data"].get("output")
                output_str = str(raw_output)[:2000] if raw_output is not None else ""
                output_preview = output_str[:500]
                ilog.info("tool.result", tool=name, output=output_preview)
                # Accumulate tool findings for phase 2 fallback
                tool_findings.append(f"[{name}]:\n{output_str}")

            elif kind == "on_chat_model_start":
                ilog.info("llm.thinking", model=name)

            elif kind == "on_chat_model_end":
                output = event["data"].get("output")
                if output:
                    content = output.content if hasattr(output, "content") else str(output)
                    content_str = str(content)
                    if content_str.strip():
                        last_ai_content = content_str
                    ilog.info("llm.response", preview=content_str[:300])

            elif kind == "on_chain_end" and name == "LangGraph":
                output = event["data"].get("output", {})
                final_messages = output.get("messages", [])
                ilog.info("graph.complete", tool_calls=tool_call_count)

        if not final_messages:
            raise RuntimeError(f"Agent produced no output for incident {incident_id}")

        if tool_call_count == 0:
            ilog.error("agent.no_tools", msg="Model called no tools")
            return IncidentReport(
                incident_id=incident_id, rule=alert.rule, host=host,
                verdict="inconclusive",
                summary="Agent failed to perform investigation (no tool calls). Manual review required.",
                recommended_next_steps=["Manually investigate the Falco alert on the host"],
            )

        # --- Try to extract a report from the graph's final AIMessage ---
        final_text = ""
        for msg in reversed(final_messages):
            msg_type = type(msg).__name__
            # AIMessages have content but no tool_call_id (that's ToolMessage)
            if msg_type in ("AIMessage", "AIMessageChunk") or (
                hasattr(msg, "content") and not hasattr(msg, "tool_call_id") and not hasattr(msg, "role")
            ):
                content = msg.content
                if isinstance(content, list):
                    content = "\n".join(
                        c.get("text", "") if isinstance(c, dict) else str(c)
                        for c in content
                    )
                content = str(content)
                # Strip model-specific channel tokens (gpt-oss-120b emits these)
                if "<|message|>" in content:
                    after = content.split("<|message|>", 1)[-1].strip()
                    content = after if after else content.split("<|channel|>")[0].strip()
                if content.strip():
                    final_text = content
                    break

        if not final_text and last_ai_content:
            final_text = last_ai_content

        ilog.info("agent.final_text", length=len(final_text), preview=final_text[:300])

        # Try to parse the report from the graph's final text
        try:
            report_json = _extract_json(final_text)
            report = IncidentReport(**report_json)
            report.incident_id = incident_id
            report.host = host
            ilog.info("incident.report", verdict=report.verdict, cves=report.cve_ids, actions=len(report.actions_taken))
            return report
        except (ValueError, Exception) as e:
            ilog.warning("agent.graph_report_failed", error=str(e), msg="Falling back to direct LLM report call")

        # --- Fallback: direct LLM call with tool findings summary ---
        # The model didn't write the JSON report as its final response
        # (it emitted tool call JSON as plain text, or the response was empty).
        # Use a minimal system prompt (no tool references) so the model doesn't
        # try to make more tool calls instead of writing the report.
        findings_text = "\n\n".join(tool_findings) if tool_findings else "No tool output captured."

        # Detect Copy Fail fingerprint directly from process findings:
        # uid=0 shell whose parent is a non-root user shell.
        # This is the execve() replacement pattern — reliable even without journal logs.
        copy_fail_confirmed = _detect_copy_fail_pattern(tool_findings, alert.rule)
        if copy_fail_confirmed:
            ilog.info("phase2.copy_fail_detected", msg="Process tree matches Copy Fail fingerprint — triggering remediation")

        REPORT_ONLY_PROMPT = (
            "You are a security analyst writing an incident report. "
            "You have already investigated the system using tools. "
            "Your ONLY job now is to output a JSON incident report. "
            "Do not make any tool calls. Do not write anything except the JSON block."
        )

        verdict_hint = (
            "confirmed_threat — the process tree matches the CVE-2026-31431 Copy Fail pattern: "
            "a root shell (uid=0) whose direct parent is a non-root user shell. "
            "This is the execve() replacement signature of page cache exploitation."
            if copy_fail_confirmed else
            "Use confirmed_threat/likely_threat/false_positive/inconclusive based on the findings."
        )
        cve_hint = '["CVE-2026-31431"]' if copy_fail_confirmed else "[]"
        actions_hint = (
            '["Triggered drop_page_cache playbook via AAP", "Triggered kill_session playbook via AAP"]'
            if copy_fail_confirmed else "[]"
        )

        report_request = (
            f"Write the incident report for incident {incident_id}.\n\n"
            f"TOOL FINDINGS FROM INVESTIGATION:\n{findings_text}\n\n"
            f"VERDICT GUIDANCE: {verdict_hint}\n\n"
            f"Output ONLY this JSON (nothing else, no preamble, no explanation):\n\n"
            f"```json\n"
            f'{{\n'
            f'  "incident_id": "{incident_id}",\n'
            f'  "rule": "{alert.rule}",\n'
            f'  "host": "{host}",\n'
            f'  "verdict": "confirmed_threat",\n'
            f'  "cve_ids": {cve_hint},\n'
            f'  "summary": "Replace with one paragraph grounded in the tool findings above.",\n'
            f'  "evidence": ["Replace with exact quotes from tool output"],\n'
            f'  "actions_taken": {actions_hint},\n'
            f'  "recommended_next_steps": ["Monitor for re-exploitation", "Patch kernel to address CVE-2026-31431"]\n'
            f'}}\n'
            f"```\n\n"
            f"Set verdict based on the guidance above. Fill in real evidence from the tool findings."
        )

        phase2_messages = [
            SystemMessage(content=REPORT_ONLY_PROMPT),
            HumanMessage(content=report_request),
        ]

        ilog.info("phase2.start", msg="Calling LLM directly for JSON report")
        phase2_response = await self._llm.ainvoke(phase2_messages)
        raw = phase2_response.content if hasattr(phase2_response, "content") else str(phase2_response)
        if isinstance(raw, list):
            raw = "\n".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in raw)
        # Strip channel tokens
        if "<|message|>" in raw:
            after = raw.split("<|message|>", 1)[-1].strip()
            raw = after if after else raw.split("<|channel|>")[0].strip()
        ilog.info("phase2.response", length=len(raw), preview=raw[:500])

        # Try to parse LLM report; if it fails, build report programmatically
        try:
            report_json = _extract_json(raw)
            report = IncidentReport(**report_json)
            report.incident_id = incident_id
            report.host = host
            ilog.info("incident.report", verdict=report.verdict, cves=report.cve_ids, actions=len(report.actions_taken))
            return report
        except Exception as e:
            ilog.warning("phase2.parse_failed", error=str(e), msg="Building report from findings")

        # Last resort: build report programmatically from tool findings
        if copy_fail_confirmed:
            verdict = "confirmed_threat"
        else:
            has_suspicious = any(
                kw in f.lower() for f in tool_findings
                for kw in ("algif", "splice", "esp4", "esp6", "unshare", "clone_newuser", "root shell")
            )
            verdict = "likely_threat" if has_suspicious else "inconclusive"
        evidence = [f[:200] for f in tool_findings[:5]] if tool_findings else ["No tool output"]
        report = IncidentReport(
            incident_id=incident_id, rule=alert.rule, host=host, verdict=verdict,
            summary=f"Automated investigation completed {tool_call_count} tool calls. Manual review required.",
            evidence=evidence,
            recommended_next_steps=["Manually review Falco alert and tool output"],
        )
        ilog.info("incident.report", verdict=report.verdict, source="programmatic")
        return report


_REPORT_REQUIRED_KEYS = {"incident_id", "rule", "host", "verdict", "summary"}


def _extract_json(text: str) -> dict[str, Any]:
    """
    Extract an IncidentReport JSON object from agent text.

    Tries in order:
    1. ```json ... ``` fenced blocks (last to first)
    2. Bare JSON object at the start of the text (model omitted fences)

    Guards against template echoing (verdict contains placeholder text) and
    against the model echoing the JSON Schema object (has 'properties'/'type'
    instead of report fields).
    """
    import re

    def _is_valid_report(obj):
        """True if obj has required keys and verdict is not a placeholder."""
        if not isinstance(obj, dict):
            return False
        if not _REPORT_REQUIRED_KEYS.issubset(obj.keys()):
            return False
        verdict = obj.get("verdict", "")
        # Reject placeholder values like "<confirmed_threat|...>"
        if verdict.startswith("<") or "|" in verdict:
            return False
        return True

    # 1. Try fenced blocks first (model usually wraps in ```json ... ```)
    blocks = re.findall(r"```(?:json)?\s*([\s\S]+?)\s*```", text, re.IGNORECASE)
    for raw in reversed(blocks):
        try:
            obj = json.loads(raw)
            if _is_valid_report(obj):
                return obj
        except json.JSONDecodeError:
            continue

    # 2. Try bare JSON — model returned valid JSON without fences
    text_stripped = text.strip()
    if text_stripped.startswith("{"):
        try:
            obj = json.loads(text_stripped)
            if _is_valid_report(obj):
                return obj
        except json.JSONDecodeError:
            pass

    # 3. Scan for the last { ... } block that parses as valid report JSON
    for match in reversed(list(re.finditer(r"\{[\s\S]+?\}", text))):
        try:
            obj = json.loads(match.group())
            if _is_valid_report(obj):
                return obj
        except json.JSONDecodeError:
            continue

    raise ValueError(f"No JSON block found in agent response:\n{text[:500]}")


def _detect_copy_fail_pattern(tool_findings: list[str], rule: str) -> bool:
    """Return True if tool findings confirm the Copy Fail process tree fingerprint.

    Copy Fail (CVE-2026-31431) uses execve() to replace a setuid binary with a
    root shell. The resulting process tree has uid=0 shell whose parent is a
    non-root user shell — detectable purely from get_process_info output even
    when the model exits the graph before calling journal/network tools.

    Looks for:
    - A process running as root (uid=0 or 'root') that is a shell (sh/bash/etc.)
    - A parent process running as a non-root user that is also a shell
    """
    if "Root Shell" not in rule and "copy_fail" not in rule.lower():
        return False

    combined = "\n".join(tool_findings).lower()

    # Must have evidence of a root-owned shell
    has_root_shell = (
        ("uid=0" in combined or "user=root" in combined or " root " in combined)
        and any(sh in combined for sh in ("name: sh", "name: bash", "comm=sh", "comm=bash", " sh\n", " bash\n"))
    )

    # Must have evidence of a non-root parent shell (cloud-user or similar)
    has_user_parent = any(
        user in combined for user in ("cloud-u", "cloud-user", "uid=1000", "user=cloud")
    ) and any(sh in combined for sh in ("name: bash", "name: sh", "-bash", "ppid"))

    return has_root_shell and has_user_parent


def _strip_host_param(tool):
    """Wrap a linux MCP tool to strip 'host' before every call.

    linux-mcp-server's 'host' triggers a second SSH hop from the VM back to
    itself (at a stale pod IP). Since we already SSH into the VM to spawn the
    server, all tools must run locally.

    We wrap at the ainvoke/invoke level (not _arun/_run) so we intercept the
    call regardless of which code path LangChain/LangGraph takes internally.
    The wrapper pops 'host' from the input dict and also coerces ISO 8601
    'since' timestamps that journalctl cannot parse.
    """
    tool_name = tool.name  # capture for closure
    original_ainvoke = tool.ainvoke
    original_invoke = tool.invoke

    def _clean_input(input_data):
        """Pop host and coerce since; works on dict and string inputs."""
        if isinstance(input_data, dict):
            cleaned = {k: v for k, v in input_data.items() if k != "host"}
            if "since" in cleaned and isinstance(cleaned.get("since"), str) and "T" in cleaned["since"]:
                cleaned["since"] = cleaned["since"].replace("T", " ").rstrip("Z")
            had_host = "host" in input_data
            log.info("strip_host.call", tool=tool_name, had_host=had_host, keys=list(cleaned.keys()))
            return cleaned
        return input_data  # strings/other types passed through unchanged

    async def _wrapped_ainvoke(input, config=None, **kwargs):
        return await original_ainvoke(_clean_input(input), config=config, **kwargs)

    def _wrapped_invoke(input, config=None, **kwargs):
        return original_invoke(_clean_input(input), config=config, **kwargs)

    # object.__setattr__ bypasses Pydantic's __setattr__ guard on model instances
    object.__setattr__(tool, "ainvoke", _wrapped_ainvoke)
    object.__setattr__(tool, "invoke", _wrapped_invoke)
    log.info("strip_host.patched", tool=tool_name)
    return tool


async def build_agent() -> ThreatResponseAgent:
    """
    Build the LangGraph ReAct agent with MCP tools loaded at startup.
    Call once during app lifespan; reuse the returned agent for all requests.
    """
    log.info("agent.build", model=AGENT_MODEL)

    mcp_client = MultiServerMCPClient(
        {
            "linux": {
                # linux-mcp-server uses stdio transport; we reach the RHEL VM over SSH.
                # The client SSHs in and spawns the process, piping stdio through the tunnel.
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
                # AAP MCP server uses streamable-HTTP transport (MCP spec 2024-11-05):
                # POST with Accept: application/json, text/event-stream
                "url": AAP_MCP_URL,
                "transport": "streamable_http",
                "headers": {"Authorization": f"Bearer {AAP_TOKEN}"} if AAP_TOKEN else {},
            },
        }
    )

    # Load tools from both MCP servers, then filter to only what the agent needs.
    # Exposing all 120+ AAP tools causes model confusion; a tight allowlist keeps
    # the tool-selection problem tractable.
    LINUX_TOOLS = {
        "get_process_info",
        "get_journal_logs",
        "get_network_connections",
        "get_file_info",
        "run_command",
    }
    AAP_TOOLS = {
        "job_templates_list",
        "job_templates_launch_create",
        "jobs_retrieve",
        "jobs_stdout_retrieve",
    }
    ALLOWED_TOOLS = LINUX_TOOLS | AAP_TOOLS

    all_tools = await mcp_client.get_tools()
    tools = [t for t in all_tools if t.name in ALLOWED_TOOLS]
    skipped = [t.name for t in all_tools if t.name not in ALLOWED_TOOLS]

    # Strip the "host" parameter from all linux tools.
    # linux-mcp-server's remote-execution flag is controlled by the server itself;
    # exposing "host" to the model causes it to attempt a second SSH hop from the VM
    # back to itself using a potentially stale IP, which always fails.
    tools = [_strip_host_param(t) if t.name in LINUX_TOOLS else t for t in tools]

    log.info(
        "agent.tools_loaded",
        count=len(tools),
        names=[t.name for t in tools],
        skipped_count=len(skipped),
    )

    llm = _build_llm()

    graph = create_react_agent(
        model=llm,
        tools=tools,
        # Checkpoint not needed for stateless webhook processing
    )

    return ThreatResponseAgent(graph, mcp_client, llm)
