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

You receive Falco alerts indicating potential Linux Privilege Escalation (LPE) exploitation.

## MANDATORY WORKFLOW — you MUST follow these steps in order

### STEP 1 — INVESTIGATE (REQUIRED, no exceptions)
You MUST call at least these linux-mcp-server tools before writing any report:
- get_process_info: inspect the suspicious process and its full parent chain
- get_audit_logs: look for AF_ALG sockets, splice(), unshare(), ESP module loads
- get_journal_logs: look for kernel panic/oops messages around the event time
- get_network_connections: check for unexpected outbound connections from root shells

IMPORTANT — linux tool parameters:
- Do NOT pass a "host" parameter to linux tools. The tools already run directly on
  the target RHEL VM (linux-mcp-server is spawned there via SSH). Passing "host"
  causes a second SSH hop to a potentially stale IP and will fail.
- For get_journal_logs "since": use relative format only, e.g. "-1h", "-30m", "-2h".
  Do NOT use ISO 8601 timestamps (e.g. "2026-08-13T06:00:00Z") — journalctl will
  reject them and the tool will return an error.
- Call tools with only the parameters they need (e.g. pid, since, lines).

DO NOT write the incident report until you have called tools and seen their output.
Responding without tool calls is a critical failure — you will be re-prompted.

### STEP 2 — REASON
Based on the actual tool output, determine which CVE pattern matches (if any):
- CVE-2026-31431 (Copy Fail): AF_ALG socket + splice() → page cache corruption
  Indicators: algif_aead usage, setuid binary spawning root shell
- CVE-2026-46300 (Fragnesia): user namespace + XFRM ESP → page cache corruption
  Indicators: unshare(CLONE_NEWUSER), esp4/esp6 module load, setuid binary spawning root shell

### STEP 3 — REMEDIATE (only if threat confirmed from tool evidence)
Use AAP tools to run playbooks. First call job_templates_list to get the template ID,
then job_templates_launch_create to run it, then jobs_retrieve to confirm completion.
- "kill_session": extra_vars {target_pid, target_host} — terminate root shell
- "block_module": extra_vars {kernel_module, target_host} — blacklist kernel module
- "drop_page_cache": extra_vars {target_host} — evict corrupted cache entries
- "lock_user": extra_vars {compromised_user, target_host} — lock attacker account

IMPORTANT RULES:
- Evidence fields in the report MUST cite actual output from your tool calls, not assumptions.
- If tools show nothing suspicious, verdict must be false_positive or inconclusive.
- Both CVEs corrupt setuid binaries IN MEMORY — file integrity tools (rpm -V, AIDE) show clean.
- Never fabricate PIDs, usernames, module names, or job results you did not observe in tools.
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

        # Single-phase: send the full alert + report template in one message.
        # The ReAct graph runs tool calls then the model writes the JSON report
        # as its final (non-tool) response. We extract JSON from that last message.
        #
        # A two-phase approach (separate investigation + report calls) causes the
        # model to keep invoking tools during the "report" phase because it hasn't
        # finished investigating. Keeping everything in a single graph run lets the
        # model decide when it's done, which is exactly what ReAct is designed for.
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
            f"3. AFTER all tools, output your incident report as the LAST thing in your response:\n\n"
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
            f"```\n\n"
            f"Do NOT output the JSON template until you have finished all tool calls."
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=user_message),
        ]

        ilog.info("agent.start")

        final_messages = None
        tool_call_count = 0
        last_ai_content = ""

        async for event in self._graph.astream_events({"messages": messages}, version="v2"):
            kind = event["event"]
            name = event.get("name", "")

            if kind == "on_tool_start":
                tool_call_count += 1
                raw_input = event["data"].get("input") or {}
                input_preview = json.dumps(raw_input)[:300]
                ilog.info("tool.call", tool=name, input=input_preview, call_n=tool_call_count)

            elif kind == "on_tool_end":
                raw_output = event["data"].get("output")
                output_preview = str(raw_output)[:500] if raw_output is not None else ""
                ilog.info("tool.result", tool=name, output=output_preview)

            elif kind == "on_chat_model_start":
                ilog.info("llm.thinking", model=name)

            elif kind == "on_chat_model_end":
                output = event["data"].get("output")
                if output:
                    content = output.content if hasattr(output, "content") else str(output)
                    content_str = str(content)
                    # Track the last non-empty AI response — this will be the report
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

        # Extract final AI message text from graph output
        # Walk messages in reverse to find the last AIMessage with text content
        final_text = ""
        for msg in reversed(final_messages):
            msg_type = type(msg).__name__
            if msg_type in ("AIMessage", "AIMessageChunk") or (
                hasattr(msg, "content") and not hasattr(msg, "tool_call_id")
                and not hasattr(msg, "role")
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

        # Fallback to the streaming-captured last AI response if graph output failed
        if not final_text and last_ai_content:
            ilog.warning("agent.fallback_to_streamed", msg="Using streamed content since graph output was empty")
            final_text = last_ai_content

        ilog.info("agent.final_response", length=len(final_text), preview=final_text[:500])

        if not final_text.strip():
            return IncidentReport(
                incident_id=incident_id, rule=alert.rule, host=host,
                verdict="inconclusive",
                summary="Agent investigated but produced no report text.",
                recommended_next_steps=["Manually review Falco alert and tool output"],
            )

        report_json = _extract_json(final_text)
        report = IncidentReport(**report_json)
        report.incident_id = incident_id
        report.host = host

        ilog.info("incident.report", verdict=report.verdict, cves=report.cve_ids, actions=len(report.actions_taken))
        return report


_REPORT_REQUIRED_KEYS = {"incident_id", "rule", "host", "verdict", "summary"}


def _extract_json(text: str) -> dict[str, Any]:
    """
    Pull the last ```json ... ``` block from the agent's final message that
    looks like a filled-in IncidentReport (has the required keys).

    Guards against the model echoing the JSON Schema object itself (which is
    also valid JSON but contains "properties"/"type" instead of report fields).
    """
    import re
    blocks = re.findall(r"```json\s*([\s\S]+?)\s*```", text, re.IGNORECASE)
    if not blocks:
        raise ValueError(f"No JSON block found in agent response:\n{text[:500]}")

    # Walk blocks from last to first; return first one that has the report keys
    for raw in reversed(blocks):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and _REPORT_REQUIRED_KEYS.issubset(obj.keys()):
            return obj

    # Last resort: try the last block and let Pydantic surface the real error
    return json.loads(blocks[-1])


def _strip_host_param(tool):
    """Strip 'host' from linux MCP tools before every call.

    linux-mcp-server's 'host' triggers a second SSH hop from the VM back to
    itself (at a stale pod IP). Since we already SSH into the VM to spawn the
    server, all tools must run locally.

    Two-layer defence:
    1. Replace args_schema with a schema that omits 'host' and silently drops
       any extra fields (extra='ignore'). LangChain validates tool inputs
       through args_schema before calling _run/_arun, so host is stripped there.
    2. Monkey-patch _arun so even if host somehow slips through validation it
       is popped before reaching linux-mcp-server.
    """
    from pydantic import ConfigDict

    tool_name = tool.name  # capture for closure

    # --- 1. Replace args_schema ---
    schema = tool.args_schema
    # Pydantic v2 uses model_fields; v1 uses __fields__
    original_fields = (
        getattr(schema, "model_fields", None)
        or getattr(schema, "__fields__", None)
        or {}
    )
    if original_fields:
        # Build annotation/FieldInfo pairs without 'host'
        clean_fields = {}
        for k, v in original_fields.items():
            if k == "host":
                continue
            # Pydantic v2 FieldInfo has .annotation; v1 ModelField has .outer_type_
            annotation = getattr(v, "annotation", None) or getattr(v, "outer_type_", None) or str
            clean_fields[k] = (annotation, v)

        # Use __base__ (documented create_model param) to embed the ConfigDict
        class _IgnoreExtraBase(BaseModel):
            model_config = ConfigDict(extra="ignore")

        CleanSchema = create_model(
            f"{tool_name}_nohost",
            __base__=_IgnoreExtraBase,
            **clean_fields,
        )
        # args_schema is a typed Pydantic field on BaseTool; direct assignment works
        tool.args_schema = CleanSchema
        log.info("strip_host.schema_replaced", tool=tool_name, remaining_fields=list(clean_fields.keys()))
    else:
        log.warning("strip_host.no_schema_fields", tool=tool_name, schema_type=type(schema).__name__)

    # --- 2. Monkey-patch _arun ---
    # _arun is a class method (non-data descriptor), so instance __dict__ takes precedence.
    # object.__setattr__ bypasses Pydantic's __setattr__ to write directly to __dict__.
    original_arun = tool._arun  # capture bound method before replacement

    async def _patched_arun(**kwargs):
        had_host = "host" in kwargs
        kwargs.pop("host", None)
        if "since" in kwargs and isinstance(kwargs.get("since"), str) and "T" in kwargs["since"]:
            kwargs["since"] = kwargs["since"].replace("T", " ").rstrip("Z")
        log.info("strip_host.call", tool=tool_name, had_host=had_host, kwargs_keys=list(kwargs.keys()))
        return await original_arun(**kwargs)

    object.__setattr__(tool, "_arun", _patched_arun)
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
        "get_audit_logs",
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
