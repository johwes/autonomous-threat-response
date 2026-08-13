"""
Autonomous Threat Response Agent — webhook entrypoint.

Receives Falco alert webhooks, runs a LangGraph ReAct agent that investigates
via linux-mcp-server and remediates via AAP MCP server, and returns a
structured incident report.
"""

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agent import build_agent, IncidentReport

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Falco webhook schema
# ---------------------------------------------------------------------------

class FalcoAlert(BaseModel):
    rule: str
    priority: str
    output: str
    output_fields: dict[str, Any] = Field(default_factory=dict)
    hostname: str = ""
    time: str = ""
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

_agent = None
_agent_task = None


async def _build_agent_background():
    """Build the agent asynchronously so uvicorn can start serving /healthz
    immediately. SSH connections to the RHEL VM can take 10-30s; without this
    the liveness probe kills the pod before startup completes.

    Retries indefinitely with exponential backoff so a transient SSH timeout
    (e.g. VM IP change, cold start) doesn't permanently disable the agent."""
    global _agent
    delay = 5
    attempt = 0
    while True:
        attempt += 1
        try:
            log.info("agent.startup", msg="Building LangGraph agent with MCP tools (background)", attempt=attempt)
            _agent = await build_agent()
            log.info("agent.ready")
            return
        except Exception as exc:
            log.error("agent.startup_failed", error=str(exc), attempt=attempt, retry_in=delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)  # cap at 60s between retries


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _agent_task
    # Fire agent build in the background — /healthz responds immediately
    _agent_task = asyncio.create_task(_build_agent_background())
    yield
    if _agent_task and not _agent_task.done():
        _agent_task.cancel()
    log.info("agent.shutdown")


app = FastAPI(
    title="Autonomous Threat Response Agent",
    version="0.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    # Always returns 200 — the liveness probe only needs the process to be alive.
    # Agent readiness is reported separately so probes don't kill the pod mid-startup.
    return {"status": "ok", "agent_ready": _agent is not None}


@app.post("/webhook", response_model=IncidentReport)
async def webhook(alert: FalcoAlert, request: Request):
    incident_id = str(uuid.uuid4())[:8]
    log.info(
        "webhook.received",
        incident_id=incident_id,
        rule=alert.rule,
        priority=alert.priority,
        host=alert.hostname,
    )

    if _agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent not ready",
        )

    try:
        report = await _agent.ainvoke(alert, incident_id=incident_id)
    except Exception as exc:
        log.error("agent.error", incident_id=incident_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent error: {exc}",
        ) from exc

    log.info(
        "webhook.complete",
        incident_id=incident_id,
        verdict=report.verdict,
        actions_taken=report.actions_taken,
    )
    return report


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8080")),
        log_level="info",
    )
