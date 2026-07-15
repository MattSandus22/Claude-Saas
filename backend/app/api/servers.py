"""MCP server registry + discovery (static scan) endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import Principal, get_current_user, get_ingest_principal, require_admin
from app.db.session import get_db
from app.detection.rules import analyze_tool_definition, combine_score
from app.models import Alert, AlertStatus, MCPServer, MCPTool, ServerStatus, Severity, User
from app.schemas import (
    MCPServerCreate,
    MCPServerOut,
    ScanFinding,
    ScanRequest,
    ScanResult,
)
from app.services.audit import record
from app.services.discovery import scan_files
from app.services.drift import diff_tool_sets, fingerprint_tool
from app.services.notify import notify_alerts

router = APIRouter(prefix="/servers", tags=["servers"])


async def _analyze_and_attach_tools(server: MCPServer, tools) -> float:
    """Attach tool defs to a server, scoring each for poisoning. Returns max risk."""
    max_risk = 0.0
    for t in tools:
        findings = analyze_tool_definition(t.name, t.description, t.input_schema)
        risk = combine_score(findings)
        max_risk = max(max_risk, risk)
        server.tools.append(
            MCPTool(
                name=t.name,
                description=t.description,
                input_schema=t.input_schema,
                is_suspicious=risk >= 35.0,
                risk_score=risk,
                fingerprint=fingerprint_tool(t.name, t.description, t.input_schema),
            )
        )
    return max_risk


@router.post("", response_model=MCPServerOut, status_code=201)
async def register_server(
    body: MCPServerCreate,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_ingest_principal),
):
    """Register a server (and optionally its tool definitions, which are scanned).

    Idempotent by endpoint: re-registering an existing server refreshes its
    tool set and runs **drift detection (R9)** — a changed tool definition
    after the initial baseline is the classic MCP "rug pull" and raises a
    high-severity alert with before/after fingerprints.
    """
    existing = await db.execute(
        select(MCPServer)
        .options(selectinload(MCPServer.tools))
        .where(MCPServer.endpoint == body.endpoint)
    )
    server = existing.scalar_one_or_none()
    drift_alerts: list[Alert] = []

    if server is None:
        server = MCPServer(
            name=body.name,
            endpoint=body.endpoint,
            transport=body.transport,
            source=body.source,
            status=ServerStatus.active,
        )
        max_risk = await _analyze_and_attach_tools(server, body.tools)
        server.risk_score = max_risk
        db.add(server)
        action = "server.register"
    else:
        # Drift pass: compare the approved baseline against the new report.
        # A server first seen without tools (e.g. via static scan) has no
        # baseline yet — its first tool report establishes one, no alerts.
        old_fps = {t.name: t.fingerprint for t in server.tools if t.fingerprint}
        if old_fps:
            new_fps = {
                t.name: fingerprint_tool(t.name, t.description, t.input_schema)
                for t in body.tools
            }
            for f in diff_tool_sets(old_fps, new_fps, server_name=server.name):
                drift_alerts.append(
                    Alert(
                        server_id=server.id,
                        rule_id=f.rule_id,
                        title=f.title,
                        description=f.detail,
                        severity=Severity(f.severity),
                        status=AlertStatus.open,
                        evidence=f.evidence,
                    )
                )

        # Replace the tool set with the fresh report (re-scanned for poisoning).
        server.tools.clear()
        max_risk = await _analyze_and_attach_tools(server, body.tools)
        server.risk_score = max(server.risk_score, max_risk)
        server.last_seen = datetime.now(timezone.utc)
        if server.status == ServerStatus.discovered:
            server.status = ServerStatus.active
        for alert in drift_alerts:
            db.add(alert)
        action = "server.reregister"

    await db.commit()
    for alert in drift_alerts:
        await db.refresh(alert)
    await notify_alerts(drift_alerts)

    # Re-load with tools eagerly for the response.
    server = await _get_server_or_404(db, server.id)
    await record(db, actor=principal.actor, action=action, target=server.id,
                 detail={"risk": max_risk, "drift_alerts": len(drift_alerts)})
    return server


@router.post("/scan", response_model=ScanResult)
async def scan(
    body: ScanRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(get_ingest_principal),
):
    """Static discovery scan.

    Accepts file contents (never disk paths) and returns discovered MCP servers,
    persisting any new ones as `discovered`.
    """
    discovered = scan_files(body.files)
    findings: list[ScanFinding] = []
    server_ids: list[str] = []

    for ds in discovered:
        # De-dupe against existing by endpoint.
        existing = await db.execute(
            select(MCPServer).where(MCPServer.endpoint == ds.endpoint)
        )
        server = existing.scalar_one_or_none()
        if server is None:
            server = MCPServer(
                name=ds.name,
                endpoint=ds.endpoint,
                transport=ds.transport,
                source="scan",
                status=ServerStatus.discovered,
                server_metadata={"source_file": ds.source_file, **ds.raw},
            )
            db.add(server)
            await db.flush()
        server_ids.append(server.id)
        findings.append(
            ScanFinding(
                file=ds.source_file,
                kind="mcp_server",
                detail=f"Discovered MCP server '{ds.name}' via {ds.raw.get('signal', 'config')}",
                endpoint=ds.endpoint,
                transport=ds.transport,
            )
        )

    await db.commit()
    await record(db, actor=principal.actor, action="server.scan",
                 detail={"files": len(body.files), "discovered": len(discovered)})
    return ScanResult(
        discovered_servers=len(discovered),
        findings=findings,
        server_ids=list(dict.fromkeys(server_ids)),
    )


@router.get("", response_model=list[MCPServerOut])
async def list_servers(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(MCPServer).options(selectinload(MCPServer.tools)).order_by(
            MCPServer.risk_score.desc()
        )
    )
    return list(result.scalars().all())


async def _get_server_or_404(db: AsyncSession, server_id: str) -> MCPServer:
    result = await db.execute(
        select(MCPServer).options(selectinload(MCPServer.tools)).where(
            MCPServer.id == server_id
        )
    )
    server = result.scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return server


@router.get("/{server_id}", response_model=MCPServerOut)
async def get_server(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return await _get_server_or_404(db, server_id)


@router.post("/{server_id}/quarantine", response_model=MCPServerOut)
async def quarantine_server(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Quarantine a server (admin-only). Marks it untrusted/blocked."""
    server = await _get_server_or_404(db, server_id)
    server.status = ServerStatus.quarantined
    await db.commit()
    await record(db, actor=admin.email, action="server.quarantine", target=server_id)
    return await _get_server_or_404(db, server_id)
