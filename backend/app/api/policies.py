"""Policy-as-code management endpoints (admin-only writes)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import func

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models import Policy, PolicyVersion, User
from app.schemas import (
    PolicyCreate,
    PolicyOut,
    PolicyVersionOut,
    SimulateRequest,
    SimulateResult,
)
from app.services.audit import record
from app.services.simulate import simulate_message

router = APIRouter(prefix="/policies", tags=["policies"])

# Allowed top-level keys in a policy rules doc. Unknown keys are rejected to
# catch typos and to keep the policy surface auditable.
_ALLOWED_RULE_KEYS = {
    "default",
    "allow_tools",
    "deny_tools",
    "deny_methods",
    "max_threat_score",
    "deny_agents",
    "require_agent_id",
}


async def _snapshot(
    db: AsyncSession, policy: Policy, *, changed_by: str, note: str
) -> PolicyVersion:
    """Append an immutable version snapshot for a policy. Caller commits."""
    current_max = (
        await db.execute(
            select(func.max(PolicyVersion.version)).where(
                PolicyVersion.policy_id == policy.id
            )
        )
    ).scalar_one()
    snap = PolicyVersion(
        policy_id=policy.id,
        version=(current_max or 0) + 1,
        name=policy.name,
        description=policy.description,
        enabled=policy.enabled,
        rules=policy.rules,
        changed_by=changed_by,
        change_note=note[:255],
    )
    db.add(snap)
    return snap


def _validate_rules(rules: dict) -> None:
    unknown = set(rules) - _ALLOWED_RULE_KEYS
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown policy rule keys: {sorted(unknown)}",
        )
    if "default" in rules and str(rules["default"]).lower() not in {"allow", "deny"}:
        raise HTTPException(status_code=422, detail="default must be 'allow' or 'deny'")


@router.get("", response_model=list[PolicyOut])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Policy).order_by(Policy.created_at.desc()))
    return list(result.scalars().all())


@router.post("/simulate", response_model=SimulateResult)
async def simulate(
    body: SimulateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Dry-run a message against detection + policy without persisting anything.

    Optionally supply `candidate_policies` to test a proposed policy before
    saving it. Candidate rule docs are validated the same way as real ones.
    """
    candidates = None
    if body.candidate_policies is not None:
        for cp in body.candidate_policies:
            _validate_rules(cp.rules)
        candidates = [{"name": cp.name, "rules": cp.rules} for cp in body.candidate_policies]

    result = await simulate_message(
        db,
        method=body.method,
        tool_name=body.tool_name,
        agent_id=body.agent_id,
        payload=body.payload,
        candidate_policies=candidates,
    )
    return SimulateResult(**result)


@router.post("", response_model=PolicyOut, status_code=201)
async def create_policy(
    body: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    _validate_rules(body.rules)
    exists = await db.execute(select(Policy).where(Policy.name == body.name))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Policy name already exists")
    policy = Policy(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        rules=body.rules,
    )
    db.add(policy)
    await db.flush()
    await _snapshot(db, policy, changed_by=admin.email, note="created")
    await db.commit()
    await db.refresh(policy)
    await record(db, actor=admin.email, action="policy.create", target=policy.id,
                 detail={"name": body.name})
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: str,
    body: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    _validate_rules(body.rules)
    policy = await db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.name = body.name
    policy.description = body.description
    policy.enabled = body.enabled
    policy.rules = body.rules
    await _snapshot(db, policy, changed_by=admin.email, note="updated")
    await db.commit()
    await db.refresh(policy)
    await record(db, actor=admin.email, action="policy.update", target=policy_id)
    return policy


@router.get("/{policy_id}/versions", response_model=list[PolicyVersionOut])
async def list_versions(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Full immutable change history for a policy, newest first."""
    if await db.get(Policy, policy_id) is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    result = await db.execute(
        select(PolicyVersion)
        .where(PolicyVersion.policy_id == policy_id)
        .order_by(PolicyVersion.version.desc())
    )
    return list(result.scalars().all())


@router.post("/{policy_id}/rollback/{version}", response_model=PolicyOut)
async def rollback(
    policy_id: str,
    version: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Restore a policy to a prior version.

    The restore itself is recorded as a NEW version (history is append-only;
    rolling back never rewrites it).
    """
    policy = await db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    snap = (
        await db.execute(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == policy_id,
                PolicyVersion.version == version,
            )
        )
    ).scalar_one_or_none()
    if snap is None:
        raise HTTPException(status_code=404, detail="Version not found")

    policy.name = snap.name
    policy.description = snap.description
    policy.enabled = snap.enabled
    policy.rules = snap.rules
    await _snapshot(
        db, policy, changed_by=admin.email, note=f"rollback to v{version}"
    )
    await db.commit()
    await db.refresh(policy)
    await record(db, actor=admin.email, action="policy.rollback", target=policy_id,
                 detail={"to_version": version})
    return policy


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    policy = await db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete(policy)
    await db.commit()
    await record(db, actor=admin.email, action="policy.delete", target=policy_id)
