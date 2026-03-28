"""
Database layer — SQLite for MVP (zero-config), optional PostgreSQL for production.

Usage:
    db = Database("sqlite+aiosqlite:///nur.db")
    await db.init()
    await db.store_eval_record(data)
"""
from __future__ import annotations

import datetime
import json
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession, async_sessionmaker, create_async_engine,
)
from sqlalchemy import select, func, text

from .models import (
    Base, Contribution, IOCHash, AttackTechnique, AggregatedScore,
    APIKeyRecord, PendingVerification, APIRequestLog,
)


class Database:
    def __init__(self, url: str = "sqlite+aiosqlite:///nur.db"):
        self.engine = create_async_engine(url, echo=False)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def init(self) -> None:
        """Create all tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self.engine.dispose()

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self.session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    # ── Store contributions ──────────────────────────────────────────────

    async def store_eval_record(self, data: dict[str, Any], submitted_by_hash: str | None = None) -> str:
        """Store an EvalRecord contribution. Returns contribution ID."""
        # Support both wire format {"context": {}, "data": {...}} and flat format {"vendor": ...}
        d = data.get("data", data)
        ctx = data.get("context", {})
        contrib = Contribution(
            contrib_type="eval",
            submitted_by_hash=submitted_by_hash,
            industry=ctx.get("industry"),
            org_size=ctx.get("org_size"),
            role=ctx.get("role"),
            vendor=d.get("vendor"),
            category=d.get("category"),
            overall_score=d.get("overall_score"),
            detection_rate=d.get("detection_rate"),
            fp_rate=d.get("fp_rate"),
            deploy_days=d.get("deploy_days"),
            cpu_overhead=d.get("cpu_overhead"),
            ttfv_hours=d.get("ttfv_hours"),
            would_buy=d.get("would_buy"),
            eval_duration_days=d.get("eval_duration_days"),
            top_strength=d.get("top_strength"),
            top_friction=d.get("top_friction"),
            notes=d.get("notes"),
        )
        async with self.session() as s:
            s.add(contrib)
            await s.flush()
            cid = contrib.id
        await self._refresh_aggregate(contrib.vendor)
        return cid

    async def store_attack_map(self, data: dict[str, Any], submitted_by_hash: str | None = None) -> str:
        """Store an AttackMap contribution. Returns contribution ID."""
        techniques = data.get("techniques", [])
        remediation = data.get("remediation", [])
        contrib = Contribution(
            contrib_type="attack_map",
            submitted_by_hash=submitted_by_hash,
            industry=data.get("context", {}).get("industry"),
            org_size=data.get("context", {}).get("org_size"),
            role=data.get("context", {}).get("role"),
            threat_name=data.get("threat_name"),
            techniques_json=json.dumps(techniques),
            tools_in_scope=json.dumps(data.get("tools_in_scope", [])),
            source=data.get("source", "practitioner"),
            notes=data.get("notes"),
            remediation_json=json.dumps(remediation) if remediation else None,
            time_to_detect=data.get("time_to_detect"),
            time_to_contain=data.get("time_to_contain"),
            time_to_recover=data.get("time_to_recover"),
            severity=data.get("severity"),
            data_exfiltrated=data.get("data_exfiltrated"),
            ransom_paid=data.get("ransom_paid"),
        )
        async with self.session() as s:
            s.add(contrib)
            await s.flush()
            cid = contrib.id
            # Store individual techniques
            for tech in techniques:
                s.add(AttackTechnique(
                    contribution_id=cid,
                    technique_id=tech.get("technique_id", ""),
                    technique_name=tech.get("technique_name"),
                    tactic=tech.get("tactic"),
                    observed=tech.get("observed", True),
                    detected_by=json.dumps(tech.get("detected_by", [])),
                    missed_by=json.dumps(tech.get("missed_by", [])),
                    notes=tech.get("notes"),
                ))
        return cid

    async def store_ioc_bundle(self, data: dict[str, Any], submitted_by_hash: str | None = None) -> str:
        """Store an IOCBundle contribution. Returns contribution ID."""
        iocs = data.get("iocs", [])
        contrib = Contribution(
            contrib_type="ioc_bundle",
            submitted_by_hash=submitted_by_hash,
            industry=data.get("context", {}).get("industry"),
            org_size=data.get("context", {}).get("org_size"),
            role=data.get("context", {}).get("role"),
            tools_in_scope=json.dumps(data.get("tools_in_scope", [])),
            source=data.get("source", "practitioner"),
            notes=data.get("notes"),
            ioc_count=len(iocs),
        )
        async with self.session() as s:
            s.add(contrib)
            await s.flush()
            cid = contrib.id
            for ioc in iocs:
                s.add(IOCHash(
                    contribution_id=cid,
                    ioc_type=ioc.get("ioc_type", ""),
                    value_hash=ioc.get("value_hash", ""),
                    detected_by=json.dumps(ioc.get("detected_by", [])),
                    missed_by=json.dumps(ioc.get("missed_by", [])),
                    threat_actor=ioc.get("threat_actor"),
                    campaign=ioc.get("campaign"),
                ))
        return cid

    # ── Query helpers ────────────────────────────────────────────────────

    async def get_vendor_aggregate(self, vendor: str) -> dict | None:
        async with self.session() as s:
            result = await s.execute(
                select(AggregatedScore).where(AggregatedScore.vendor == vendor)
            )
            row = result.scalar_one_or_none()
            if not row:
                return None
            return {
                "vendor": row.vendor,
                "category": row.category,
                "avg_score": row.avg_score,
                "avg_detection_rate": row.avg_detection_rate,
                "avg_fp_rate": row.avg_fp_rate,
                "avg_deploy_days": row.avg_deploy_days,
                "contribution_count": row.contribution_count,
                "would_buy_pct": row.would_buy_pct,
            }

    async def get_category_vendors(self, category: str) -> list[dict]:
        async with self.session() as s:
            result = await s.execute(
                select(AggregatedScore)
                .where(AggregatedScore.category == category)
                .order_by(AggregatedScore.avg_score.desc())
            )
            return [
                {
                    "vendor": r.vendor,
                    "avg_score": r.avg_score,
                    "avg_detection_rate": r.avg_detection_rate,
                    "contribution_count": r.contribution_count,
                    "would_buy_pct": r.would_buy_pct,
                }
                for r in result.scalars().all()
            ]

    async def get_top_techniques(self, limit: int = 20) -> list[dict]:
        async with self.session() as s:
            result = await s.execute(
                select(
                    AttackTechnique.technique_id,
                    AttackTechnique.technique_name,
                    func.count().label("count"),
                )
                .group_by(AttackTechnique.technique_id, AttackTechnique.technique_name)
                .order_by(text("count DESC"))
                .limit(limit)
            )
            return [
                {"technique_id": r[0], "technique_name": r[1], "count": r[2]}
                for r in result.all()
            ]

    async def get_ioc_stats(self) -> dict:
        async with self.session() as s:
            result = await s.execute(
                select(
                    IOCHash.ioc_type,
                    func.count().label("count"),
                )
                .group_by(IOCHash.ioc_type)
            )
            return {r[0]: r[1] for r in result.all()}

    async def get_stats(self) -> dict:
        async with self.session() as s:
            total = await s.execute(select(func.count(Contribution.id)))
            by_type = await s.execute(
                select(
                    Contribution.contrib_type,
                    func.count().label("count"),
                )
                .group_by(Contribution.contrib_type)
            )
            unique_vendors = await s.execute(
                select(func.count(func.distinct(Contribution.vendor)))
                .where(Contribution.vendor.isnot(None))
            )
            return {
                "total_contributions": total.scalar() or 0,
                "by_type": {r[0]: r[1] for r in by_type.all()},
                "unique_vendors": unique_vendors.scalar() or 0,
            }

    # ── Aggregate refresh ────────────────────────────────────────────────

    async def get_ioc_matches(
        self, ioc_hashes: list[str], exclude_contribution_id: str | None = None,
    ) -> list[dict]:
        """Find IOC hashes that already exist in the DB. Returns matches with metadata."""
        if not ioc_hashes:
            return []
        async with self.session() as s:
            stmt = select(IOCHash).where(IOCHash.value_hash.in_(ioc_hashes))
            if exclude_contribution_id:
                stmt = stmt.where(IOCHash.contribution_id != exclude_contribution_id)
            result = await s.execute(stmt)
            return [
                {
                    "ioc_type": row.ioc_type,
                    "value_hash": row.value_hash,
                    "threat_actor": row.threat_actor,
                    "campaign": row.campaign,
                    "detected_by": json.loads(row.detected_by) if row.detected_by else [],
                    "missed_by": json.loads(row.missed_by) if row.missed_by else [],
                }
                for row in result.scalars().all()
            ]

    async def get_techniques_for_tools(
        self, tools: list[str], exclude_contribution_id: str | None = None,
    ) -> list[dict]:
        """Find techniques where the given tools appear in missed_by."""
        if not tools:
            return []
        tools_lower = {t.lower() for t in tools}
        async with self.session() as s:
            stmt = select(AttackTechnique)
            if exclude_contribution_id:
                stmt = stmt.where(AttackTechnique.contribution_id != exclude_contribution_id)
            result = await s.execute(stmt)
            rows = result.scalars().all()
        out = []
        for row in rows:
            missed = json.loads(row.missed_by) if row.missed_by else []
            if any(m.lower() in tools_lower for m in missed):
                out.append({
                    "technique_id": row.technique_id,
                    "technique_name": row.technique_name,
                    "tactic": row.tactic,
                    "detected_by": json.loads(row.detected_by) if row.detected_by else [],
                    "missed_by": missed,
                })
        return out

    async def get_category_average(self, category: str) -> float | None:
        """Get the average score across all vendors in a category."""
        if not category:
            return None
        async with self.session() as s:
            result = await s.execute(
                select(func.avg(AggregatedScore.avg_score))
                .where(AggregatedScore.category == category)
            )
            return result.scalar()

    async def get_vendor_gaps(self, vendor: str) -> list[str]:
        """Find technique IDs where this vendor appears in missed_by."""
        if not vendor:
            return []
        vendor_lower = vendor.lower()
        async with self.session() as s:
            result = await s.execute(select(AttackTechnique))
            rows = result.scalars().all()
        gaps = []
        for row in rows:
            missed = json.loads(row.missed_by) if row.missed_by else []
            if any(m.lower() == vendor_lower for m in missed):
                gaps.append(row.technique_id)
        return list(set(gaps))

    async def get_remediation_for_threat(
        self, threat_name: str | None = None, technique_ids: list[str] | None = None,
        exclude_contribution_id: str | None = None,
    ) -> list[dict]:
        """Get remediation actions from other contributions for similar attacks."""
        async with self.session() as s:
            stmt = select(Contribution).where(
                Contribution.contrib_type == "attack_map",
                Contribution.remediation_json.isnot(None),
            )
            if exclude_contribution_id:
                stmt = stmt.where(Contribution.id != exclude_contribution_id)
            result = await s.execute(stmt)
            rows = result.scalars().all()

        remediations = []
        for row in rows:
            try:
                actions = json.loads(row.remediation_json) if row.remediation_json else []
            except (json.JSONDecodeError, TypeError):
                continue
            if not actions:
                continue

            relevant = False
            if threat_name and row.threat_name and threat_name.lower() in row.threat_name.lower():
                relevant = True
            if technique_ids and row.techniques_json:
                try:
                    their_techs = {t.get("technique_id") for t in json.loads(row.techniques_json)}
                    if set(technique_ids) & their_techs:
                        relevant = True
                except (json.JSONDecodeError, TypeError):
                    pass
            if not relevant and not threat_name and not technique_ids:
                relevant = True

            if relevant:
                remediations.append({
                    "threat_name": row.threat_name,
                    "industry": row.industry,
                    "severity": row.severity,
                    "time_to_detect": row.time_to_detect,
                    "time_to_contain": row.time_to_contain,
                    "time_to_recover": row.time_to_recover,
                    "data_exfiltrated": row.data_exfiltrated,
                    "ransom_paid": row.ransom_paid,
                    "actions": actions,
                })
        return remediations

    # ── Dashboard analytics ───────────────────────────────────────────

    async def get_contributions_over_time(self, days: int = 90) -> list[dict]:
        """Daily contribution counts for the last N days."""
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        async with self.session() as s:
            result = await s.execute(
                select(
                    func.date(Contribution.received_at).label("day"),
                    func.count().label("count"),
                )
                .where(Contribution.received_at >= cutoff)
                .group_by(text("day"))
                .order_by(text("day"))
            )
            return [{"date": str(r[0]), "count": r[1]} for r in result.all()]

    async def get_contributions_by_type_over_time(self, days: int = 90) -> list[dict]:
        """Daily contribution counts grouped by type."""
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        async with self.session() as s:
            result = await s.execute(
                select(
                    func.date(Contribution.received_at).label("day"),
                    Contribution.contrib_type,
                    func.count().label("count"),
                )
                .where(Contribution.received_at >= cutoff)
                .group_by(text("day"), Contribution.contrib_type)
                .order_by(text("day"))
            )
            return [{"date": str(r[0]), "type": r[1], "count": r[2]} for r in result.all()]

    _DISTRIBUTION_COLUMNS = {"industry", "org_size", "role"}

    async def get_distribution(self, column: str) -> list[dict]:
        """Distribution of contributions by a bucketed column (industry/org_size/role)."""
        if column not in self._DISTRIBUTION_COLUMNS:
            return []
        col = getattr(Contribution, column)
        async with self.session() as s:
            result = await s.execute(
                select(col, func.count().label("count"))
                .where(col.isnot(None))
                .group_by(col)
                .order_by(text("count DESC"))
            )
            return [{"value": r[0], "count": r[1]} for r in result.all()]

    async def get_top_vendors(self, limit: int = 20) -> list[dict]:
        """Top vendors by contribution count."""
        async with self.session() as s:
            result = await s.execute(
                select(Contribution.vendor, func.count().label("count"))
                .where(Contribution.vendor.isnot(None))
                .group_by(Contribution.vendor)
                .order_by(text("count DESC"))
                .limit(limit)
            )
            return [{"vendor": r[0], "count": r[1]} for r in result.all()]

    async def get_top_categories(self, limit: int = 20) -> list[dict]:
        """Top categories by contribution count."""
        async with self.session() as s:
            result = await s.execute(
                select(Contribution.category, func.count().label("count"))
                .where(Contribution.category.isnot(None))
                .group_by(Contribution.category)
                .order_by(text("count DESC"))
                .limit(limit)
            )
            return [{"category": r[0], "count": r[1]} for r in result.all()]

    async def get_users_over_time(self, days: int = 90) -> list[dict]:
        """Daily registration counts."""
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        async with self.session() as s:
            result = await s.execute(
                select(
                    func.date(APIKeyRecord.created_at).label("day"),
                    func.count().label("count"),
                )
                .where(APIKeyRecord.created_at >= cutoff)
                .group_by(text("day"))
                .order_by(text("day"))
            )
            return [{"date": str(r[0]), "count": r[1]} for r in result.all()]

    async def get_user_activity_distribution(self) -> dict:
        """Active vs inactive users and request count distribution."""
        thirty_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
        async with self.session() as s:
            total = (await s.execute(select(func.count(APIKeyRecord.id)))).scalar() or 0
            active = (await s.execute(
                select(func.count(APIKeyRecord.id))
                .where(APIKeyRecord.last_used >= thirty_days_ago)
            )).scalar() or 0
            # Request count buckets
            buckets = {"0": 0, "1-10": 0, "11-100": 0, "101-1000": 0, "1000+": 0}
            rows = (await s.execute(select(APIKeyRecord.request_count))).scalars().all()
            for rc in rows:
                if rc == 0:
                    buckets["0"] += 1
                elif rc <= 10:
                    buckets["1-10"] += 1
                elif rc <= 100:
                    buckets["11-100"] += 1
                elif rc <= 1000:
                    buckets["101-1000"] += 1
                else:
                    buckets["1000+"] += 1
        return {
            "total_users": total,
            "active_last_30d": active,
            "inactive": total - active,
            "request_count_buckets": buckets,
        }

    async def get_tier_distribution(self) -> list[dict]:
        """User count by tier."""
        async with self.session() as s:
            result = await s.execute(
                select(APIKeyRecord.tier, func.count().label("count"))
                .group_by(APIKeyRecord.tier)
            )
            return [{"tier": r[0], "count": r[1]} for r in result.all()]

    async def get_invite_metrics(self) -> dict:
        """Viral coefficient and invite chain metrics."""
        async with self.session() as s:
            total_users = (await s.execute(select(func.count(APIKeyRecord.id)))).scalar() or 0
            inviters = (await s.execute(
                select(func.count(APIKeyRecord.id))
                .where(APIKeyRecord.invite_count > 0)
            )).scalar() or 0
            total_invited = (await s.execute(
                select(func.sum(APIKeyRecord.invite_count))
            )).scalar() or 0
            invited_users = (await s.execute(
                select(func.count(APIKeyRecord.id))
                .where(APIKeyRecord.invited_by.isnot(None))
            )).scalar() or 0
        viral_coefficient = (total_invited / total_users) if total_users > 0 else 0
        return {
            "total_users": total_users,
            "inviters": inviters,
            "inviter_pct": round(inviters / total_users * 100, 1) if total_users > 0 else 0,
            "total_invited": total_invited or 0,
            "invited_users": invited_users,
            "viral_coefficient": round(viral_coefficient, 3),
        }

    async def get_api_usage_over_time(self, days: int = 30) -> list[dict]:
        """Daily API request counts from the request log."""
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        async with self.session() as s:
            result = await s.execute(
                select(
                    func.date(APIRequestLog.timestamp).label("day"),
                    func.count().label("count"),
                )
                .where(APIRequestLog.timestamp >= cutoff)
                .group_by(text("day"))
                .order_by(text("day"))
            )
            return [{"date": str(r[0]), "count": r[1]} for r in result.all()]

    async def get_network_health(self) -> dict:
        """Supply/demand ratio, velocity, and coverage metrics."""
        now = datetime.datetime.now(datetime.timezone.utc)
        seven_days_ago = now - datetime.timedelta(days=7)
        fourteen_days_ago = now - datetime.timedelta(days=14)

        async with self.session() as s:
            total_contributions = (await s.execute(select(func.count(Contribution.id)))).scalar() or 0
            total_users = (await s.execute(select(func.count(APIKeyRecord.id)))).scalar() or 0

            this_week = (await s.execute(
                select(func.count(Contribution.id))
                .where(Contribution.received_at >= seven_days_ago)
            )).scalar() or 0
            last_week = (await s.execute(
                select(func.count(Contribution.id))
                .where(
                    Contribution.received_at >= fourteen_days_ago,
                    Contribution.received_at < seven_days_ago,
                )
            )).scalar() or 0

            unique_industries = (await s.execute(
                select(func.count(func.distinct(Contribution.industry)))
                .where(Contribution.industry.isnot(None))
            )).scalar() or 0
            unique_categories = (await s.execute(
                select(func.count(func.distinct(Contribution.category)))
                .where(Contribution.category.isnot(None))
            )).scalar() or 0

        velocity_pct = round((this_week - last_week) / last_week * 100, 1) if last_week > 0 else (100.0 if this_week > 0 else 0.0)
        supply_demand_ratio = round(total_contributions / total_users, 2) if total_users > 0 else total_contributions

        return {
            "total_contributions": total_contributions,
            "total_users": total_users,
            "supply_demand_ratio": supply_demand_ratio,
            "this_week": this_week,
            "last_week": last_week,
            "velocity_pct": velocity_pct,
            "unique_industries": unique_industries,
            "unique_categories": unique_categories,
        }

    async def get_engagement_funnel(self) -> dict:
        """Funnel: registered → verified → contributed → queried → returned."""
        thirty_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
        async with self.session() as s:
            registered = (await s.execute(select(func.count(APIKeyRecord.id)))).scalar() or 0
            verified = (await s.execute(
                select(func.count(PendingVerification.id))
                .where(PendingVerification.verified.is_(True))
            )).scalar() or 0
            contributed = (await s.execute(
                select(func.count(func.distinct(Contribution.submitted_by_hash)))
                .where(Contribution.submitted_by_hash.isnot(None))
            )).scalar() or 0
            queried = (await s.execute(
                select(func.count(func.distinct(APIRequestLog.api_key_hash)))
                .where(APIRequestLog.endpoint.like("/query%"))
            )).scalar() or 0
            # "Returned" = users with activity on >1 distinct day
            returned_sub = (
                select(
                    APIRequestLog.api_key_hash,
                    func.count(func.distinct(func.date(APIRequestLog.timestamp))).label("days"),
                )
                .group_by(APIRequestLog.api_key_hash)
                .subquery()
            )
            returned = (await s.execute(
                select(func.count()).select_from(returned_sub).where(returned_sub.c.days > 1)
            )).scalar() or 0

        return {
            "registered": registered,
            "verified": verified,
            "contributed": contributed,
            "queried": queried,
            "returned": returned,
        }

    async def get_retention_cohorts(self, weeks: int = 8) -> list[dict]:
        """Weekly registration cohorts with retention at 1, 2, 4 weeks."""
        now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(weeks=weeks)
        async with self.session() as s:
            # Get users registered in the window
            users = (await s.execute(
                select(APIKeyRecord.api_key, APIKeyRecord.created_at)
                .where(APIKeyRecord.created_at >= cutoff)
            )).all()

            if not users:
                return []

            # Build a map of api_key_hash → set of active dates
            import hashlib
            key_hashes = {}
            key_cohort_week = {}
            for api_key, created in users:
                h = hashlib.sha256(api_key.encode()).hexdigest()
                key_hashes[h] = created
                week_start = created - datetime.timedelta(days=created.weekday())
                key_cohort_week[h] = week_start.date()

            if key_hashes:
                logs = (await s.execute(
                    select(APIRequestLog.api_key_hash, APIRequestLog.timestamp)
                    .where(APIRequestLog.api_key_hash.in_(list(key_hashes.keys())))
                )).all()
            else:
                logs = []

            activity: dict[str, set] = {}
            for kh, ts in logs:
                activity.setdefault(kh, set()).add(ts.date())

            # Group by cohort week
            cohorts: dict[str, dict] = {}
            for kh, week_date in key_cohort_week.items():
                wk = str(week_date)
                if wk not in cohorts:
                    cohorts[wk] = {"week": wk, "size": 0, "retained_1w": 0, "retained_2w": 0, "retained_4w": 0}
                cohorts[wk]["size"] += 1
                created = key_hashes[kh]
                dates = activity.get(kh, set())
                for d in dates:
                    days_after = (d - created.date()).days
                    if 7 <= days_after < 14:
                        cohorts[wk]["retained_1w"] += 1
                        break
                for d in dates:
                    days_after = (d - created.date()).days
                    if 14 <= days_after < 21:
                        cohorts[wk]["retained_2w"] += 1
                        break
                for d in dates:
                    days_after = (d - created.date()).days
                    if 28 <= days_after < 35:
                        cohorts[wk]["retained_4w"] += 1
                        break

        return sorted(cohorts.values(), key=lambda c: c["week"])

    async def get_public_dashboard_stats(self) -> dict:
        """Extended stats safe for public display."""
        health = await self.get_network_health()
        stats = await self.get_stats()
        return {
            **stats,
            "velocity_pct": health["velocity_pct"],
            "this_week": health["this_week"],
            "unique_industries": health["unique_industries"],
            "unique_categories": health["unique_categories"],
            "total_users": health["total_users"],
        }

    async def log_api_request(self, api_key_hash: str, endpoint: str, method: str, status: int) -> None:
        """Log an API request for demand-side analytics."""
        async with self.session() as s:
            s.add(APIRequestLog(
                api_key_hash=api_key_hash,
                endpoint=endpoint,
                method=method,
                response_status=status,
            ))

    async def bump_api_key_usage(self, api_key: str) -> None:
        """Increment request_count and update last_used for an API key."""
        async with self.session() as s:
            result = await s.execute(
                select(APIKeyRecord).where(APIKeyRecord.api_key == api_key)
            )
            record = result.scalar_one_or_none()
            if record:
                record.request_count = (record.request_count or 0) + 1
                record.last_used = datetime.datetime.now(datetime.timezone.utc)

    # ── Scrape dedup ────────────────────────────────────────────────────

    async def is_scraped(self, content_hash: str) -> bool:
        """Check if an item has already been scraped and ingested."""
        from .models import ScrapedItem
        async with self.session() as s:
            result = await s.execute(
                select(ScrapedItem).where(ScrapedItem.id == content_hash)
            )
            return result.scalar_one_or_none() is not None

    async def mark_scraped(self, content_hash: str, source: str, source_id: str = "", metadata: dict | None = None) -> None:
        """Mark an item as scraped to prevent re-ingestion."""
        from .models import ScrapedItem
        async with self.session() as s:
            existing = await s.execute(select(ScrapedItem).where(ScrapedItem.id == content_hash))
            if existing.scalar_one_or_none():
                return
            s.add(ScrapedItem(
                id=content_hash,
                source=source,
                source_id=source_id,
                metadata_json=json.dumps(metadata) if metadata else None,
            ))

    async def get_scrape_stats(self) -> dict:
        """Get counts of scraped items by source."""
        from .models import ScrapedItem
        async with self.session() as s:
            result = await s.execute(
                select(ScrapedItem.source, func.count(ScrapedItem.id)).group_by(ScrapedItem.source)
            )
            stats = {row[0]: row[1] for row in result.all()}
        return {"total": sum(stats.values()), "by_source": stats}

    # ── Aggregate refresh ────────────────────────────────────────────────

    async def _refresh_aggregate(self, vendor: str | None) -> None:
        """Recompute aggregate for a vendor after new contribution."""
        if not vendor:
            return
        async with self.session() as s:
            result = await s.execute(
                select(
                    func.avg(Contribution.overall_score),
                    func.avg(Contribution.detection_rate),
                    func.avg(Contribution.fp_rate),
                    func.avg(Contribution.deploy_days),
                    func.count(),
                    Contribution.category,
                )
                .where(Contribution.vendor == vendor, Contribution.contrib_type == "eval")
                .group_by(Contribution.category)
            )
            row = result.first()
            if not row:
                return

            # Count would_buy
            wb = await s.execute(
                select(func.count())
                .where(
                    Contribution.vendor == vendor,
                    Contribution.would_buy.is_(True),
                )
            )
            wb_count = wb.scalar() or 0
            total = row[4]
            wb_pct = (wb_count / total * 100) if total > 0 else None

            # Upsert aggregate
            existing = await s.execute(
                select(AggregatedScore).where(AggregatedScore.vendor == vendor)
            )
            agg = existing.scalar_one_or_none()
            if agg:
                agg.avg_score = row[0]
                agg.avg_detection_rate = row[1]
                agg.avg_fp_rate = row[2]
                agg.avg_deploy_days = row[3]
                agg.contribution_count = total
                agg.would_buy_pct = wb_pct
                agg.category = row[5]
            else:
                s.add(AggregatedScore(
                    vendor=vendor,
                    category=row[5],
                    avg_score=row[0],
                    avg_detection_rate=row[1],
                    avg_fp_rate=row[2],
                    avg_deploy_days=row[3],
                    contribution_count=total,
                    would_buy_pct=wb_pct,
                ))
