"""
Database layer — SQLite for MVP (zero-config), optional PostgreSQL for production.

Usage:
    db = Database("sqlite+aiosqlite:///nur.db")
    await db.init()
    await db.store_eval_record(data)
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession, async_sessionmaker, create_async_engine,
)
from sqlalchemy import select, func, text

from .models import (
    Base, Contribution, IOCHash, AttackTechnique, AggregatedScore,
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

    async def store_eval_record(self, data: dict[str, Any]) -> str:
        """Store an EvalRecord contribution. Returns contribution ID."""
        # Support both wire format {"context": {}, "data": {...}} and flat format {"vendor": ...}
        d = data.get("data", data)
        ctx = data.get("context", {})
        # Normalize vendor name against canonical VENDORS list
        vendor = d.get("vendor")
        if vendor and isinstance(vendor, str):
            from ..vendors import VENDORS
            _vendor_lookup = {v.lower(): v for v in VENDORS}
            vendor = _vendor_lookup.get(vendor.strip().lower(), vendor.strip())
        contrib = Contribution(
            contrib_type="eval",
            industry=ctx.get("industry"),
            org_size=ctx.get("org_size"),
            role=ctx.get("role"),
            vendor=vendor,
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
            annual_cost=d.get("annual_cost"),
            support_quality=d.get("support_quality"),
            decision_factor=d.get("decision_factor"),
            also_evaluated=json.dumps(d["also_evaluated"]) if d.get("also_evaluated") else None,
            replacing=d.get("replacing"),
            source=d.get("source", ctx.get("source")),
        )
        async with self.session() as s:
            s.add(contrib)
            await s.flush()
            cid = contrib.id
        await self._refresh_aggregate(contrib.vendor)
        return cid

    async def store_attack_map(self, data: dict[str, Any]) -> str:
        """Store an AttackMap contribution. Returns contribution ID."""
        techniques = data.get("techniques", [])
        remediation = data.get("remediation", [])
        contrib = Contribution(
            contrib_type="attack_map",
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

    async def store_ioc_bundle(self, data: dict[str, Any]) -> str:
        """Store an IOCBundle contribution. Returns contribution ID."""
        iocs = data.get("iocs", [])
        contrib = Contribution(
            contrib_type="ioc_bundle",
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
        # Normalize to canonical name so lookups match stored aggregates
        if vendor and isinstance(vendor, str):
            from ..vendors import VENDORS
            _vendor_lookup = {v.lower(): v for v in VENDORS}
            vendor = _vendor_lookup.get(vendor.strip().lower(), vendor.strip())
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

    async def get_contributions(
        self,
        source: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        contrib_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """Query contributions with filters. Returns anonymized records (no PII)."""
        async with self.session() as s:
            stmt = select(Contribution).order_by(Contribution.received_at.desc())
            count_stmt = select(func.count(Contribution.id))

            if source:
                stmt = stmt.where(Contribution.source == source)
                count_stmt = count_stmt.where(Contribution.source == source)
            if vendor:
                stmt = stmt.where(Contribution.vendor == vendor)
                count_stmt = count_stmt.where(Contribution.vendor == vendor)
            if category:
                stmt = stmt.where(Contribution.category == category)
                count_stmt = count_stmt.where(Contribution.category == category)
            if contrib_type:
                stmt = stmt.where(Contribution.contrib_type == contrib_type)
                count_stmt = count_stmt.where(Contribution.contrib_type == contrib_type)

            total = (await s.execute(count_stmt)).scalar() or 0
            result = await s.execute(stmt.offset(offset).limit(limit))
            rows = result.scalars().all()

            # Source breakdown for this filter set
            source_stmt = select(
                Contribution.source, func.count().label("count"),
            ).group_by(Contribution.source)
            if vendor:
                source_stmt = source_stmt.where(Contribution.vendor == vendor)
            if category:
                source_stmt = source_stmt.where(Contribution.category == category)
            if contrib_type:
                source_stmt = source_stmt.where(Contribution.contrib_type == contrib_type)
            source_counts = {r[0] or "unknown": r[1] for r in (await s.execute(source_stmt)).all()}

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "by_source": source_counts,
            "contributions": [
                {
                    "id": r.id,
                    "contrib_type": r.contrib_type,
                    "received_at": r.received_at.isoformat() if r.received_at else None,
                    "source": r.source,
                    "vendor": r.vendor,
                    "category": r.category,
                    "overall_score": r.overall_score,
                    "would_buy": r.would_buy,
                    "annual_cost": r.annual_cost,
                    "support_quality": r.support_quality,
                    "decision_factor": r.decision_factor,
                    "replacing": r.replacing,
                    "also_evaluated": json.loads(r.also_evaluated) if r.also_evaluated else None,
                    "industry": r.industry,
                    "org_size": r.org_size,
                }
                for r in rows
            ],
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
