"""
Database layer — SQLite for MVP (zero-config), optional PostgreSQL for production.

Usage:
    db = Database("sqlite+aiosqlite:///oombra.db")
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
    def __init__(self, url: str = "sqlite+aiosqlite:///oombra.db"):
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
        contrib = Contribution(
            contrib_type="eval",
            industry=data.get("context", {}).get("industry"),
            org_size=data.get("context", {}).get("org_size"),
            role=data.get("context", {}).get("role"),
            vendor=data.get("data", {}).get("vendor") or data.get("vendor"),
            category=data.get("data", {}).get("category") or data.get("category"),
            overall_score=data.get("data", {}).get("overall_score"),
            detection_rate=data.get("data", {}).get("detection_rate"),
            fp_rate=data.get("data", {}).get("fp_rate"),
            deploy_days=data.get("data", {}).get("deploy_days"),
            cpu_overhead=data.get("data", {}).get("cpu_overhead"),
            ttfv_hours=data.get("data", {}).get("ttfv_hours"),
            would_buy=data.get("data", {}).get("would_buy"),
            eval_duration_days=data.get("data", {}).get("eval_duration_days"),
            top_strength=data.get("data", {}).get("top_strength"),
            top_friction=data.get("data", {}).get("top_friction"),
            notes=data.get("data", {}).get("notes"),
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
