"""Deterministic risk engine. The ONLY place a score and level are decided.

Pipeline (all Decimal arithmetic, no randomness, no clock reads):
  evidence items -> per-factor score (diminishing-returns / noisy-OR)
                 -> weighted sum with missing-data renormalisation
                 -> level via policy bands
                 -> explanation, warnings, counterfactuals.
`assess` is a pure function of (items, policy, as_of): this is what makes
stored assessments replayable and verifiable.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_FLOOR
from typing import Iterable, List, Optional

from .policy import FACTORS, SEVERITIES, DEFAULT_POLICY, RiskPolicy, q2

D = Decimal


def parse_dt(value) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return parse_dt(dt).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    factor: str
    severity: str
    confidence: float
    observed_at: str
    source: str
    title: str
    resolved: bool = False

    def __post_init__(self):
        if self.factor not in FACTORS:
            raise ValueError(f"unknown factor '{self.factor}'")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity '{self.severity}'")
        if not 0 <= float(self.confidence) <= 1:
            raise ValueError("confidence must be within 0..1")

    def to_dict(self) -> dict:
        return {"id": self.id, "factor": self.factor, "severity": self.severity,
                "confidence": float(self.confidence), "observed_at": iso(self.observed_at),
                "source": self.source, "title": self.title, "resolved": bool(self.resolved)}

    @staticmethod
    def from_dict(d: dict) -> "EvidenceItem":
        return EvidenceItem(d["id"], d["factor"], d["severity"], float(d["confidence"]), iso(d["observed_at"]),
                            d["source"], d["title"], bool(d.get("resolved", False)))


def _impact(item: EvidenceItem, policy: RiskPolicy) -> Decimal:
    if item.resolved:
        return D(0)
    return policy.severity_points[item.severity] * D(str(item.confidence))


def _factor_score(items: List[EvidenceItem], policy: RiskPolicy) -> Decimal:
    """Noisy-OR aggregation: independent evidence compounds with diminishing returns, bounded to 0..100."""
    remaining = D(1)
    for it in items:
        remaining *= D(1) - _impact(it, policy) / D(100)
    return D(100) * (D(1) - remaining)


def _age_days(item: EvidenceItem, as_of: datetime) -> float:
    return max(0.0, (as_of - parse_dt(item.observed_at)).total_seconds() / 86400.0)


def _freshness(age: float, stale_after: int) -> float:
    return 1.0 if age <= stale_after else 0.5 ** ((age - stale_after) / stale_after)


def _score_total(items: List[EvidenceItem], policy: RiskPolicy):
    """Returns (exact_total, per_factor dict, present_factors, W) or None when no evidence."""
    by = {f: [i for i in items if i.factor == f] for f in FACTORS}
    present = [f for f in FACTORS if by[f]]
    if not present:
        return None
    W = sum(policy.weights[f] for f in present)
    if W == 0:
        return None
    scores = {f: q2(_factor_score(by[f], policy)) for f in present}
    exact = sum(scores[f] * policy.weights[f] for f in present) / W
    return exact, scores, present, W, by


def assess(items: Iterable[EvidenceItem], as_of, policy: RiskPolicy = DEFAULT_POLICY,
           counterfactuals: bool = True) -> dict:
    items = sorted(items, key=lambda i: i.id)
    as_of_dt = parse_dt(as_of)
    base = {"policy_version": policy.version, "policy_hash": policy.content_hash(), "as_of": iso(as_of_dt)}
    warnings: List[dict] = []
    calc = _score_total(items, policy)
    if calc is None:
        warnings.append({"code": "no_evidence", "message": "No evidence available: no score can be produced."})
        return {**base, "status": "insufficient_evidence", "score": None, "level": None, "coverage": 0.0,
                "trust": 0.0, "factors": [], "warnings": warnings, "evidence_ids": [],
                "counterfactuals": {"level_drop": [], "remediation": []}}

    exact, scores, present, W, by = calc
    score = q2(exact)
    level = policy.level_for(score)
    coverage = W
    missing = [f for f in FACTORS if f not in present]
    status = "complete"
    for f in missing:
        warnings.append({"code": "missing_factor", "factor": f,
                         "message": f"No evidence for '{f}'. It is NOT treated as zero; remaining weights are renormalised."})
    if missing:
        status = "partial"
    if coverage < policy.min_coverage:
        warnings.append({"code": "low_coverage", "message": f"Only {float(coverage):.0%} of policy weight is backed by evidence; treat the score as provisional."})

    stale, lowconf, trusts = [], [], []
    for it in items:
        age = _age_days(it, as_of_dt)
        trusts.append(float(it.confidence) * _freshness(age, policy.stale_after_days))
        if age > policy.stale_after_days:
            stale.append(it.id)
        if D(str(it.confidence)) < policy.low_confidence_below:
            lowconf.append(it.id)
    if stale:
        warnings.append({"code": "stale_evidence", "evidence_ids": stale, "message": f"{len(stale)} evidence item(s) older than {policy.stale_after_days} days."})
    if lowconf:
        warnings.append({"code": "low_confidence", "evidence_ids": lowconf, "message": f"{len(lowconf)} evidence item(s) below confidence {float(policy.low_confidence_below)}."})

    factors = []
    for f in FACTORS:
        row = {"factor": f, "weight": float(policy.weights[f]), "present": f in present}
        if f in present:
            eff = policy.weights[f] / W
            top = max(by[f], key=lambda i: (_impact(i, policy), i.id))
            open_n = sum(1 for i in by[f] if not i.resolved)
            row.update({
                "score": float(scores[f]), "effective_weight": float(eff.quantize(D("0.0001"))),
                "contribution": float(q2(scores[f] * eff)), "evidence_ids": [i.id for i in by[f]],
                "rationale": (f"{len(by[f])} evidence item(s), {open_n} unresolved. Largest driver: "
                              f"{top.severity} '{top.title}' (confidence {float(top.confidence):.2f}). "
                              f"Combined with diminishing returns to {float(scores[f]):.2f}/100."),
            })
        else:
            row.update({"score": None, "effective_weight": 0.0, "contribution": 0.0, "evidence_ids": [],
                        "rationale": "No evidence collected. Excluded from the weighted sum and flagged; never treated as zero."})
        factors.append(row)

    result = {**base, "status": status, "score": float(score), "level": level, "coverage": float(coverage),
              "trust": round(sum(trusts) / len(trusts), 4), "factors": factors, "warnings": warnings,
              "evidence_ids": [i.id for i in items], "counterfactuals": {"level_drop": [], "remediation": []}}
    if counterfactuals:
        result["counterfactuals"] = _counterfactuals(items, policy, exact, scores, present, W, level, score)
    return result


def _counterfactuals(items, policy, exact, scores, present, W, level, score) -> dict:
    drop = []
    below = policy.level_below(level)
    if below is not None:
        # total must round to < lower bound: target is just under the bound
        lower = policy.lower_bound_of(level)
        target = lower - D("0.005")
        need = exact - target
        for f in present:
            eff = policy.weights[f] / W
            if eff == 0:
                continue
            required = (scores[f] - need / eff).quantize(D("0.01"), rounding=ROUND_FLOOR)
            # Verify by actually re-scoring (rounding can land exactly on a boundary): step down until the level truly drops.
            for _ in range(5):
                if required < 0:
                    break
                alt = dict(scores); alt[f] = required
                if q2(sum(alt[x] * policy.weights[x] for x in present) / W) < lower:
                    break
                required -= D("0.01")
            feasible = required >= 0 and q2(sum({**scores, f: required}[x] * policy.weights[x] for x in present) / W) < lower
            drop.append({"factor": f, "current": float(scores[f]),
                         "required_score": float(required) if feasible else None,
                         "reduction": float(scores[f] - required) if feasible else None, "feasible": feasible,
                         "target_level": below})
        drop.sort(key=lambda r: (not r["feasible"], r["reduction"] if r["reduction"] is not None else 1e9))
    remediation = []
    for it in items:
        if it.resolved or it.severity == "none":
            continue
        alt = [EvidenceItem(**{**it.__dict__, "resolved": True}) if i.id == it.id else i for i in items]
        calc = _score_total(alt, policy)
        new_score = q2(calc[0]) if calc else None
        if new_score is None:
            continue
        remediation.append({"evidence_id": it.id, "title": it.title, "factor": it.factor, "severity": it.severity,
                            "score_if_resolved": float(new_score), "delta": float(score - new_score),
                            "level_if_resolved": policy.level_for(new_score)})
    remediation.sort(key=lambda r: (-r["delta"], r["evidence_id"]))
    return {"level_drop": drop, "remediation": remediation[:8]}


def result_hash(items: List[EvidenceItem], result: dict) -> str:
    blob = json.dumps({"items": [i.to_dict() for i in sorted(items, key=lambda i: i.id)], "result": result},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def weighted_score(factor_scores: dict, policy: RiskPolicy = DEFAULT_POLICY) -> Decimal:
    """Plain weighted sum of explicit 0-100 factor scores (all five required). Used to audit the brief's formula."""
    if set(factor_scores) != set(FACTORS):
        raise ValueError("all five factor scores are required")
    for v in factor_scores.values():
        if not 0 <= D(str(v)) <= 100:
            raise ValueError("factor scores must be within 0..100")
    return q2(sum(D(str(factor_scores[f])) * policy.weights[f] for f in FACTORS))
