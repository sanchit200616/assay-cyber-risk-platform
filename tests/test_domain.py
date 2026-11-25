import unittest
from decimal import Decimal as D

from tests.helpers import *  # noqa
from cyberrisk.domain.policy import DEFAULT_POLICY as P, RiskPolicy, PolicyError, FACTORS, q2
from cyberrisk.domain.risk import EvidenceItem, assess, weighted_score, result_hash
from cyberrisk.domain import lifecycle

AS_OF = "2026-11-15T12:00:00Z"


def item(i, factor="vulnerability", sev="high", conf=1.0, observed="2026-11-10T00:00:00Z", resolved=False):
    return EvidenceItem(i, factor, sev, conf, observed, "t", f"title {i}", resolved)


class PolicyTests(unittest.TestCase):
    def test_default_weights_sum_to_one(self):
        self.assertEqual(sum(P.weights.values()), D("1"))

    def test_brief_formula_illustration_is_64_not_63(self):
        # The brief says 80/60/70/40/50 -> 63. The stated formula actually gives 64.
        s = weighted_score(dict(zip(FACTORS, (80, 60, 70, 40, 50))))
        self.assertEqual(s, D("64.00"))
        self.assertEqual(P.level_for(s), "High")

    def test_band_boundaries(self):
        cases = {"0": "Minimal", "19.99": "Minimal", "20": "Low", "39.99": "Low", "40": "Medium", "59.99": "Medium",
                 "60": "High", "79.99": "High", "80": "Critical", "100": "Critical"}
        for score, level in cases.items():
            self.assertEqual(P.level_for(D(score)), level, score)

    def test_no_gap_for_fractional_scores(self):
        self.assertEqual(P.level_for(q2("19.995")), "Low")  # rounds to 20.00 -> Low
        self.assertEqual(P.level_for(D("19.5")), "Minimal")

    def test_out_of_range_rejected(self):
        for bad in (D("-0.01"), D("100.01")):
            with self.assertRaises(PolicyError):
                P.level_for(bad)

    def test_invalid_weights_rejected(self):
        w = dict(P.weights)
        for mutate in (lambda x: x.update(vulnerability=D("0.5")),            # sum != 1
                       lambda x: x.update(vulnerability=D("-0.1"), threat=D("0.65")),  # negative
                       lambda x: x.pop("threat")):                               # missing factor
            ww = dict(w); mutate(ww)
            with self.assertRaises(PolicyError):
                RiskPolicy("x", ww, P.bands, P.severity_points)

    def test_policy_hash_changes_when_policy_changes(self):
        w = dict(P.weights); w["vulnerability"], w["threat"] = D("0.25"), D("0.30")
        other = RiskPolicy("1.1", w, P.bands, P.severity_points)
        self.assertNotEqual(P.content_hash(), other.content_hash())
        self.assertEqual(P.content_hash(), P.content_hash())


class RiskTests(unittest.TestCase):
    def all_five(self, sev="high"):
        return [item(f, f, sev) for f in FACTORS]

    def test_all_factors_high_confidence_one(self):
        r = assess(self.all_five("high"), AS_OF)
        self.assertEqual((r["score"], r["level"], r["status"]), (75.0, "High", "complete"))
        self.assertEqual(sum(f["contribution"] for f in r["factors"]), 75.0)

    def test_deterministic_and_order_independent(self):
        items = [item("b", "threat", "medium", 0.6), item("a", "vulnerability", "critical", 0.9), item("c", "exposure", "low", 0.5)]
        r1, r2 = assess(items, AS_OF), assess(list(reversed(items)), AS_OF)
        self.assertEqual(r1, r2)
        self.assertEqual(result_hash(items, r1), result_hash(list(reversed(items)), r2))

    def test_noisy_or_is_bounded_and_monotonic(self):
        one = assess([item("1", sev="high")], AS_OF)["factors"][0]["score"]
        many = assess([item(str(i), sev="high") for i in range(20)], AS_OF)["factors"][0]["score"]
        self.assertEqual(one, 75.0)
        self.assertTrue(one < many <= 100.0)

    def test_missing_factor_is_not_zero_and_is_flagged(self):
        r = assess([item("v", "vulnerability", "high")], AS_OF)
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["score"], 75.0)  # renormalised over the single present factor, NOT diluted by zeros
        codes = [w["code"] for w in r["warnings"]]
        self.assertEqual(codes.count("missing_factor"), 4)
        self.assertIn("low_coverage", codes)
        self.assertEqual(r["coverage"], 0.3)
        absent = [f for f in r["factors"] if not f["present"]]
        self.assertTrue(all(f["score"] is None for f in absent))

    def test_no_evidence_produces_no_score(self):
        r = assess([], AS_OF)
        self.assertEqual((r["status"], r["score"], r["level"]), ("insufficient_evidence", None, None))

    def test_resolved_evidence_contributes_zero_but_counts_as_present(self):
        r = assess([item("v", "vulnerability", "critical", resolved=True), item("t", "threat", "high")], AS_OF)
        v = next(f for f in r["factors"] if f["factor"] == "vulnerability")
        self.assertEqual(v["score"], 0.0)
        self.assertTrue(v["present"])

    def test_explicit_attestation_of_absence_is_not_missing(self):
        r = assess([item("c", "compliance", "none")], AS_OF)
        self.assertEqual(r["score"], 0.0)
        self.assertEqual(r["level"], "Minimal")

    def test_confidence_scales_impact(self):
        hi = assess([item("a", conf=1.0)], AS_OF)["score"]
        lo = assess([item("a", conf=0.4)], AS_OF)["score"]
        self.assertGreater(hi, lo)
        self.assertEqual(lo, 30.0)

    def test_stale_and_low_confidence_warnings(self):
        r = assess([item("old", observed="2026-01-01T00:00:00Z"), item("weak", conf=0.2)], AS_OF)
        codes = {w["code"]: w for w in r["warnings"]}
        self.assertEqual(codes["stale_evidence"]["evidence_ids"], ["old"])
        self.assertEqual(codes["low_confidence"]["evidence_ids"], ["weak"])
        self.assertLess(r["trust"], 0.7)

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            item("x", sev="catastrophic")
        with self.assertRaises(ValueError):
            item("x", conf=1.5)
        with self.assertRaises(ValueError):
            item("x", factor="vibes")
        with self.assertRaises(ValueError):
            weighted_score({"vulnerability": 50})

    def test_rationale_and_metadata_present(self):
        r = assess(self.all_five(), AS_OF)
        self.assertEqual((r["policy_version"], r["as_of"]), ("1.0", AS_OF))
        self.assertEqual(r["policy_hash"], P.content_hash())
        self.assertTrue(all(f["rationale"] for f in r["factors"]))
        self.assertEqual(len(r["evidence_ids"]), 5)

    def test_counterfactual_level_drop_is_arithmetically_correct(self):
        items = [item("v", "vulnerability", "critical", 1.0), item("t", "threat", "critical", 1.0), item("e", "exposure", "high", 1.0),
                 item("c", "compliance", "high", 1.0), item("i", "investigation", "medium", 1.0)]
        r = assess(items, AS_OF)
        self.assertEqual((r["score"], r["level"]), (83.5, "Critical"))
        scores = {f["factor"]: D(str(f["score"])) for f in r["factors"]}
        checked = 0
        for cf in r["counterfactuals"]["level_drop"]:
            if not cf["feasible"]:
                continue
            alt = dict(scores); alt[cf["factor"]] = D(str(cf["required_score"]))
            total = q2(sum(alt[f] * P.weights[f] for f in FACTORS))
            self.assertEqual(P.level_for(total), cf["target_level"], cf["factor"])
            checked += 1
        self.assertGreater(checked, 0)

    def test_remediation_delta_matches_actual_rescore(self):
        items = [item("v", "vulnerability", "critical", 0.9), item("t", "threat", "high", 0.8)]
        r = assess(items, AS_OF)
        top = r["counterfactuals"]["remediation"][0]
        alt = [EvidenceItem(**{**i.__dict__, "resolved": True}) if i.id == top["evidence_id"] else i for i in items]
        self.assertEqual(assess(alt, AS_OF, counterfactuals=False)["score"], top["score_if_resolved"])
        self.assertAlmostEqual(r["score"] - top["score_if_resolved"], top["delta"], places=2)


class LifecycleTests(unittest.TestCase):
    def test_transitions(self):
        lifecycle.check_transition("finding", "open", "resolved")
        lifecycle.check_transition("workflow", "todo", "doing")
        for kind, a, b in (("finding", "resolved", "accepted"), ("workflow", "todo", "done"), ("assessment", "archived", "draft")):
            with self.assertRaises(lifecycle.TransitionError):
                lifecycle.check_transition(kind, a, b)
        with self.assertRaises(lifecycle.TransitionError):
            lifecycle.check_transition("finding", "open", "bogus")


if __name__ == "__main__":
    unittest.main()
