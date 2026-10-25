"""Regression tests for fix synthesis and remediation planning."""

import unittest
from unittest.mock import patch

from backend.analyze import _build_fixes
from backend.tools import build_patch, fix_plan, simulate


class FixSynthesisTests(unittest.TestCase):
    def test_fix_versions_must_exceed_every_installed_vulnerable_version(self) -> None:
        fixes = _build_fixes({
            "shared-package": {
                "installed_versions": ["1.0.0", "1.5.0"],
                "vuln_ids": ["OSV-1"],
                "fixed_per_vuln": {"OSV-1": ["1.2.0"]},
                "reqs": ["^1.0.0"],
                "pkg_ids": ["shared-package@1.0.0", "shared-package@1.5.0"],
                "vuln_risks": {"OSV-1": 10.0},
            }
        })

        self.assertEqual(len(fixes), 1)
        self.assertIsNone(fixes[0]["toVersion"])
        self.assertEqual(fixes[0]["clears"], 0)
        self.assertEqual(fixes[0]["unfixed"], 1)

    def test_fix_tiers_and_unfixed_advisories_are_reported(self) -> None:
        packages = {
            "refresh-me": {
                "installed_versions": ["1.0.0"],
                "vuln_ids": ["A", "B"],
                "fixed_per_vuln": {"A": ["1.1.0"], "B": ["1.2.0"]},
                "reqs": ["^1.0.0"],
                "pkg_ids": ["refresh-me@1.0.0"],
                "vuln_risks": {"A": 4.0, "B": 6.0},
            },
            "override-me": {
                "installed_versions": ["1.0.0"],
                "vuln_ids": ["C"],
                "fixed_per_vuln": {"C": ["1.2.0"]},
                "reqs": ["~1.0.0"],
                "pkg_ids": ["override-me@1.0.0"],
                "vuln_risks": {"C": 3.0},
            },
            "breaking-me": {
                "installed_versions": ["1.0.0"],
                "vuln_ids": ["D"],
                "fixed_per_vuln": {"D": ["2.0.0"]},
                "reqs": ["^1.0.0"],
                "pkg_ids": ["breaking-me@1.0.0"],
                "vuln_risks": {"D": 2.0},
            },
            "unfixed": {
                "installed_versions": ["1.0.0"],
                "vuln_ids": ["E"],
                "fixed_per_vuln": {"E": []},
                "reqs": ["^1.0.0"],
                "pkg_ids": ["unfixed@1.0.0"],
                "vuln_risks": {"E": 1.0},
            },
        }

        fixes = {fix["pkg"]: fix for fix in _build_fixes(packages)}

        self.assertEqual((fixes["refresh-me"]["toVersion"], fixes["refresh-me"]["tier"]), ("1.2.0", "refresh"))
        self.assertEqual(fixes["refresh-me"]["clears"], 2)
        self.assertEqual((fixes["override-me"]["toVersion"], fixes["override-me"]["tier"]), ("1.2.0", "override"))
        self.assertEqual((fixes["breaking-me"]["toVersion"], fixes["breaking-me"]["tier"]), ("2.0.0", "breaking"))
        self.assertEqual((fixes["unfixed"]["clears"], fixes["unfixed"]["unfixed"]), (0, 1))


class RemediationPlanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = {
            "engine": "sqlite",
            "ms": 1.0,
            "cypher": "-- local snapshot",
            "vuln_risk": {"A": 12.0, "B": 9.0, "C": 5.0},
            "pkg_vulns": {"pkg-a@1.0.0": {"A"}, "pkg-b@1.0.0": {"B", "C"}},
            "fixes": {
                "fix:pkg-a": {
                    "id": "fix:pkg-a", "pkg": "pkg-a", "toVersion": "1.1.0", "tier": "refresh",
                    "clears": 2, "unfixed": 0, "riskCleared": 21.0,
                    "targets": ["pkg-a@1.0.0"], "resolves": ["A", "B"],
                },
                "fix:pkg-b": {
                    "id": "fix:pkg-b", "pkg": "pkg-b", "toVersion": "2.0.0", "tier": "breaking",
                    "clears": 2, "unfixed": 0, "riskCleared": 14.0,
                    "targets": ["pkg-b@1.0.0"], "resolves": ["B", "C"],
                },
            },
        }
        self.state_patch = patch("backend.tools._state", return_value=self.state)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)

    def test_fix_plan_prefers_risk_reduction_per_effort(self) -> None:
        result = fix_plan()["data"]

        self.assertEqual([action["fixId"] for action in result["actions"]], ["fix:pkg-a", "fix:pkg-b"])
        self.assertEqual(result["totalRiskReduction"], 26.0)
        self.assertEqual(result["finalBlastScore"], 0)

    def test_simulation_deduplicates_and_ignores_unknown_advisories(self) -> None:
        self.state["fixes"]["fix:pkg-a"]["resolves"] = ["A", "A", "UNKNOWN"]

        result = simulate(["pkg-a"])["data"]

        self.assertEqual(result["healedVulnsCount"], 1)
        self.assertEqual(result["remainingVulnsCount"], 2)
        self.assertEqual(result["resolvedVulns"], ["A"])
        self.assertEqual(result["healedPackages"], ["pkg-a@1.0.0"])

    def test_patch_provenance_matches_the_engine_used(self) -> None:
        result = build_patch(["pkg-a"])["data"]

        self.assertIn("local SQLite snapshot with NetworkX", result["issue_markdown"])
        self.assertNotIn("analysed in FalkorDB", result["issue_markdown"])
        self.assertEqual(result["overrides"], {"pkg-a": "^1.1.0"})
        self.assertIn("npm run lint", result["commands"])
        self.assertIn("npm run build", result["commands"])
        self.assertNotIn("npm test", result["commands"])


if __name__ == "__main__":
    unittest.main()
