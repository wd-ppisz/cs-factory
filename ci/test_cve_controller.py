#!/usr/bin/env python3
"""CVE controller tests - no network. Run: python3 -m unittest ci/test_cve_controller.py"""
import copy
import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cve_controller as c  # noqa: E402

NOW = dt.datetime(2026, 11, 14, 12, 0, tzinfo=dt.timezone.utc)
T = NOW.timestamp()
SHA = "a" * 64


def iso(hours_ago=0.0, days_ago=0.0):
    return (NOW - dt.timedelta(hours=hours_ago, days=days_ago)).isoformat()


POLICY = json.loads((Path(__file__).resolve().parent / "cve-policy.json").read_text(encoding="utf-8"))


def inventory(**kw):
    d = {"schema": c.INVENTORY_SCHEMA, "host": POLICY["expected_host"],
         "captured_at": iso(0.5), "installed_packages": 300, "dpkg_status_sha256": SHA,
         "running_kernel": "6.12.0", "reboot_required": False}
    d.update(kw)
    return d


def report(vulns=(), packages=300, artifact="filesystem", family="debian"):
    return {"ArtifactType": artifact, "Metadata": {"OS": {"Family": family, "Name": "13.2"}},
            "Results": [{"Class": "os-pkgs", "Target": "debian 13.2",
                         "Packages": [{"Name": f"p{i}"} for i in range(packages)],
                         "Vulnerabilities": list(vulns)}]}


def vuln(cve="CVE-2026-0001", pkg="openssl", sev="HIGH", fixed="3.0.1"):
    return {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": "3.0.0",
            "Severity": sev, "FixedVersion": fixed}


KEV = {"retrieved_at": iso(0.1), "dateReleased": iso(days_ago=1),
       "vulnerabilities": [{"cveID": "CVE-2026-9999"}]}
TV = {"VulnerabilityDB": {"UpdatedAt": iso(5)}}
META = {"dpkg_status_sha256": SHA}


class Inputs(unittest.TestCase):
    def ok(self, **over):
        args = dict(inventory=inventory(), scan_meta=META, report=report(), trivy_version=TV,
                    kev=KEV, policy=POLICY, now=T)
        args.update(over)
        return c.check_inputs(**args)

    def boom(self, msg, **over):
        with self.assertRaises(c.InputError) as e:
            self.ok(**over)
        self.assertIn(msg, str(e.exception))

    def test_valid(self):
        self.assertEqual(self.ok()["scanned_packages"], 300)

    def test_foreign_host(self):
        self.boom("expected", inventory=inventory(host="laptop"))

    def test_stale_inventory(self):
        self.boom("inventory: stale", inventory=inventory(captured_at=iso(7)))

    def test_inventory_from_future(self):
        self.boom("from the future", inventory=inventory(captured_at=iso(-1)))

    def test_empty_host(self):
        self.boom("full host", inventory=inventory(installed_packages=3))

    def test_different_dpkg_status(self):
        self.boom("DIFFERENT dpkg/status", scan_meta={"dpkg_status_sha256": "b" * 64})

    def test_incomplete_scan(self):
        # a green scan without the package list = no evidence, not PASS
        self.boom("incomplete scan", report=report(packages=10))

    def test_no_os(self):
        self.boom("did not detect", report=report(family=None))

    def test_image_scan_instead_of_fs(self):
        self.boom("not a filesystem scan", report=report(artifact="container_image"))

    def test_stale_db(self):
        self.boom("Trivy DB", trivy_version={"VulnerabilityDB": {"UpdatedAt": iso(72)}})

    def test_stale_kev(self):
        self.boom("KEV release", kev={**KEV, "dateReleased": iso(days_ago=30)})

    def test_empty_kev(self):
        self.boom("empty KEV catalog", kev={**KEV, "vulnerabilities": []})


class Assessment(unittest.TestCase):
    def run_(self, vulns, policy=POLICY):
        return c.assess(report(vulns), KEV, policy, T)

    def test_fixable_high_blocks(self):
        r = self.run_([vuln()])
        self.assertEqual(len(r["blocked"]), 1)

    def test_unfixed_reported(self):
        r = self.run_([vuln(fixed="")])
        self.assertEqual((len(r["blocked"]), len(r["unfixed"])), (0, 1))

    def test_medium_ignored(self):
        r = self.run_([vuln(sev="MEDIUM")])
        self.assertFalse(any(r.values()))

    def test_kev_blocks_even_unfixed_low(self):
        r = self.run_([vuln(cve="CVE-2026-9999", sev="LOW", fixed="")])
        self.assertEqual(r["blocked"][0]["why"], "KEV - exploited in the wild")

    def test_duplicates_counted_once(self):
        r = self.run_([vuln(), vuln()])
        self.assertEqual(len(r["blocked"]), 1)

    def test_exception_passes(self):
        p = copy.deepcopy(POLICY)
        p["exceptions"] = [{"cve": "CVE-2026-0001", "package": "openssl", "approved_by": "alice",
                            "reason": "test", "approved_at": iso(24), "expires_at": iso(-24)}]
        r = self.run_([vuln()], p)
        self.assertEqual((len(r["blocked"]), len(r["accepted"])), (0, 1))

    def test_expired_exception_ignored(self):
        p = copy.deepcopy(POLICY)
        p["exceptions"] = [{"cve": "CVE-2026-0001", "package": "openssl", "approved_by": "x",
                            "reason": "r", "approved_at": iso(days_ago=20), "expires_at": iso(days_ago=1)}]
        self.assertEqual(len(self.run_([vuln()], p)["blocked"]), 1)

    def test_too_long_exception_rejected(self):
        p = copy.deepcopy(POLICY)
        p["exceptions"] = [{"cve": "CVE-2026-0001", "package": "openssl", "approved_by": "x",
                            "reason": "r", "approved_at": iso(24), "expires_at": iso(days_ago=-60)}]
        with self.assertRaises(c.InputError):
            self.run_([vuln()], p)

    def test_kev_requires_vex(self):
        p = copy.deepcopy(POLICY)
        base = {"cve": "CVE-2026-9999", "package": "openssl", "approved_by": "x", "reason": "r",
                "approved_at": iso(24), "expires_at": iso(-24)}
        p["exceptions"] = [base]
        self.assertEqual(len(self.run_([vuln(cve="CVE-2026-9999")], p)["blocked"]), 1)
        p["exceptions"] = [{**base, "vex": "not_affected", "justification": "code not reachable"}]
        self.assertEqual(len(self.run_([vuln(cve="CVE-2026-9999")], p)["accepted"]), 1)


class Cli(unittest.TestCase):
    def test_bad_input_blocks_and_reports(self):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            (dp / "inv.json").write_text(json.dumps(inventory(host="foreign")))
            for name, data in (("meta.json", META), ("r.json", report()), ("tv.json", TV), ("kev.json", KEV)):
                (dp / name).write_text(json.dumps(data))
            rc = c.main(["--inventory", str(dp / "inv.json"), "--scan-meta", str(dp / "meta.json"),
                         "--report", str(dp / "r.json"), "--trivy-version", str(dp / "tv.json"),
                         "--kev", str(dp / "kev.json"), "--out-json", str(dp / "v.json"),
                         "--out-md", str(dp / "v.md"), "--commit", "abc",
                         "--policy", str(Path(c.__file__).parent / "cve-policy.json")])
            self.assertEqual(rc, 2)
            v = json.loads((dp / "v.json").read_text(encoding="utf-8"))
            self.assertFalse(v["passed"])
            self.assertIn("expected", v["error"])

    def _run(self, inv, policy=None):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            now_iso = dt.datetime.now(dt.timezone.utc)
            inv = {**inv, "captured_at": now_iso.isoformat()}
            kev = {**KEV, "retrieved_at": now_iso.isoformat(), "dateReleased": now_iso.isoformat()}
            tv = {"VulnerabilityDB": {"UpdatedAt": now_iso.isoformat()}}
            for name, data in (("inv.json", inv), ("meta.json", META), ("r.json", report()),
                               ("tv.json", tv), ("kev.json", kev), ("p.json", policy or POLICY)):
                (dp / name).write_text(json.dumps(data))
            rc = c.main(["--inventory", str(dp / "inv.json"), "--scan-meta", str(dp / "meta.json"),
                         "--report", str(dp / "r.json"), "--trivy-version", str(dp / "tv.json"),
                         "--kev", str(dp / "kev.json"), "--out-json", str(dp / "v.json"),
                         "--out-md", str(dp / "v.md"), "--commit", "abc", "--policy", str(dp / "p.json")])
            return rc, json.loads((dp / "v.json").read_text(encoding="utf-8"))

    def test_clean_host_pass(self):
        rc, v = self._run(inventory())
        self.assertEqual((rc, v["passed"]), (0, True))

    def test_reboot_required_blocks(self):
        rc, v = self._run(inventory(reboot_required=True))
        self.assertEqual(rc, 1)
        self.assertEqual(v["result"]["blocked"][0]["id"], "REBOOT-REQUIRED")

    def test_reboot_report_only_when_policy_allows(self):
        p = {**POLICY, "reboot_required_action": "report"}
        rc, _ = self._run(inventory(reboot_required=True), p)
        self.assertEqual(rc, 0)

    def test_check_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "v.json"
            now = dt.datetime.now(dt.timezone.utc)
            good = {"schema": c.VERDICT_SCHEMA, "passed": True, "commit": "abc",
                    "evaluated_at": now.isoformat()}
            path.write_text(json.dumps(good))
            self.assertEqual(c.check_verdict(str(path), POLICY, "abc", now.timestamp()), 0)
            self.assertEqual(c.check_verdict(str(path), POLICY, "other", now.timestamp()), 1)
            path.write_text(json.dumps({**good, "passed": False}))
            self.assertEqual(c.check_verdict(str(path), POLICY, "abc", now.timestamp()), 1)
            path.write_text(json.dumps({**good, "evaluated_at": (now - dt.timedelta(hours=30)).isoformat()}))
            self.assertEqual(c.check_verdict(str(path), POLICY, "abc", now.timestamp()), 1)


if __name__ == "__main__":
    unittest.main()
