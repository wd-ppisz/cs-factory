#!/usr/bin/env python3
"""Factory CVE controller - prod stage gate.

Evaluates THE FACTORY ITSELF (the factory host: GUI, build tools, runner, OS),
NOT the VM templates the factory produces. Templates have their own gates
(validate-offline, smoke, tier3); scanning their contents is a separate step.

Inputs (CI job artifacts):
  inventory.json      - from `ci/factory_inventory.sh` on the host (who, when, how many
                        packages, digest of /var/lib/dpkg/status, kernel, reboot need)
  scan-meta.json      - from the scan job: digest of the status file Trivy ACTUALLY got
  trivy-factory.json  - `trivy rootfs --list-all-pkgs --format json`
  trivy-version.json  - `trivy version --format json` (vulnerability DB age)
  kev.json            - CISA KEV catalog (downloaded here unless given as a file)
  ci/cve-policy.json  - thresholds and exceptions

Output: cve-verdict.json + cve-report.md, exit code 0 = pass, 1 = block,
2 = untrustworthy input (also a block - missing evidence is not a green light).

Overriding rule: an empty or incomplete scan must NEVER yield PASS. That is why
the controller checks host identity, inventory freshness, DB and KEV freshness,
the dpkg/status digest match between inventory and scan, and package coverage
BEFORE it looks at any finding. No network except fetching KEV; no mutations.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INVENTORY_SCHEMA = "cs-factory-inventory/v1"
VERDICT_SCHEMA = "cs-factory-cve-verdict/v1"
POLICY_SCHEMA = "cs-factory-cve-policy/v1"


class InputError(ValueError):
    """The input does not provide trustworthy evidence - the controller refuses to evaluate."""


def require(cond, reason: str) -> None:
    if not cond:
        raise InputError(reason)


def ts(value: str) -> float:
    require(isinstance(value, str) and value, "missing timestamp")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, f"timestamp without a time zone: {value}")
    return parsed.timestamp()


def age_ok(stamp: str, now: float, max_seconds: float, what: str) -> None:
    age = now - ts(stamp)
    require(age >= -300, f"{what}: timestamp from the future ({stamp})")
    require(age <= max_seconds,
            f"{what}: stale ({age / 3600:.1f} h > {max_seconds / 3600:.0f} h)")


# ---------------------------------------------------------------- input evidence

def check_inputs(inventory: dict, scan_meta: dict, report: dict, trivy_version: dict,
                 kev: dict, policy: dict, now: float) -> dict:
    """Verifies that the scan concerns the right host and is complete and fresh.
    Returns facts for the report. Any deviation = InputError."""
    require(policy.get("schema") in (None, POLICY_SCHEMA), "unknown policy format")
    require(inventory.get("schema") == INVENTORY_SCHEMA, "unknown inventory format")
    require(inventory.get("host") == policy["expected_host"],
            f"inventory from host {inventory.get('host')!r}, expected {policy['expected_host']!r}")
    age_ok(inventory.get("captured_at"), now, policy["max_inventory_age_hours"] * 3600, "inventory")
    installed = inventory.get("installed_packages")
    require(isinstance(installed, int) and installed >= policy["min_packages"],
            f"inventory has {installed} packages (< {policy['min_packages']}) - this is not a full host")
    status_sha = inventory.get("dpkg_status_sha256")
    require(isinstance(status_sha, str) and len(status_sha) == 64, "inventory without a dpkg/status digest")
    require(scan_meta.get("dpkg_status_sha256") == status_sha,
            "the scan got a DIFFERENT dpkg/status file than the inventory - the result does not describe this host")

    require(report.get("ArtifactType") == "filesystem", f"not a filesystem scan: {report.get('ArtifactType')!r}")
    os_meta = (report.get("Metadata") or {}).get("OS") or {}
    require(os_meta.get("Family") == policy["expected_os_family"],
            f"Trivy did not detect {policy['expected_os_family']} (Family={os_meta.get('Family')!r})")
    require(not os_meta.get("EOSL"), f"OS {os_meta.get('Family')} {os_meta.get('Name')} is past end of support")
    os_sections = [r for r in report.get("Results") or [] if r.get("Class") == "os-pkgs"]
    require(os_sections, "no os-pkgs section in the Trivy report")
    scanned = sum(len(r.get("Packages") or []) for r in os_sections)
    coverage = scanned / installed
    require(coverage >= policy["min_package_coverage"],
            f"Trivy scanned {scanned} of {installed} packages ({coverage:.0%}) - "
            "incomplete scan (missing --list-all-pkgs or a damaged status file)")

    db = trivy_version.get("VulnerabilityDB") or {}
    age_ok(db.get("UpdatedAt"), now, policy["max_database_age_hours"] * 3600, "Trivy DB")

    require(isinstance(kev.get("vulnerabilities"), list) and kev["vulnerabilities"], "empty KEV catalog")
    age_ok(kev.get("retrieved_at"), now, policy["max_kev_age_hours"] * 3600, "KEV retrieval")
    age_ok(kev.get("dateReleased"), now, policy["max_kev_release_age_days"] * 86400, "KEV release")

    return {"host": inventory["host"], "captured_at": inventory["captured_at"],
            "installed_packages": installed, "scanned_packages": scanned,
            "os": f"{os_meta.get('Family')} {os_meta.get('Name')}",
            "trivy_db_updated_at": db.get("UpdatedAt"), "kev_released": kev.get("dateReleased"),
            "running_kernel": inventory.get("running_kernel"),
            "reboot_required": bool(inventory.get("reboot_required"))}


# ---------------------------------------------------------------- findings

def findings(report: dict) -> list[dict]:
    out = []
    for section in report.get("Results") or []:
        for v in section.get("Vulnerabilities") or []:
            require(all(v.get(k) for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")),
                    "incomplete finding in the Trivy report")
            fixed = v.get("FixedVersion")
            require(fixed is None or isinstance(fixed, str), "invalid FixedVersion")
            out.append({"id": v["VulnerabilityID"], "package": v["PkgName"],
                        "installed": v["InstalledVersion"], "fixed": (fixed or "").strip(),
                        "severity": v["Severity"], "status": v.get("Status", ""),
                        "title": (v.get("Title") or "")[:160], "class": section.get("Class")})
    return out


def matching_exception(f: dict, exceptions: list[dict], kev_hit: bool, policy: dict, now: float):
    for e in exceptions:
        if e.get("cve") != f["id"] or e.get("package") != f["package"]:
            continue
        require(e.get("approved_by") and e.get("reason"), f"exception {f['id']} without an approver and a reason")
        issued, expiry = ts(e.get("approved_at")), ts(e.get("expires_at"))
        require(0 < expiry - issued <= policy["max_exception_days"] * 86400,
                f"exception {f['id']} longer than {policy['max_exception_days']} days")
        if not issued <= now < expiry:
            continue  # expired or not yet valid - does not apply, but does not break the evaluation
        # KEV = exploited in the wild. A plain risk acceptance is not enough: a VEX
        # statement that the host is NOT affected, with a justification, is required.
        if kev_hit and not (e.get("vex") == "not_affected" and e.get("justification")):
            continue
        return e
    return None


def assess(report: dict, kev: dict, policy: dict, now: float) -> dict:
    require(policy.get("fixable_action") in ("block", "warn"), "unknown fixable_action")
    require(policy.get("unfixed_action") in ("block", "allow_and_report"), "unknown unfixed_action")
    require(policy.get("kev_action") in ("block",), "kev_action can only be block")
    exploited = {x.get("cveID") for x in kev["vulnerabilities"]}
    blocked, warned, unfixed, accepted = [], [], [], []
    seen = set()
    for f in findings(report):
        key = (f["id"], f["package"], f["installed"])
        if key in seen:
            continue
        seen.add(key)
        kev_hit = f["id"] in exploited
        f["kev"] = kev_hit
        if not kev_hit and f["severity"] not in policy["blocked_severities"]:
            continue
        exc = matching_exception(f, policy.get("exceptions") or [], kev_hit, policy, now)
        if exc:
            accepted.append({**f, "exception": {k: exc.get(k) for k in
                                                ("approved_by", "reason", "expires_at", "vex")}})
        elif kev_hit:
            blocked.append({**f, "why": "KEV - exploited in the wild"})
        elif f["fixed"] and policy["fixable_action"] == "block":
            blocked.append({**f, "why": "fix available, host not patched"})
        elif f["fixed"]:
            warned.append(f)
        elif policy["unfixed_action"] == "block":
            blocked.append({**f, "why": "no fix available, policy blocks"})
        else:
            unfixed.append(f)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    for lst in (blocked, warned, unfixed, accepted):
        lst.sort(key=lambda x: (not x.get("kev"), order.get(x["severity"], 9), x["package"], x["id"]))
    return {"blocked": blocked, "warned": warned, "unfixed": unfixed, "accepted": accepted}


# ---------------------------------------------------------------- report

def render_md(verdict: dict) -> str:
    facts, res = verdict.get("facts") or {}, verdict.get("result") or {}
    lines = [f"# Factory CVE controller - {'PASS' if verdict['passed'] else 'BLOCKED'}", ""]
    if verdict.get("error"):
        lines += [f"**Input rejected:** {verdict['error']}", "",
                  "No trustworthy evidence = block. Re-run the `cve_inventory` -> `cve_scan` jobs.", ""]
    if facts:
        lines += ["| fact | value |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in facts.items()]
        lines.append("")
    for title, key in (("Blocking", "blocked"), ("Warnings (fix available)", "warned"),
                       ("No fix (report only)", "unfixed"), ("Accepted by exception", "accepted")):
        items = res.get(key) or []
        lines.append(f"## {title}: {len(items)}")
        if items:
            lines += ["", "| CVE | package | installed | fixed | severity | KEV |", "|---|---|---|---|---|---|"]
            for f in items[:200]:
                lines.append(f"| {f['id']} | {f['package']} | {f['installed']} | {f['fixed'] or '-'} "
                             f"| {f['severity']} | {'YES' if f.get('kev') else ''} |")
            if len(items) > 200:
                lines.append(f"| ... | +{len(items) - 200} | | | | |")
        lines.append("")
    if facts.get("reboot_required"):
        lines += ["WARNING: the host is waiting for a reboot - kernel/library fixes are not active until then.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI

def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fetch_kev() -> dict:
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "cve-controller"})
    # fixed, hard-coded https constant (KEV_URL) - no external input
    with urllib.request.urlopen(req, timeout=60) as r:  # nosec B310
        kev = json.load(r)
    kev["retrieved_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    return kev


def check_verdict(path: str, policy: dict, commit: str, now: float) -> int:
    """Mode for the deploy job: the verdict must be PASS, fresh and for this commit."""
    v = load(path)
    try:
        require(v.get("schema") == VERDICT_SCHEMA, "unknown verdict format")
        require(v.get("passed") is True, "the controller verdict is BLOCKED")
        require(v.get("commit") == commit, f"verdict for commit {v.get('commit')}, deploying {commit}")
        age_ok(v.get("evaluated_at"), now, policy["max_verdict_age_hours"] * 3600, "CVE verdict")
    except InputError as e:
        print(f"DEPLOY BLOCKED: {e}. Re-run the cve_inventory -> cve_scan -> cve_controller jobs.")
        return 1
    print(f"CVE verdict OK ({v['evaluated_at']}, commit {commit[:12]})")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--policy", default="ci/cve-policy.json")
    p.add_argument("--inventory", default="inventory.json")
    p.add_argument("--scan-meta", default="scan-meta.json")
    p.add_argument("--report", default="trivy-factory.json")
    p.add_argument("--trivy-version", default="trivy-version.json")
    p.add_argument("--kev", help="KEV file (downloaded from CISA by default)")
    p.add_argument("--out-json", default="cve-verdict.json")
    p.add_argument("--out-md", default="cve-report.md")
    p.add_argument("--commit", default="")
    p.add_argument("--check-verdict", help="only check an existing verdict (deploy job)")
    a = p.parse_args(argv)
    policy = load(a.policy)
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    if a.check_verdict:
        return check_verdict(a.check_verdict, policy, a.commit, now)

    verdict = {"schema": VERDICT_SCHEMA, "commit": a.commit,
               "evaluated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "passed": False}
    code = 2
    try:
        kev = load(a.kev) if a.kev else fetch_kev()
        report = load(a.report)
        verdict["facts"] = check_inputs(load(a.inventory), load(a.scan_meta), report,
                                        load(a.trivy_version), kev, policy, now)
        res = assess(report, kev, policy, now)
        # Trivy sees the dpkg state, not what is running. After an update without a
        # reboot (especially a kernel within the same ABI) the scan is clean while
        # the host still executes vulnerable code. Blocks by default.
        if verdict["facts"]["reboot_required"] and policy.get("reboot_required_action", "block") == "block":
            res["blocked"].insert(0, {"id": "REBOOT-REQUIRED", "package": "(host)",
                                      "installed": verdict["facts"].get("running_kernel") or "?",
                                      "fixed": "reboot the host", "severity": "HIGH", "kev": False,
                                      "why": "fixes installed but not active until a reboot"})
        verdict["result"] = res
        verdict["counts"] = {k: len(v) for k, v in res.items()}
        verdict["passed"] = not res["blocked"]
        code = 0 if verdict["passed"] else 1
    except (InputError, OSError, ValueError, KeyError) as e:
        verdict["error"] = f"{type(e).__name__}: {e}" if not isinstance(e, InputError) else str(e)
    Path(a.out_json).write_text(json.dumps(verdict, indent=2, ensure_ascii=False), encoding="utf-8")
    md = render_md(verdict)
    Path(a.out_md).write_text(md, encoding="utf-8")
    print(md)
    return code


if __name__ == "__main__":
    sys.exit(main())
