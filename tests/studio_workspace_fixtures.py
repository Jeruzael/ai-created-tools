"""Invented Phase 2 preview data. Never inspect files, registry or processes."""

from studio_preview import FIXTURE_ROOT, dashboard


def processes():
    return [{"pid": index + 1000, "parent_pid": 999, "name": f"Fixture{index}.exe",
             "friendly_name": f"Synthetic program {index}", "publisher": f"Fixture publisher {index % 7}",
             "memory_bytes": (index + 1) * 1024 * 1024,
             "memory": dashboard.format_size((index + 1) * 1024 * 1024),
             "executable_path": FIXTURE_ROOT + f"\\Program{index}\\Fixture.exe",
             "command_line": FIXTURE_ROOT + "\\Fixture.exe " + "synthetic-argument " * 60,
             "review_reasons": ["Synthetic review indicator"] if index % 9 == 0 else [],
             "risk_indicators": [], "signature": {"status": "Unavailable", "error": "Synthetic data; no verification attempted"},
             "sha256": None} for index in range(501)]


def security_record():
    findings = [dashboard.normalize_security_finding(dashboard.security_finding(
        "Registry Startup", f"Synthetic finding {index}", severity="Low Review", score=20,
        evidence={"path": FIXTURE_ROOT + f"\\Fixture{index}.exe"},
        review_reasons=["Synthetic evidence, not a real machine finding"])) for index in range(63)]
    coverage = dashboard.new_security_coverage("standard")
    dashboard.update_security_coverage(coverage, "registry_startup", dashboard.SecurityCollection(
        findings, [], [dashboard.security_source_result("Synthetic user startup", "complete", len(findings))]))
    record = {"schema_version": "security-check-lifecycle-v1", "check_id": "f" * 32,
              "status": "cancelled", "mode": "standard", "options": {}, "findings": findings,
              "started_at": "2026-10-31T09:30:00", "completed_at": "2026-10-31T09:31:00",
              "steps": dashboard.security_check_steps(), "skipped_items": [], "errors": [],
              "collector_coverage": coverage}
    dashboard.validate_security_check_record_payload(record)
    return dashboard.project_security_check_record(record)


def installer_review():
    files = [{"name": f"Fixture{index}.msp", "path": FIXTURE_ROOT + f"\\Installer\\Fixture{index}.msp",
              "package_type": "Synthetic MSP", "extension": ".msp", "size_bytes": (index + 1) * 1024,
              "size": dashboard.format_size((index + 1) * 1024), "classification": "Unknown MSP",
              "confidence": "Unknown", "needs_review": True, "incomplete_checks": ["Synthetic preview"],
              "backup_review": {"eligible_for_manifest": False, "status": "Manual investigation",
                                "reason": "Invented data; no package was inspected"},
              "recommendation": "Synthetic evidence only. Do not remove real cache files."}
             for index in range(63)]
    return {"cache_path": FIXTURE_ROOT + "\\Installer", "collected_at": "2026-10-31T09:30:00",
            "summary": {"status": "Synthetic incomplete review", "cache_files": len(files), "unknown_files": len(files)},
            "coverage": {"status": "Unavailable (synthetic)", "complete": False}, "files": files,
            "missing_registered_files": [{"path": FIXTURE_ROOT + f"\\Missing{index}.msi", "products": ["Fixture product"],
                                          "recommendation": "Synthetic missing-file evidence"} for index in range(63)],
            "errors": ["Synthetic preview only. No installer cache or registrations were read."]}
