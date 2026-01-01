# Bidi/Hidden Unicode CI Enforcement - Wave 2

**Date:** 2026-01-01
**Repo:** saas202529
**Wave:** 2 (Fleet Rollout)

## Changes Made

1. **Added bidi scan script:** `scripts/security/bidi_scan.mjs`
2. **Updated CI workflow:** .github/workflows/security-bidi.yml (dedicated)
3. **Evidence report:** This file

## Purpose

Prevent Trojan Source attacks (CVE-2021-42574) by detecting bidirectional and hidden Unicode control characters in source code.

## Verification

Local scan:
```bash
node scripts/security/bidi_scan.mjs
# Expected: ✅ No unsafe Unicode control characters found.
```

## Safety Checklist

- ✅ No `pull_request_target` introduced
- ✅ Minimal permissions (`contents: read`)
- ✅ Fail-fast placement (runs early in CI)
- ✅ No external downloads (uses git ls-files)

## References

- Wave 1 baseline scan: ai-guidance PR #72
- Fleet scanner: `pnpm fleet:bidi-ci-scan` in ai-guidance
- CVE-2021-42574: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574

---

🤖 Generated with [Claude Code](https://claude.com/claude-code) via verdaio-bot (Wave 2 autofix)
