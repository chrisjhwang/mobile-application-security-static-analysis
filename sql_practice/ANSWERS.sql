-- ANSWERS.sql — worked solutions for EXERCISES.md
-- Try each exercise yourself first. Run with: sqlite3 compliance_findings.db < ANSWERS.sql
-- (or paste individual queries into a SQLite client)

-- ============================================================
-- Tier 1 — SELECT, WHERE, ORDER BY
-- ============================================================

-- 1. First 10 apps, alphabetically
SELECT * FROM apps ORDER BY app_name LIMIT 10;

-- 2. Apps with HIGH risk on RQ4
SELECT app_id, risk_level FROM rq4_scan WHERE risk_level = 'HIGH';

-- 3. Unused permissions mentioning LOCATION
SELECT DISTINCT permission FROM rq5_unused_permissions WHERE permission LIKE '%LOCATION%';

-- 4. Unguarded content providers
SELECT COUNT(*) FROM rq7_vulnerable_components WHERE component_type = 'provider';

-- 5. Apps with fewest total permissions (RQ4)
SELECT app_id, normal_count + dangerous_count AS total_perms
FROM rq4_scan
ORDER BY total_perms ASC
LIMIT 10;

-- ============================================================
-- Tier 2 — Aggregates, GROUP BY, HAVING
-- ============================================================

-- 6. App count per risk bucket
SELECT risk_level, COUNT(*) AS app_count
FROM rq4_scan
GROUP BY risk_level
ORDER BY app_count DESC;

-- 7. Flagged instances per exported component type
SELECT component_type, COUNT(*) AS flagged_count
FROM rq7_vulnerable_components
GROUP BY component_type
ORDER BY flagged_count DESC;

-- 8. Top 10 most common "unused" permissions
SELECT permission, COUNT(*) AS flag_count
FROM rq5_unused_permissions
GROUP BY permission
ORDER BY flag_count DESC
LIMIT 10;

-- 9. Apps with >20 unguarded exported components
SELECT app_id, COUNT(*) AS vuln_count
FROM rq7_vulnerable_components
GROUP BY app_id
HAVING vuln_count > 20
ORDER BY vuln_count DESC;

-- ============================================================
-- Tier 3 — JOINs
-- ============================================================

-- 10. App name + risk level for HIGH-risk apps
SELECT a.app_name, s.risk_level
FROM apps a
JOIN rq4_scan s ON s.app_id = a.app_id
WHERE s.risk_level = 'HIGH'
ORDER BY a.app_name;

-- 11. Top 10 apps by unguarded exported component count
SELECT a.app_name, COUNT(*) AS vuln_count
FROM apps a
JOIN rq7_vulnerable_components v ON v.app_id = a.app_id
GROUP BY a.app_id
ORDER BY vuln_count DESC
LIMIT 10;

-- 12. Dangerous permissions with vs. without call-site evidence
SELECT p.app_id, p.permission,
       CASE WHEN e.call_site IS NULL THEN 'NO EVIDENCE — needs manual review' ELSE 'has evidence' END AS evidence_status
FROM rq4_permissions p
LEFT JOIN rq4_permission_evidence e
       ON e.app_id = p.app_id AND e.permission = p.permission
WHERE p.permission_type = 'dangerous'
GROUP BY p.app_id, p.permission
ORDER BY evidence_status DESC;

-- ============================================================
-- Tier 4 — Subqueries & set logic
-- ============================================================

-- 13. Compounding risk: VULNERABLE on both RQ5 and RQ7 (subquery)
SELECT a.app_name
FROM apps a
WHERE a.app_id IN (SELECT app_id FROM rq5_scan WHERE status = 'VULNERABLE')
  AND a.app_id IN (SELECT app_id FROM rq7_scan WHERE status = 'VULNERABLE')
ORDER BY a.app_name;

-- 14. Same result using INTERSECT
SELECT app_id FROM rq5_scan WHERE status = 'VULNERABLE'
INTERSECT
SELECT app_id FROM rq7_scan WHERE status = 'VULNERABLE';

-- 15. VULNERABLE on RQ7 with zero safe-by-design exports
SELECT a.app_name
FROM apps a
JOIN rq7_scan s ON s.app_id = a.app_id AND s.status = 'VULNERABLE'
WHERE a.app_id NOT IN (SELECT app_id FROM rq7_safe_exports)
ORDER BY a.app_name;

-- ============================================================
-- Tier 5 — CTEs & window functions
-- ============================================================

-- 16. Risk register: rank apps by combined finding count across all three checks
WITH finding_totals AS (
    SELECT
        a.app_id,
        a.app_name,
        COALESCE((SELECT dangerous_count FROM rq4_scan WHERE app_id = a.app_id), 0) AS rq4_dangerous,
        COALESCE((SELECT COUNT(*) FROM rq5_unused_permissions WHERE app_id = a.app_id), 0) AS rq5_unused,
        COALESCE((SELECT COUNT(*) FROM rq7_vulnerable_components WHERE app_id = a.app_id), 0) AS rq7_unguarded
    FROM apps a
)
SELECT
    app_name,
    rq4_dangerous, rq5_unused, rq7_unguarded,
    (rq4_dangerous + rq5_unused + rq7_unguarded) AS total_findings,
    RANK() OVER (ORDER BY (rq4_dangerous + rq5_unused + rq7_unguarded) DESC) AS risk_rank
FROM finding_totals
ORDER BY risk_rank
LIMIT 15;

-- 17. Share of total unused-permission findings per permission
SELECT
    permission,
    COUNT(*) AS flag_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM rq5_unused_permissions), 2) AS pct_of_all_findings
FROM rq5_unused_permissions
GROUP BY permission
ORDER BY flag_count DESC
LIMIT 10;

-- 18. Quartile apps by vulnerable-activity count
WITH per_app_activities AS (
    SELECT app_id, COUNT(*) AS activity_count
    FROM rq7_vulnerable_components
    WHERE component_type = 'activity'
    GROUP BY app_id
)
SELECT
    app_id,
    activity_count,
    NTILE(4) OVER (ORDER BY activity_count) AS quartile
FROM per_app_activities
ORDER BY activity_count DESC;

-- ============================================================
-- Tier 6 — Building compliance artifacts
-- ============================================================

-- 19. Control testing summary — reproduces the paper's headline flag rates
SELECT 'RQ4 — Internet + PII' AS control,
       COUNT(*) AS apps_tested,
       SUM(CASE WHEN risk_level != 'NONE' THEN 1 ELSE 0 END) AS apps_flagged,
       ROUND(100.0 * SUM(CASE WHEN risk_level != 'NONE' THEN 1 ELSE 0 END) / COUNT(*), 1) AS flag_rate_pct
FROM rq4_scan
UNION ALL
SELECT 'RQ5 — Unused Permissions',
       COUNT(*),
       SUM(CASE WHEN status = 'VULNERABLE' THEN 1 ELSE 0 END),
       ROUND(100.0 * SUM(CASE WHEN status = 'VULNERABLE' THEN 1 ELSE 0 END) / COUNT(*), 1)
FROM rq5_scan
UNION ALL
SELECT 'RQ7 — Unguarded Exports',
       COUNT(*),
       SUM(CASE WHEN status = 'VULNERABLE' THEN 1 ELSE 0 END),
       ROUND(100.0 * SUM(CASE WHEN status = 'VULNERABLE' THEN 1 ELSE 0 END) / COUNT(*), 1)
FROM rq7_scan;

-- 20. Full evidence export for a single app (swap the app_name literal to parameterize)
WITH target AS (
    SELECT app_id FROM apps WHERE app_name = 'Amazon Alexa_2.2.486074.0_Apkpure'
)
SELECT app_id, 'RQ4' AS check_name,
       'INTERNET + ' || permission_type || ': ' || permission AS finding_detail
FROM rq4_permissions WHERE app_id IN (SELECT app_id FROM target)
UNION ALL
SELECT app_id, 'RQ5', 'Unused permission: ' || permission
FROM rq5_unused_permissions WHERE app_id IN (SELECT app_id FROM target)
UNION ALL
SELECT app_id, 'RQ7', 'Unguarded ' || component_type || ': ' || component_name
FROM rq7_vulnerable_components WHERE app_id IN (SELECT app_id FROM target);
