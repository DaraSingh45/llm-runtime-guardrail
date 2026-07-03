from prometheus_client import Counter, Histogram

REQUESTS_TOTAL = Counter("guardrail_requests_total", "Total chat requests received")
REQUESTS_BLOCKED_TOTAL = Counter("guardrail_requests_blocked_total", "Requests blocked, by direction", ["direction"])
FINDINGS_TOTAL = Counter("guardrail_findings_total", "Findings emitted, by layer and label", ["layer", "label"])
SCAN_LATENCY = Histogram("guardrail_scan_latency_seconds", "Time to run the full detection pipeline on one text blob")
