"""
Prometheus metrics definitions for UniVex.
"""
from prometheus_client import Counter, Histogram, Gauge

# HTTP metrics
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"]
)
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

# Tool execution metrics
tool_executions_total = Counter(
    "tool_executions_total",
    "Total tool executions",
    ["tool_name", "status"]
)
tool_execution_duration_seconds = Histogram(
    "tool_execution_duration_seconds",
    "Tool execution duration in seconds",
    ["tool_name"],
    buckets=[1, 5, 15, 30, 60, 120, 300, 600, 1800]
)

# Job/scan metrics
active_scans = Gauge("active_scans_total", "Number of currently active scans")
queued_jobs = Gauge("queued_jobs_total", "Number of jobs in the queue")
scan_duration_seconds = Histogram(
    "scan_duration_seconds",
    "Full scan duration in seconds",
    ["scan_type"],
    buckets=[60, 300, 600, 1800, 3600, 7200, 14400]
)

# Error metrics
errors_total = Counter(
    "errors_total",
    "Total errors",
    ["error_type", "endpoint"]
)
