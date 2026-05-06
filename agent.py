"""
Infranexis Resolve — Forwarder Agent
=====================================
Runs anywhere: Kubernetes pod, Linux VM, bare-metal server.
Makes ONE outbound WebSocket connection to Resolve backend.
No inbound ports required.

Install options:
  Kubernetes:  kubectl apply -f https://your-server/dashboard/install/{customer_id}.yaml
  Linux/VM:    curl -fsSL https://your-server/dashboard/install/{customer_id}.sh | sudo bash
  Docker:      docker run -e RCABOT_API_KEY=... ghcr.io/infranexis/resolve-agent:latest

Environment variables:
  RCABOT_SERVER_URL   - wss://your-server/agent/ws
  RCABOT_API_KEY      - rbk_live_xxx
  RCABOT_CUSTOMER_ID  - uuid
  RCABOT_NAMESPACES   - production,staging  (k8s only)
"""

import asyncio
import json
import logging
import os
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

import websockets

# k8s is optional — agent works without it on plain Linux
try:
    from kubernetes import client as k8s_client, config as k8s_config
    from kubernetes.client.rest import ApiException
    _K8S_AVAILABLE = True
except ImportError:
    _K8S_AVAILABLE = False

# psutil for system metrics — optional
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("rcabot-agent")

# Config from environment
SERVER_URL   = os.environ["RCABOT_SERVER_URL"]    # wss://api.yourproduct.com/agent/ws
API_KEY      = os.environ["RCABOT_API_KEY"]        # rbk_live_xxx
CUSTOMER_ID  = os.environ["RCABOT_CUSTOMER_ID"]
NAMESPACES   = os.environ.get("RCABOT_NAMESPACES", "default").split(",")
VERSION      = "0.1.0"
HEARTBEAT_INTERVAL = 30  # seconds

# Labels: RCABOT_LABELS=env=prod,role=webserver
def _parse_labels(raw: str) -> dict:
    labels = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            labels[k.strip()] = v.strip()
    return labels

LABELS = _parse_labels(os.environ.get("RCABOT_LABELS", ""))


# ---------------------------------------------------------------------------
# Cloud environment detection
# ---------------------------------------------------------------------------

def _imds_get(url: str, headers: dict = None, timeout: float = 1.5) -> bool:
    """Return True if an IMDS endpoint responds with 2xx."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status < 300
    except Exception:
        return False


def detect_capabilities() -> list:
    """
    Probe what's available: k8s, system (Linux), cloud provider.
    """
    caps = []

    # k8s — only if library present and config loads
    if _K8S_AVAILABLE:
        try:
            k8s_config.load_incluster_config()
            caps.append("k8s")
        except Exception:
            try:
                k8s_config.load_kube_config()
                caps.append("k8s")
            except Exception:
                pass

    # system — always available on Linux
    import platform
    if platform.system() == "Linux":
        caps.append("system")

    if not caps:
        caps.append("system")  # fallback

    # eBPF — bpftrace present and we can run a trivial probe
    try:
        r = subprocess.run(
            ["bpftrace", "-e", "BEGIN { exit(); }"],
            capture_output=True, timeout=5,
        )
        if r.returncode == 0:
            caps.append("ebpf")
            logger.info("Detected bpftrace — eBPF context enabled")
        else:
            logger.info("bpftrace found but probe failed (needs root / CAP_BPF)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # AWS: IMDSv2 token request
    if _imds_get(
        "http://169.254.169.254/latest/meta-data/",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "10"},
    ):
        caps.append("aws")
        logger.info("Detected AWS environment")

    # Azure: IMDS
    elif _imds_get(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers={"Metadata": "true"},
    ):
        caps.append("azure")
        logger.info("Detected Azure environment")

    # GCP: metadata server
    elif _imds_get(
        "http://metadata.google.internal/computeMetadata/v1/",
        headers={"Metadata-Flavor": "Google"},
    ):
        caps.append("gcp")
        logger.info("Detected GCP environment")

    return caps


# ---------------------------------------------------------------------------
# Cloud context collectors
# ---------------------------------------------------------------------------

# Cloud config from environment
AWS_REGION     = os.environ.get("RCABOT_AWS_REGION", "")
AWS_LOG_GROUPS = [g.strip() for g in os.environ.get("RCABOT_AWS_LOG_GROUPS", "").split(",") if g.strip()]
AZURE_WORKSPACE_ID = os.environ.get("RCABOT_AZURE_WORKSPACE_ID", "")
AZURE_RESOURCE_ID  = os.environ.get("RCABOT_AZURE_RESOURCE_ID", "")
GCP_PROJECT_ID  = os.environ.get("RCABOT_GCP_PROJECT_ID", "")
GCP_LOG_NAMES   = [n.strip() for n in os.environ.get("RCABOT_GCP_LOG_NAMES", "").split(",") if n.strip()]


def _get_aws_region() -> str:
    if AWS_REGION:
        return AWS_REGION
    try:
        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "10"},
        )
        with urllib.request.urlopen(token_req, timeout=1.5) as r:
            token = r.read().decode()
        region_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/placement/region",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(region_req, timeout=1.5) as r:
            return r.read().decode()
    except Exception:
        return "us-east-1"


def _parse_alert_time(fired_at: str) -> datetime:
    try:
        return datetime.fromisoformat(fired_at.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)

def collect_aws_context(service: str, fired_at: str) -> dict:
    """
    Collect AWS context via instance-role / IRSA — no static credentials needed.
    Gathers: CloudWatch Logs, Metrics, Alarms, CloudTrail events.
    Optional env vars: RCABOT_AWS_REGION, RCABOT_AWS_LOG_GROUPS
    """
    try:
        import boto3
        from datetime import timedelta
    except ImportError:
        return {"error": "boto3 not installed — run: pip install boto3"}

    result    = {}
    alert_time = _parse_alert_time(fired_at)
    start_time = alert_time - timedelta(minutes=15)
    end_time   = alert_time + timedelta(minutes=5)
    region     = _get_aws_region()

    # ── 1. CloudWatch Logs ──────────────────────────────────────────────────
    try:
        logs_client = boto3.client("logs", region_name=region)
        log_groups  = list(AWS_LOG_GROUPS)
        if not log_groups:
            try:
                resp = logs_client.describe_log_groups(logGroupNamePattern=service, limit=5)
                log_groups = [g["logGroupName"] for g in resp.get("logGroups", [])]
            except Exception:
                pass
            if not log_groups:
                log_groups = [
                    f"/aws/lambda/{service}",
                    f"/aws/ecs/{service}",
                    f"/aws/rds/instance/{service}/error",
                ]

        cw_logs = []
        for group in log_groups[:4]:
            try:
                resp = logs_client.filter_log_events(
                    logGroupName=group,
                    startTime=int(start_time.timestamp() * 1000),
                    endTime=int(end_time.timestamp() * 1000),
                    filterPattern="?ERROR ?Error ?WARN ?FATAL ?Exception ?exception ?panic",
                    limit=50,
                )
                events = [
                    {
                        "time":    datetime.fromtimestamp(e["timestamp"] / 1000, tz=timezone.utc).isoformat(),
                        "message": e["message"][:500],
                    }
                    for e in resp.get("events", [])
                ]
                if events:
                    cw_logs.append({"log_group": group, "events": events})
            except Exception as e:
                if "ResourceNotFoundException" not in str(e):
                    cw_logs.append({"log_group": group, "error": str(e)})
        result["cloudwatch_logs"] = cw_logs
    except Exception as e:
        result["cloudwatch_logs"] = [{"error": str(e)}]

    # ── 2. CloudWatch Metrics ───────────────────────────────────────────────
    try:
        cw = boto3.client("cloudwatch", region_name=region)
        _METRICS = [
            ("AWS/EC2",             "CPUUtilization",              "InstanceId"),
            ("AWS/ECS",             "CPUUtilization",              "ServiceName"),
            ("AWS/ECS",             "MemoryUtilization",           "ServiceName"),
            ("AWS/RDS",             "CPUUtilization",              "DBInstanceIdentifier"),
            ("AWS/RDS",             "DatabaseConnections",         "DBInstanceIdentifier"),
            ("AWS/Lambda",          "Duration",                    "FunctionName"),
            ("AWS/Lambda",          "Errors",                      "FunctionName"),
            ("AWS/Lambda",          "Throttles",                   "FunctionName"),
            ("AWS/ApplicationELB",  "HTTPCode_Target_5XX_Count",   "LoadBalancer"),
        ]
        metrics_out = []
        for namespace, metric_name, dim_name in _METRICS:
            try:
                resp = cw.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric_name,
                    Dimensions=[{"Name": dim_name, "Value": service}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=60,
                    Statistics=["Average", "Maximum", "Sum"],
                )
                pts = sorted(resp["Datapoints"], key=lambda x: x["Timestamp"])
                if pts:
                    metrics_out.append({
                        "namespace": namespace,
                        "metric":    metric_name,
                        "datapoints": [
                            {
                                "time": d["Timestamp"].isoformat(),
                                "avg":  round(d.get("Average", 0), 2),
                                "max":  round(d.get("Maximum", 0), 2),
                                "sum":  round(d.get("Sum", 0), 2),
                            }
                            for d in pts[-15:]
                        ],
                    })
            except Exception:
                pass
        result["cloudwatch_metrics"] = metrics_out
    except Exception as e:
        result["cloudwatch_metrics"] = [{"error": str(e)}]

    # ── 3. CloudWatch Alarms ────────────────────────────────────────────────
    try:
        alarms = cw.describe_alarms(AlarmNamePrefix=service)
        result["cloudwatch_alarms"] = [
            {
                "name":    a["AlarmName"],
                "state":   a["StateValue"],
                "reason":  a["StateReason"],
                "updated": a["StateUpdatedTimestamp"].isoformat(),
            }
            for a in alarms.get("MetricAlarms", [])[:10]
        ]
    except Exception as e:
        result["cloudwatch_alarms"] = [{"error": str(e)}]

    # ── 4. CloudTrail — recent API changes ─────────────────────────────────
    try:
        ct = boto3.client("cloudtrail", region_name=region)
        events = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": service}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=10,
        )
        result["cloudtrail_events"] = [
            {
                "event": e["EventName"],
                "user":  e.get("Username", "unknown"),
                "time":  e["EventTime"].isoformat(),
            }
            for e in events.get("Events", [])
        ]
    except Exception as e:
        result["cloudtrail_events"] = [{"error": str(e)}]

    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


def collect_azure_context(service: str, fired_at: str) -> dict:
    """
    Collect Azure context via Managed Identity — no credentials needed on Azure VMs / AKS.
    Gathers: Log Analytics logs, Azure Monitor metrics.
    Required: pip install azure-identity azure-monitor-query
    Optional env vars: RCABOT_AZURE_WORKSPACE_ID, RCABOT_AZURE_RESOURCE_ID
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient, MetricsQueryClient, LogsQueryStatus
        from datetime import timedelta
    except ImportError:
        return {"error": "Azure SDK not installed — run: pip install azure-identity azure-monitor-query"}

    result     = {}
    alert_time = _parse_alert_time(fired_at)
    start_time = alert_time - timedelta(minutes=15)
    end_time   = alert_time + timedelta(minutes=5)
    timespan   = (start_time, end_time)

    try:
        credential = DefaultAzureCredential()
    except Exception as e:
        return {"error": f"Azure credential failed (is Managed Identity enabled?): {e}"}

    # ── 1. Log Analytics ────────────────────────────────────────────────────
    if AZURE_WORKSPACE_ID:
        try:
            logs_client = LogsQueryClient(credential)
            query = f"""
union AppTraces, AppExceptions, AppRequests, ContainerLog
| where TimeGenerated between (datetime('{start_time.isoformat()}') .. datetime('{end_time.isoformat()}'))
| where SeverityLevel >= 2 or Success == false
      or LogEntry contains "ERROR" or LogEntry contains "WARN"
| project TimeGenerated, Message, SeverityLevel, AppRoleName, ContainerName, LogEntry
| order by TimeGenerated desc
| limit 50
"""
            resp = logs_client.query_workspace(AZURE_WORKSPACE_ID, query, timespan=timespan)
            if resp.status == LogsQueryStatus.SUCCESS and resp.tables:
                cols = [c.name for c in resp.tables[0].columns]
                result["azure_logs"] = [
                    dict(zip(cols, [str(v) for v in row]))
                    for row in resp.tables[0].rows[:50]
                ]
            else:
                result["azure_logs"] = [{"note": "No logs returned"}]
        except Exception as e:
            result["azure_logs"] = [{"error": str(e)}]
    else:
        result["azure_logs"] = [{"note": "Set RCABOT_AZURE_WORKSPACE_ID to enable Log Analytics"}]

    # ── 2. Azure Monitor Metrics ────────────────────────────────────────────
    if AZURE_RESOURCE_ID:
        try:
            metrics_client = MetricsQueryClient(credential)
            resp = metrics_client.query_resource(
                AZURE_RESOURCE_ID,
                metric_names=["Percentage CPU", "Network In Total", "Network Out Total",
                               "Available Memory Bytes", "Http5xx"],
                timespan=timespan,
                granularity=timedelta(minutes=1),
            )
            result["azure_metrics"] = [
                {
                    "name": m.name,
                    "datapoints": [
                        {"time": ts.timestamp.isoformat(), "value": ts.average}
                        for ts in (m.timeseries[0].data if m.timeseries else [])
                        if ts.average is not None
                    ][-15:],
                }
                for m in resp.metrics
            ]
        except Exception as e:
            result["azure_metrics"] = [{"error": str(e)}]
    else:
        result["azure_metrics"] = [{"note": "Set RCABOT_AZURE_RESOURCE_ID to enable metrics"}]

    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


def collect_gcp_context(service: str, fired_at: str) -> dict:
    """
    Collect GCP context via Workload Identity / Application Default Credentials.
    Gathers: Cloud Logging entries, Cloud Monitoring metrics.
    Required: pip install google-cloud-logging google-cloud-monitoring
    Optional env vars: RCABOT_GCP_PROJECT_ID, RCABOT_GCP_LOG_NAMES
    """
    try:
        from google.cloud import logging as gcp_logging
        from google.cloud import monitoring_v3
        from datetime import timedelta
    except ImportError:
        return {"error": "GCP SDK not installed — run: pip install google-cloud-logging google-cloud-monitoring"}

    result     = {}
    alert_time = _parse_alert_time(fired_at)
    start_time = alert_time - timedelta(minutes=15)
    end_time   = alert_time + timedelta(minutes=5)

    project_id = GCP_PROJECT_ID
    if not project_id:
        try:
            req = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                headers={"Metadata-Flavor": "Google"},
            )
            with urllib.request.urlopen(req, timeout=2) as r:
                project_id = r.read().decode()
        except Exception:
            return {"error": "RCABOT_GCP_PROJECT_ID not set and metadata server unavailable"}

    # ── 1. Cloud Logging ────────────────────────────────────────────────────
    try:
        log_client = gcp_logging.Client(project=project_id)
        ts_start   = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        ts_end     = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        filter_parts = [
            f'timestamp>="{ts_start}"',
            f'timestamp<="{ts_end}"',
            '(severity>=WARNING OR textPayload=~"(?i)(error|exception|fatal|panic)")',
        ]
        if GCP_LOG_NAMES:
            log_filter = " OR ".join(
                f'logName="projects/{project_id}/logs/{n}"' for n in GCP_LOG_NAMES
            )
            filter_parts.append(f"({log_filter})")
        else:
            filter_parts.append(
                f'(resource.labels.service_name="{service}" OR '
                f'resource.labels.function_name="{service}" OR '
                f'resource.labels.container_name="{service}")'
            )

        entries = list(log_client.list_entries(
            filter_=" AND ".join(filter_parts),
            max_results=50,
            order_by=gcp_logging.DESCENDING,
        ))
        result["gcp_logs"] = [
            {
                "time":     e.timestamp.isoformat() if e.timestamp else None,
                "severity": str(e.severity),
                "message":  str(e.payload)[:500],
            }
            for e in entries
        ]
    except Exception as e:
        result["gcp_logs"] = [{"error": str(e)}]

    # ── 2. Cloud Monitoring Metrics ─────────────────────────────────────────
    try:
        metrics_client = monitoring_v3.MetricServiceClient()
        project_name   = f"projects/{project_id}"

        from google.protobuf.timestamp_pb2 import Timestamp as GProtoTS
        ts_s = GProtoTS(); ts_s.FromDatetime(start_time.replace(tzinfo=None))
        ts_e = GProtoTS(); ts_e.FromDatetime(end_time.replace(tzinfo=None))
        interval = monitoring_v3.TimeInterval({"start_time": ts_s, "end_time": ts_e})

        _GCP_METRICS = [
            ("compute.googleapis.com/instance/cpu/utilization",       "cpu_utilization"),
            ("run.googleapis.com/request_count",                      "request_count"),
            ("run.googleapis.com/request_latencies",                  "request_latency_ms"),
            ("cloudfunctions.googleapis.com/function/execution_count","function_executions"),
            ("cloudfunctions.googleapis.com/function/execution_times","function_duration_ms"),
        ]
        metrics_out = []
        for metric_type, label in _GCP_METRICS:
            try:
                for ts in metrics_client.list_time_series(request={
                    "name":     project_name,
                    "filter":   (
                        f'metric.type="{metric_type}" AND '
                        f'(resource.labels.service_name="{service}" OR '
                        f'resource.labels.function_name="{service}")'
                    ),
                    "interval": interval,
                    "view":     monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                }):
                    metrics_out.append({
                        "metric": label,
                        "points": [
                            {"time": p.interval.end_time.isoformat(),
                             "value": p.value.double_value or p.value.int64_value}
                            for p in ts.points[-15:]
                        ],
                    })
            except Exception:
                pass
        result["gcp_metrics"] = metrics_out
    except Exception as e:
        result["gcp_metrics"] = [{"error": str(e)}]

    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


def collect_aws_infra_context(fired_at: str) -> dict:
    """
    Account-wide AWS infra context — NOT filtered by service name.
    Covers: CloudTrail mutating events, AWS Health incidents, EC2 state changes,
    Auto Scaling activities. Designed to surface regional/account outages.
    """
    try:
        import boto3
        from datetime import timedelta
    except ImportError:
        return {"error": "boto3 not installed — run: pip install boto3"}

    result     = {}
    alert_time = _parse_alert_time(fired_at)
    start_time = alert_time - timedelta(minutes=30)
    end_time   = alert_time + timedelta(minutes=5)
    region     = _get_aws_region()

    # 1. CloudTrail — account-wide mutating events (no ResourceName filter)
    try:
        ct = boto3.client("cloudtrail", region_name=region)
        _MUTATING = ("Create", "Delete", "Update", "Modify", "Put", "Attach",
                     "Detach", "Terminate", "Stop", "Reboot", "Revoke", "Disable")
        resp = ct.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50,
        )
        events = []
        for e in resp.get("Events", []):
            name = e.get("EventName", "")
            if any(name.startswith(p) for p in _MUTATING):
                resources = e.get("Resources", [])
                events.append({
                    "event":    name,
                    "user":     e.get("Username", "unknown"),
                    "resource": resources[0].get("ResourceName", "") if resources else "",
                    "time":     e["EventTime"].isoformat(),
                })
        result["cloudtrail_changes"] = events[:30]
    except Exception as e:
        result["cloudtrail_changes"] = [{"error": str(e)}]

    # 2. AWS Health — active/upcoming events for this region
    try:
        health = boto3.client("health", region_name="us-east-1")  # Health API is us-east-1 only
        resp = health.describe_events(filter={
            "regions":          [region],
            "eventStatusCodes": ["open", "upcoming"],
        })
        result["aws_health_events"] = [
            {
                "service":    e.get("service", ""),
                "type":       e.get("eventTypeCode", ""),
                "status":     e.get("statusCode", ""),
                "region":     e.get("region", ""),
                "start_time": e["startTime"].isoformat() if hasattr(e.get("startTime"), "isoformat") else str(e.get("startTime", "")),
            }
            for e in resp.get("events", [])[:10]
        ] or [{"note": "No active AWS Health events for this region"}]
    except Exception as e:
        result["aws_health_events"] = [{"error": str(e)}]

    # 3. EC2 — instances in non-healthy states
    try:
        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_instances(Filters=[{
            "Name": "instance-state-name",
            "Values": ["stopping", "stopped", "shutting-down"],
        }])
        instances = []
        for reservation in resp.get("Reservations", []):
            for i in reservation.get("Instances", []):
                name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), "")
                instances.append({
                    "id":    i["InstanceId"],
                    "type":  i["InstanceType"],
                    "state": i["State"]["Name"],
                    "name":  name,
                })
        result["ec2_state_changes"] = instances[:20] or [{"note": "No instances in non-healthy state"}]
    except Exception as e:
        result["ec2_state_changes"] = [{"error": str(e)}]

    # 4. Auto Scaling — recent scaling activities
    try:
        asg = boto3.client("autoscaling", region_name=region)
        resp = asg.describe_scaling_activities(MaxRecords=20)
        result["autoscaling_events"] = [
            {
                "group":       a.get("AutoScalingGroupName", ""),
                "description": a.get("Description", ""),
                "status":      a.get("StatusCode", ""),
                "time":        a["StartTime"].isoformat() if hasattr(a.get("StartTime"), "isoformat") else str(a.get("StartTime", "")),
            }
            for a in resp.get("Activities", [])
        ] or [{"note": "No recent Auto Scaling activity"}]
    except Exception as e:
        result["autoscaling_events"] = [{"error": str(e)}]

    result["scope"]        = "account-wide"
    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


def collect_azure_infra_context(fired_at: str) -> dict:
    """
    Subscription-wide Azure infra context — NOT filtered by resource.
    Covers: Azure Service Health events, Activity Log writes/deletes.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from datetime import timedelta
        import os
    except ImportError:
        return {"error": "Azure SDK not installed — run: pip install azure-identity azure-mgmt-monitor"}

    result     = {}
    alert_time = _parse_alert_time(fired_at)
    start_time = alert_time - timedelta(minutes=30)
    end_time   = alert_time + timedelta(minutes=5)

    try:
        credential = DefaultAzureCredential()
    except Exception as e:
        return {"error": f"Azure credential failed: {e}"}

    # Resolve subscription ID
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not subscription_id:
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/metadata/instance/compute/subscriptionId"
                "?api-version=2021-02-01&format=text",
                headers={"Metadata": "true"},
            )
            with urllib.request.urlopen(req, timeout=2) as r:
                subscription_id = r.read().decode().strip()
        except Exception:
            return {"error": "AZURE_SUBSCRIPTION_ID not set and IMDS unavailable"}

    try:
        from azure.mgmt.monitor import MonitorManagementClient
        monitor = MonitorManagementClient(credential, subscription_id)
        ts_start = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        ts_end   = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Service Health events (Microsoft.ResourceHealth provider)
        try:
            health_events = list(monitor.activity_logs.list(
                filter=(
                    f"eventTimestamp ge '{ts_start}' and eventTimestamp le '{ts_end}'"
                    " and resourceProvider eq 'Microsoft.ResourceHealth'"
                ),
                select="eventTimestamp,operationName,resourceGroupName,resourceId,status,level",
            ))
            result["azure_service_health"] = [
                {
                    "time":           e.event_timestamp.isoformat() if e.event_timestamp else None,
                    "operation":      e.operation_name.value if e.operation_name else "",
                    "resource_group": e.resource_group_name or "",
                    "status":         e.status.value if e.status else "",
                    "level":          e.level.value if e.level else "",
                }
                for e in health_events[:15]
            ] or [{"note": "No Azure Service Health events in window"}]
        except Exception as e:
            result["azure_service_health"] = [{"error": str(e)}]

        # 2. Activity Log — write and delete operations (subscription-wide mutations)
        try:
            activity_events = list(monitor.activity_logs.list(
                filter=(
                    f"eventTimestamp ge '{ts_start}' and eventTimestamp le '{ts_end}'"
                ),
                select="eventTimestamp,operationName,resourceGroupName,resourceId,caller,status",
            ))
            result["activity_log_changes"] = [
                {
                    "time":           e.event_timestamp.isoformat() if e.event_timestamp else None,
                    "operation":      e.operation_name.value if e.operation_name else "",
                    "resource_group": e.resource_group_name or "",
                    "resource":       (e.resource_id or "").split("/")[-1],
                    "caller":         e.caller or "",
                    "status":         e.status.value if e.status else "",
                }
                for e in activity_events
                if e.operation_name and any(
                    kw in (e.operation_name.value or "").lower()
                    for kw in ("write", "delete", "action")
                )
            ][:30] or [{"note": "No write/delete operations in window"}]
        except Exception as e:
            result["activity_log_changes"] = [{"error": str(e)}]

    except Exception as e:
        result["error"] = str(e)

    result["scope"]        = "subscription-wide"
    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


def collect_gcp_infra_context(fired_at: str) -> dict:
    """
    Project-wide GCP infra context — NOT filtered by service.
    Covers: GCP Status (open incidents), Cloud Audit Logs (admin activity).
    """
    try:
        from google.cloud import logging as gcp_logging
        from datetime import timedelta
    except ImportError:
        return {"error": "GCP SDK not installed — run: pip install google-cloud-logging"}

    result     = {}
    alert_time = _parse_alert_time(fired_at)
    start_time = alert_time - timedelta(minutes=30)

    project_id = GCP_PROJECT_ID
    if not project_id:
        try:
            req = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                headers={"Metadata-Flavor": "Google"},
            )
            with urllib.request.urlopen(req, timeout=2) as r:
                project_id = r.read().decode().strip()
        except Exception:
            return {"error": "RCABOT_GCP_PROJECT_ID not set and metadata server unavailable"}

    # 1. GCP Status — open incidents (public, no auth required)
    try:
        status_req = urllib.request.Request("https://status.cloud.google.com/incidents.json")
        with urllib.request.urlopen(status_req, timeout=5) as r:
            incidents = json.loads(r.read().decode())
        open_incidents = [
            {
                "id":       i.get("id", ""),
                "service":  i.get("service_name", ""),
                "severity": i.get("severity", ""),
                "summary":  i.get("external_desc", "")[:200],
                "begin":    i.get("begin", ""),
            }
            for i in incidents
            if not i.get("end")  # no end = still open
        ][:10]
        result["gcp_status_incidents"] = open_incidents or [{"note": "No active GCP status incidents"}]
    except Exception as e:
        result["gcp_status_incidents"] = [{"error": str(e)}]

    # 2. Cloud Audit Logs — admin activity across the whole project
    try:
        log_client = gcp_logging.Client(project=project_id)
        ts_start   = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        entries = list(log_client.list_entries(
            filter_=(
                f'timestamp>="{ts_start}" '
                f'logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity" '
                'protoPayload.methodName!~"^(Get|List|Watch|Describe)"'
            ),
            max_results=30,
            order_by=gcp_logging.DESCENDING,
        ))
        result["gcp_audit_logs"] = [
            {
                "time":      e.timestamp.isoformat() if e.timestamp else None,
                "method":    e.payload.get("methodName", "")    if isinstance(e.payload, dict) else str(e.payload)[:100],
                "principal": e.payload.get("authenticationInfo", {}).get("principalEmail", "") if isinstance(e.payload, dict) else "",
                "resource":  e.payload.get("resourceName", "")  if isinstance(e.payload, dict) else "",
                "status":    str(e.payload.get("status", {}).get("code", "OK")) if isinstance(e.payload, dict) else "",
            }
            for e in entries
        ] or [{"note": "No admin activity in window"}]
    except Exception as e:
        result["gcp_audit_logs"] = [{"error": str(e)}]

    result["scope"]        = "project-wide"
    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


# ---------------------------------------------------------------------------
# Kubernetes client setup (optional)
# ---------------------------------------------------------------------------

def setup_k8s():
    """Load k8s config. Returns (CoreV1Api, AppsV1Api) or (None, None)."""
    if not _K8S_AVAILABLE:
        return None, None
    try:
        k8s_config.load_incluster_config()
        logger.info("Loaded in-cluster k8s config")
    except Exception:
        try:
            k8s_config.load_kube_config()
            logger.info("Loaded local kubeconfig (dev mode)")
        except Exception:
            logger.info("No k8s config found — running in system mode")
            return None, None
    return k8s_client.CoreV1Api(), k8s_client.AppsV1Api()


# ---------------------------------------------------------------------------
# System context collector (Linux — no k8s required)
# ---------------------------------------------------------------------------

def handle_collect_system_context(service: str) -> dict:
    """Collect system-level context for a service on a plain Linux host."""
    logger.info(f"Collecting system context for service: {service}")
    result = {}

    # 1. systemd service status
    try:
        out = subprocess.run(
            ["systemctl", "status", service, "--no-pager", "-l"],
            capture_output=True, text=True, timeout=5
        )
        result["systemd_status"] = out.stdout[:2000] or out.stderr[:500]
    except Exception as e:
        result["systemd_status"] = f"systemctl not available: {e}"

    # 2. Recent journal logs for the service
    try:
        out = subprocess.run(
            ["journalctl", "-u", service, "-n", "50", "--no-pager", "--output=short-iso"],
            capture_output=True, text=True, timeout=5
        )
        result["journal_logs"] = out.stdout[:3000] or "(no logs)"
    except Exception as e:
        # Fall back to /var/log if journald not available
        result["journal_logs"] = f"journalctl not available: {e}"
        for log_path in (f"/var/log/{service}.log", f"/var/log/{service}/{service}.log"):
            try:
                out = subprocess.run(["tail", "-n", "50", log_path],
                                     capture_output=True, text=True, timeout=3)
                if out.stdout:
                    result["journal_logs"] = out.stdout[:3000]
                    break
            except Exception:
                pass

    # 3. System resource snapshot
    if _PSUTIL_AVAILABLE:
        try:
            result["system_metrics"] = {
                "cpu_percent":    psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_used_mb": psutil.virtual_memory().used // (1024 * 1024),
                "disk_percent":   psutil.disk_usage("/").percent,
                "load_avg":       list(os.getloadavg()),
            }
            # Find processes matching the service name
            procs = [
                {"pid": p.pid, "name": p.name(), "cpu": p.cpu_percent(),
                 "mem_mb": p.memory_info().rss // (1024 * 1024), "status": p.status()}
                for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"])
                if service.lower() in p.name().lower()
            ]
            result["matching_processes"] = procs[:10]
        except Exception as e:
            result["system_metrics"] = {"error": str(e)}
    else:
        # Basic fallback without psutil
        try:
            load = os.getloadavg()
            result["system_metrics"] = {"load_avg": list(load)}
        except Exception:
            pass

    result["collected_at"] = datetime.now(timezone.utc).isoformat()
    return result


# ---------------------------------------------------------------------------
# Targeted investigation commands (agentic investigation loop)
# ---------------------------------------------------------------------------

def handle_investigate_command(command: str, params: dict) -> dict:
    """Dispatch a targeted investigation command requested by the backend AI loop."""
    handlers = {
        "top_processes":      lambda: _inv_top_processes(),
        "process_details":    lambda: _inv_process_details(params.get("name", ""), params.get("pid")),
        "read_log":           lambda: _inv_read_log(params.get("path", ""), int(params.get("lines", 100))),
        "search_logs":        lambda: _inv_search_logs(params.get("path", ""), params.get("pattern", ""), int(params.get("lines", 50))),
        "journal_logs_unit":  lambda: _inv_journal_unit(params.get("unit", ""), int(params.get("lines", 100))),
        "disk_usage_detail":  lambda: _inv_disk_usage(params.get("path", "/")),
        "network_connections": lambda: _inv_network_connections(params.get("process", "")),
        "system_overview":    lambda: _inv_system_overview(),
    }
    fn = handlers.get(command)
    if fn:
        return fn()
    return {"error": f"Unknown investigation command: {command}"}


def _inv_top_processes() -> dict:
    result = {}
    if _PSUTIL_AVAILABLE:
        procs = []
        for p in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent", "memory_info", "status", "username"]):
            try:
                info = p.info
                procs.append({
                    "pid":    info["pid"],
                    "name":   info["name"],
                    "cmd":    " ".join((info["cmdline"] or [])[:5]) or info["name"],
                    "cpu":    info["cpu_percent"] or 0,
                    "mem_mb": (info["memory_info"].rss // (1024 * 1024)) if info["memory_info"] else 0,
                    "status": info["status"],
                    "user":   info["username"] or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        result["top_by_cpu"]    = sorted(procs, key=lambda x: x["cpu"],    reverse=True)[:15]
        result["top_by_memory"] = sorted(procs, key=lambda x: x["mem_mb"], reverse=True)[:15]
        result["total_processes"] = len(procs)
    else:
        try:
            out = subprocess.run(["ps", "aux", "--sort=-%cpu"], capture_output=True, text=True, timeout=5)
            result["ps_output"] = out.stdout[:3000]
        except Exception as e:
            result["error"] = str(e)
    return result


def _inv_process_details(name: str = "", pid=None) -> dict:
    result = {}
    if _PSUTIL_AVAILABLE:
        targets = []
        if pid:
            try:
                targets = [psutil.Process(int(pid))]
            except Exception:
                pass
        elif name:
            targets = [p for p in psutil.process_iter(["name"]) if name.lower() in p.name().lower()][:5]

        if not targets:
            return {"error": f"No process found: name={name} pid={pid}"}

        details = []
        for p in targets[:3]:
            try:
                with p.oneshot():
                    d = {
                        "pid":     p.pid,
                        "name":    p.name(),
                        "cmdline": " ".join(p.cmdline()[:10]) if p.cmdline() else "",
                        "status":  p.status(),
                        "cpu":     p.cpu_percent(interval=0.5),
                        "mem_mb":  p.memory_info().rss // (1024 * 1024),
                        "threads": p.num_threads(),
                        "user":    p.username(),
                        "cwd":     "",
                        "open_files":  [],
                        "connections": [],
                    }
                    try:
                        d["cwd"] = p.cwd()
                    except Exception:
                        pass
                    try:
                        d["open_files"] = [f.path for f in p.open_files()[:20]]
                    except Exception:
                        pass
                    try:
                        d["connections"] = [
                            {
                                "status": c.status,
                                "local":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                            }
                            for c in p.net_connections()[:20]
                        ]
                    except Exception:
                        pass
                    details.append(d)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        result["processes"] = details
    else:
        try:
            cmd = ["ps", "-p", str(pid), "-f"] if pid else ["pgrep", "-la", name]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            result["ps_output"] = out.stdout[:2000]
        except Exception as e:
            result["error"] = str(e)
    return result


def _inv_read_log(path: str, lines: int = 100) -> dict:
    if not path:
        return {"error": "No path specified"}
    safe_prefixes = ("/var/log/", "/tmp/", "/opt/", "/home/", "/srv/", "/app/", "/data/", "/run/log/")
    if not any(path.startswith(p) for p in safe_prefixes):
        return {"error": f"Path not in allowed locations: {path}"}
    try:
        out = subprocess.run(["tail", "-n", str(min(lines, 500)), path],
                             capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return {"error": out.stderr[:500] or f"Cannot read {path}"}
        content = out.stdout[:5000]
        return {"path": path, "content": content, "truncated": len(out.stdout) > 5000}
    except Exception as e:
        return {"error": str(e)}


def _inv_search_logs(path: str, pattern: str, lines: int = 50) -> dict:
    if not path or not pattern:
        return {"error": "path and pattern required"}
    safe_prefixes = ("/var/log/", "/tmp/", "/opt/", "/home/", "/srv/", "/app/", "/data/", "/run/log/")
    if not any(path.startswith(p) for p in safe_prefixes):
        return {"error": f"Path not in allowed locations: {path}"}
    try:
        out = subprocess.run(["grep", "-i", "-n", "--", pattern, path],
                             capture_output=True, text=True, timeout=5)
        matches = out.stdout.splitlines()
        return {
            "path":          path,
            "pattern":       pattern,
            "matches":       matches[-lines:],
            "total_matches": len(matches),
        }
    except Exception as e:
        return {"error": str(e)}


def _inv_journal_unit(unit: str, lines: int = 100) -> dict:
    if not unit:
        return {"error": "unit name required"}
    try:
        out = subprocess.run(
            ["journalctl", "-u", unit, "-n", str(min(lines, 500)), "--no-pager", "--output=short-iso"],
            capture_output=True, text=True, timeout=5,
        )
        return {"unit": unit, "logs": out.stdout[:5000] or "(no logs)", "truncated": len(out.stdout) > 5000}
    except Exception as e:
        return {"error": str(e)}


def _inv_disk_usage(path: str = "/") -> dict:
    result = {}

    # 1. df -h — instant
    try:
        out = subprocess.run(["df", "-h"], capture_output=True, text=True, timeout=5)
        result["df"] = out.stdout
    except Exception as e:
        result["df_error"] = str(e)

    # 2. Size of key top-level dirs individually — much faster than du --max-depth
    key_dirs = [d for d in ["/var", "/tmp", "/home", "/opt", "/usr", "/root",
                             "/srv", "/data", "/run", "/snap", "/mnt"]
                if os.path.isdir(d)]
    if key_dirs:
        try:
            out2 = subprocess.run(["du", "-sh"] + key_dirs,
                                  capture_output=True, text=True, timeout=8)
            if out2.stdout.strip():
                result["dir_sizes"] = out2.stdout.strip().splitlines()
        except subprocess.TimeoutExpired:
            result["dir_sizes_note"] = "du timed out on key directories"
        except Exception as e:
            result["dir_sizes_error"] = str(e)

    # 3. Find large files in most likely locations only (fast)
    search_dirs = [d for d in ["/tmp", "/var", "/home", "/opt", "/root", "/data", "/srv"]
                   if os.path.isdir(d)]
    for d in search_dirs:
        try:
            out3 = subprocess.run(
                ["find", d, "-maxdepth", "3", "-type", "f", "-size", "+100M"],
                capture_output=True, text=True, timeout=5,
            )
            files = [f for f in out3.stdout.splitlines() if f][:10]
            if files:
                out4 = subprocess.run(["ls", "-lh"] + files,
                                      capture_output=True, text=True, timeout=3)
                result.setdefault("large_files", "")
                result["large_files"] += out4.stdout
        except Exception:
            pass

    return result


def _inv_network_connections(process: str = "") -> dict:
    result = {}
    if process and _PSUTIL_AVAILABLE:
        conns = []
        for p in psutil.process_iter(["name", "pid"]):
            if process.lower() in p.name().lower():
                try:
                    for c in p.net_connections():
                        conns.append({
                            "pid":     p.pid,
                            "process": p.name(),
                            "status":  c.status,
                            "local":   f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                            "remote":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        result["connections"] = conns[:50]
    else:
        try:
            out = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=5)
            result["ss_output"] = out.stdout[:3000]
        except Exception as e:
            result["error"] = str(e)
    try:
        out2 = subprocess.run(["ss", "-s"], capture_output=True, text=True, timeout=5)
        result["connection_summary"] = out2.stdout
    except Exception:
        pass
    return result


def _inv_system_overview() -> dict:
    result = {}
    if _PSUTIL_AVAILABLE:
        try:
            cpu_per_core = psutil.cpu_percent(interval=1, percpu=True)
            result["cpu_total_pct"]  = round(sum(cpu_per_core) / len(cpu_per_core), 1)
            result["cpu_per_core"]   = cpu_per_core
            result["cpu_count"]      = psutil.cpu_count()
            mem  = psutil.virtual_memory()
            swap = psutil.swap_memory()
            result["memory"] = {
                "total_mb":     mem.total // (1024 * 1024),
                "used_mb":      mem.used // (1024 * 1024),
                "available_mb": mem.available // (1024 * 1024),
                "percent":      mem.percent,
                "cached_mb":    getattr(mem, "cached", 0) // (1024 * 1024),
            }
            result["swap"] = {
                "total_mb": swap.total // (1024 * 1024),
                "used_mb":  swap.used // (1024 * 1024),
                "percent":  swap.percent,
            }
            try:
                io = psutil.disk_io_counters()
                result["disk_io"] = {
                    "read_mb":    io.read_bytes  // (1024 * 1024),
                    "write_mb":   io.write_bytes // (1024 * 1024),
                    "read_ops":   io.read_count,
                    "write_ops":  io.write_count,
                }
            except Exception:
                pass
            result["load_avg"]     = list(os.getloadavg())
            result["uptime_hours"] = round((time.time() - psutil.boot_time()) / 3600, 1)
            # Recent OOM events
            try:
                out = subprocess.run(
                    ["journalctl", "-k", "--no-pager", "-n", "20", "--grep", "oom"],
                    capture_output=True, text=True, timeout=5,
                )
                if out.stdout.strip():
                    result["recent_oom"] = out.stdout[:1000]
            except Exception:
                pass
        except Exception as e:
            result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Context collectors — run inside the cluster, talk to local APIs
# ---------------------------------------------------------------------------

def collect_pod_status(core_v1: k8s_client.CoreV1Api, service: str, namespaces: list) -> list:
    pods = []
    for ns in namespaces:
        try:
            pod_list = core_v1.list_namespaced_pod(
                ns, label_selector=f"app={service}"
            )
            for pod in pod_list.items:
                restarts = sum(
                    cs.restart_count
                    for cs in (pod.status.container_statuses or [])
                )
                pods.append({
                    "name": pod.metadata.name,
                    "namespace": ns,
                    "phase": pod.status.phase,
                    "restarts": restarts,
                })
        except ApiException as e:
            logger.warning(f"Failed to list pods in {ns}: {e.status}")
    return pods


def collect_recent_events(core_v1: k8s_client.CoreV1Api, service: str, namespaces: list) -> list:
    events = []
    for ns in namespaces:
        try:
            event_list = core_v1.list_namespaced_event(
                ns,
                field_selector=f"involvedObject.name={service}"
            )
            for event in event_list.items[-20:]:  # last 20 events
                events.append({
                    "type":    event.type,
                    "reason":  event.reason,
                    "message": event.message,
                    "count":   event.count,
                    "time":    event.last_timestamp.isoformat() if event.last_timestamp else None,
                })
        except ApiException as e:
            logger.warning(f"Failed to list events in {ns}: {e.status}")
    return events


def collect_pod_logs(core_v1: k8s_client.CoreV1Api, pod_name: str, namespace: str) -> str:
    try:
        logs = core_v1.read_namespaced_pod_log(
            pod_name, namespace,
            tail_lines=50,
            timestamps=True,
        )
        return logs
    except ApiException as e:
        return f"Failed to collect logs: {e.status} {e.reason}"


def collect_recent_deployments(apps_v1: k8s_client.AppsV1Api, service: str, namespaces: list) -> list:
    deployments = []
    for ns in namespaces:
        try:
            dep_list = apps_v1.list_namespaced_deployment(ns)
            for dep in dep_list.items:
                if service.lower() not in dep.metadata.name.lower():
                    continue
                # Check rollout history via annotations
                change_cause = (dep.metadata.annotations or {}).get(
                    "kubernetes.io/change-cause", "no change-cause recorded"
                )
                deployments.append({
                    "name":   dep.metadata.name,
                    "time":   dep.metadata.creation_timestamp.isoformat() if dep.metadata.creation_timestamp else None,
                    "detail": change_cause,
                    "replicas_ready": dep.status.ready_replicas,
                    "replicas_desired": dep.spec.replicas,
                })
        except ApiException as e:
            logger.warning(f"Failed to list deployments in {ns}: {e.status}")
    return deployments


def handle_collect_context(
    core_v1: k8s_client.CoreV1Api,
    apps_v1: k8s_client.AppsV1Api,
    service: str,
    namespaces: list,
) -> dict:
    """Collect all context for a service. Called when server requests it."""
    logger.info(f"Collecting context for service: {service}")

    pod_status = collect_pod_status(core_v1, service, namespaces)

    # Get logs from first crashing pod, or first running pod
    log_pod = next(
        (p for p in pod_status if p["phase"] == "CrashLoopBackOff"),
        pod_status[0] if pod_status else None,
    )

    logs = ""
    if log_pod:
        logs = collect_pod_logs(core_v1, log_pod["name"], log_pod["namespace"])

    return {
        "pod_status":          pod_status,
        "recent_events":       collect_recent_events(core_v1, service, namespaces),
        "recent_deployments":  collect_recent_deployments(apps_v1, service, namespaces),
        "pod_logs":            logs,
        "log_pod":             log_pod["name"] if log_pod else None,
        "collected_at":        datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# eBPF context collector (bpftrace)
# ---------------------------------------------------------------------------

# Each script runs for DURATION seconds then exits.
# $SVC is replaced with the service name (first 15 chars — comm limit).
_BPFTRACE_SCRIPTS = {
    "network": """
tracepoint:syscalls:sys_enter_connect { @tcp_start[tid] = nsecs; }
tracepoint:syscalls:sys_exit_connect {
    if (@tcp_start[tid]) {
        $lat = (nsecs - @tcp_start[tid]) / 1000000;
        @tcp_conns[comm, retval] = count();
        if ($lat > 50) { @slow_connects[comm] = hist($lat); }
        delete(@tcp_start[tid]);
    }
}
tracepoint:syscalls:sys_exit_sendto   /retval < 0/ { @send_errors[comm, retval]  = count(); }
tracepoint:syscalls:sys_exit_recvfrom /retval < 0/ { @recv_errors[comm, retval]  = count(); }
interval:s:DURATION {
    print(@tcp_conns); print(@slow_connects);
    print(@send_errors); print(@recv_errors);
    exit();
}
""",

    "io": """
tracepoint:syscalls:sys_enter_read  { @rs[tid] = nsecs; }
tracepoint:syscalls:sys_exit_read   /@rs[tid] && retval > 0/ {
    $lat = (nsecs - @rs[tid]) / 1000000;
    if ($lat > 100) { @slow_read[comm]  = hist($lat); }
    delete(@rs[tid]);
}
tracepoint:syscalls:sys_enter_write { @ws[tid] = nsecs; }
tracepoint:syscalls:sys_exit_write  /@ws[tid] && retval > 0/ {
    $lat = (nsecs - @ws[tid]) / 1000000;
    if ($lat > 100) { @slow_write[comm] = hist($lat); }
    delete(@ws[tid]);
}
tracepoint:syscalls:sys_exit_openat /retval < 0/ {
    @open_errors[comm, retval] = count();
}
interval:s:DURATION {
    print(@slow_read); print(@slow_write); print(@open_errors);
    exit();
}
""",

    "process": """
tracepoint:sched:sched_process_exit {
    if (args->exit_code != 0) {
        printf("EXIT pid=%d comm=%s code=%d\\n",
               pid, comm, args->exit_code >> 8);
    }
}
tracepoint:syscalls:sys_exit_execve /retval < 0/ {
    printf("EXECVE_FAIL comm=%s ret=%d\\n", comm, retval);
}
interval:s:DURATION { exit(); }
""",
}


def handle_collect_ebpf_context(service: str, duration: int = 5) -> dict:
    """
    Run bpftrace scripts in parallel for `duration` seconds.
    Returns a dict with network / io / process sections.
    """
    logger.info(f"Collecting eBPF context for '{service}' ({duration}s window)")
    results = {}

    import concurrent.futures

    def run_script(name: str, script: str) -> tuple:
        prog = script.strip().replace("DURATION", str(duration))
        try:
            r = subprocess.run(
                ["bpftrace", "-e", prog],
                capture_output=True, text=True,
                timeout=duration + 5,
            )
            output = (r.stdout + r.stderr).strip()
            return name, output if output else "(no activity)"
        except subprocess.TimeoutExpired:
            return name, f"Timed out after {duration + 5}s"
        except Exception as e:
            return name, f"Error: {e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(run_script, name, script): name
            for name, script in _BPFTRACE_SCRIPTS.items()
        }
        for fut in concurrent.futures.as_completed(futures):
            name, output = fut.result()
            results[name] = output

    results["duration_secs"] = duration
    results["collected_at"]  = datetime.now(timezone.utc).isoformat()
    return results


# ---------------------------------------------------------------------------
# Health check HTTP server (for k8s liveness probe)
# ---------------------------------------------------------------------------

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # suppress access logs


def start_health_server():
    server = HTTPServer(("0.0.0.0", 8080), HealthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Health server running on :8080")


# ---------------------------------------------------------------------------
# Main websocket loop
# ---------------------------------------------------------------------------

async def run_agent():
    core_v1, apps_v1 = setup_k8s()

    # Count pods across watched namespaces (k8s mode only)
    total_pods = 0
    if core_v1:
        for ns in NAMESPACES:
            try:
                pods = core_v1.list_namespaced_pod(ns)
                total_pods += len(pods.items)
            except Exception:
                pass

    capabilities = detect_capabilities()
    logger.info(f"Agent capabilities: {capabilities}")

    import socket
    hello_msg = {
        "type":         "hello",
        "api_key":      API_KEY,
        "customer_id":  CUSTOMER_ID,
        "hostname":     os.environ.get("RCABOT_HOSTNAME") or socket.gethostname(),
        "labels":       LABELS,
        "version":      VERSION,
        "namespaces":   NAMESPACES,
        "pod_count":    total_pods,
        "capabilities": capabilities,
    }

    retry_delay = 5  # seconds, grows on repeated failures

    while True:
        try:
            logger.info(f"Connecting to RCABot server: {SERVER_URL}")

            async with websockets.connect(SERVER_URL, ping_interval=20) as ws:
                # Send hello / auth
                await ws.send(json.dumps(hello_msg))
                response = json.loads(await ws.recv())

                if response.get("type") == "error":
                    logger.error(f"Auth failed: {response.get('message')}")
                    raise SystemExit(1)  # Don't retry auth failures

                logger.info(f"Connected! Agent ID: {response.get('agent_id')}")
                retry_delay = 5  # reset on successful connection

                # Main message loop
                last_heartbeat = time.time()

                while True:
                    # Send heartbeat every 30s
                    if time.time() - last_heartbeat > HEARTBEAT_INTERVAL:
                        await ws.send(json.dumps({
                            "type": "heartbeat",
                            "pod_count": total_pods,
                        }))
                        last_heartbeat = time.time()

                    # Handle incoming requests from server
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        msg = json.loads(raw)

                        if msg.get("type") == "heartbeat_ack":
                            pass  # all good

                        elif msg.get("type") == "collect_context":
                            service    = msg.get("service", "unknown")
                            namespaces = msg.get("namespaces", NAMESPACES)
                            corr_id    = msg.get("correlation_id", "")
                            try:
                                if core_v1:
                                    context = handle_collect_context(core_v1, apps_v1, service, namespaces)
                                else:
                                    # No k8s — fall back to system collection
                                    context = handle_collect_system_context(service)
                                await ws.send(json.dumps({
                                    "type": "context_response", "status": "ok", "data": context,
                                    "correlation_id": corr_id,
                                }))
                            except Exception as e:
                                logger.exception(f"Context collection failed: {e}")
                                await ws.send(json.dumps({
                                    "type": "context_response", "status": "error", "error": str(e),
                                    "correlation_id": corr_id,
                                }))

                        elif msg.get("type") == "collect_cloud_context":
                            cloud   = msg.get("cloud", "")
                            service = msg.get("service", "unknown")
                            fired   = msg.get("fired_at", "")
                            corr_id = msg.get("correlation_id", "")

                            try:
                                if cloud == "aws":
                                    data = collect_aws_context(service, fired)
                                elif cloud == "azure":
                                    data = collect_azure_context(service, fired)
                                elif cloud == "gcp":
                                    data = collect_gcp_context(service, fired)
                                else:
                                    data = {"error": f"Unknown cloud: {cloud}"}

                                await ws.send(json.dumps({
                                    "type":           "cloud_context_response",
                                    "status":         "ok",
                                    "data":           data,
                                    "correlation_id": corr_id,
                                }))
                            except Exception as e:
                                logger.exception(f"Cloud context collection failed: {e}")
                                await ws.send(json.dumps({
                                    "type":           "cloud_context_response",
                                    "status":         "error",
                                    "error":          str(e),
                                    "correlation_id": corr_id,
                                }))

                        elif msg.get("type") == "collect_ebpf_context":
                            svc      = msg.get("service", "unknown")
                            duration = int(msg.get("duration", 5))
                            corr_id  = msg.get("correlation_id", "")
                            try:
                                data = handle_collect_ebpf_context(svc, duration)
                                await ws.send(json.dumps({
                                    "type":           "ebpf_context_response",
                                    "status":         "ok",
                                    "data":           data,
                                    "correlation_id": corr_id,
                                }))
                            except Exception as e:
                                logger.exception(f"eBPF collection failed: {e}")
                                await ws.send(json.dumps({
                                    "type":           "ebpf_context_response",
                                    "status":         "error",
                                    "error":          str(e),
                                    "correlation_id": corr_id,
                                }))

                        elif msg.get("type") == "collect_infra_context":
                            cloud   = msg.get("cloud", "")
                            fired   = msg.get("fired_at", "")
                            corr_id = msg.get("correlation_id", "")
                            try:
                                if cloud == "aws":
                                    data = collect_aws_infra_context(fired)
                                elif cloud == "azure":
                                    data = collect_azure_infra_context(fired)
                                elif cloud == "gcp":
                                    data = collect_gcp_infra_context(fired)
                                else:
                                    data = {"error": f"Unknown cloud: {cloud}"}
                                await ws.send(json.dumps({
                                    "type":           "infra_context_response",
                                    "status":         "ok",
                                    "data":           data,
                                    "correlation_id": corr_id,
                                }))
                            except Exception as e:
                                logger.exception(f"Infra context collection failed: {e}")
                                await ws.send(json.dumps({
                                    "type":           "infra_context_response",
                                    "status":         "error",
                                    "error":          str(e),
                                    "correlation_id": corr_id,
                                }))

                        elif msg.get("type") == "investigate":
                            command = msg.get("command", "")
                            params  = msg.get("params", {})
                            corr_id = msg.get("correlation_id", "")
                            try:
                                # Run in thread so blocking subprocesses don't stall the event loop
                                loop = asyncio.get_running_loop()
                                import concurrent.futures as _cf
                                with _cf.ThreadPoolExecutor(max_workers=1) as _ex:
                                    data = await loop.run_in_executor(
                                        _ex, handle_investigate_command, command, params
                                    )
                                await ws.send(json.dumps({
                                    "type":           "investigate_response",
                                    "status":         "ok",
                                    "data":           data,
                                    "correlation_id": corr_id,
                                }))
                            except Exception as e:
                                logger.exception(f"Investigation command '{command}' failed: {e}")
                                await ws.send(json.dumps({
                                    "type":           "investigate_response",
                                    "status":         "error",
                                    "error":          str(e),
                                    "correlation_id": corr_id,
                                }))

                        else:
                            logger.warning(f"Unknown message type: {msg.get('type')}")

                    except asyncio.TimeoutError:
                        pass  # no message — loop back to heartbeat check

        except websockets.exceptions.ConnectionClosed as e:
            logger.warning(f"Connection closed: {e}. Reconnecting in {retry_delay}s...")
        except OSError as e:
            logger.warning(f"Connection failed: {e}. Retrying in {retry_delay}s...")
        except Exception as e:
            logger.exception(f"Unexpected error: {e}. Retrying in {retry_delay}s...")

        await asyncio.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, 60)  # exponential backoff, max 60s


if __name__ == "__main__":
    start_health_server()
    logger.info(f"RCABot Forwarder Agent v{VERSION} starting")
    logger.info(f"Watching namespaces: {NAMESPACES}")
    asyncio.run(run_agent())
