# Causa Agent

> Open-source infrastructure agent for [Infranexis Causa](https://causa.infranexis.com) — AI-powered incident root cause analysis for Kubernetes and Linux infrastructure.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![Platform](https://img.shields.io/badge/platform-Kubernetes%20%7C%20Linux%20%7C%20bare--metal-lightgrey)](#what-the-agent-collects)

---

## What is Causa?

Causa is an AI-powered incident root cause analysis (RCA) platform. When an alert fires, Causa automatically investigates your infrastructure — pod logs, system journals, process state, Kubernetes events, eBPF kernel traces — and delivers a precise root cause in under 90 seconds.

**This repository contains the open-source agent** that runs on your infrastructure. It makes a single outbound WebSocket connection to Causa and collects read-only context when an incident occurs. Nothing is stored on your servers. No inbound ports required.

---

## How it works

```
Alert fires
    │
    ▼
Causa backend receives alert
    │
    ▼
Causa sends investigation task to agent via WebSocket
    │
    ▼
Agent collects context (logs, metrics, events, traces)
    │
    ▼
Agent sends context back → LLM generates RCA
    │
    ▼
RCA delivered to Slack / email / PagerDuty / webhook
```

---

## Quick start

Get your personalised install command from the [Causa dashboard](https://causa.infranexis.com) → **Settings → Agents**.

### Linux / VM

```bash
curl -fsSL https://causa.infranexis.com/dashboard/install/<your-customer-id>.sh | sudo bash
```

Installs as a `systemd` service at `/opt/infranexis/causa-agent/`.

### Kubernetes

```bash
kubectl apply -f https://causa.infranexis.com/dashboard/install/<your-customer-id>.yaml
```

Deploys as a `Deployment` in the `causa-agent` namespace with read-only cluster access.

### Docker

```bash
docker run -d \
  -e CAUSA_SERVER_URL=wss://causa.infranexis.com/agent/ws \
  -e CAUSA_API_KEY=rbk_live_xxx \
  -e CAUSA_CUSTOMER_ID=your-customer-id \
  ghcr.io/infranexis/causa-agent:latest
```

---

## Run from source

```bash
git clone https://github.com/infranexisAI/causa-agent
cd causa-agent
pip install -r requirements.txt
export CAUSA_SERVER_URL=wss://causa.infranexis.com/agent/ws
export CAUSA_API_KEY=rbk_live_xxx
export CAUSA_CUSTOMER_ID=your-customer-id
python agent.py
```

---

## What the agent collects

All collection is **read-only**. The agent never writes to your infrastructure.

| Source | Data collected |
|--------|---------------|
| **Kubernetes** | Pod logs, events, deployment status, replica sets, node info, resource limits |
| **Linux system** | CPU, memory, disk, load average, network connections |
| **systemd** | Service status, journal logs for failed/degraded services |
| **AWS** | CloudWatch alarms, metrics, CloudTrail events, Log Insights queries |
| **Azure** | Monitor metrics, Log Analytics logs, Activity Log |
| **GCP** | Cloud Logging, Cloud Monitoring metrics |

Cloud credentials are **never stored** — the agent uses your existing instance role (IRSA / Workload Identity / EC2 instance profile).

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CAUSA_SERVER_URL` | Yes | — | `wss://causa.infranexis.com/agent/ws` |
| `CAUSA_API_KEY` | Yes | — | API key from the Causa dashboard |
| `CAUSA_CUSTOMER_ID` | Yes | — | Customer ID from the Causa dashboard |
| `CAUSA_NAMESPACES` | No | `default` | Kubernetes namespaces to watch (comma-separated) |
| `CAUSA_HOSTNAME` | No | auto-detected | Override reported hostname |
| `CAUSA_LABELS` | No | — | Extra labels e.g. `env=prod,role=webserver` |
| `CAUSA_AWS_REGION` | No | auto-detected | AWS region |
| `CAUSA_AWS_LOG_GROUPS` | No | — | CloudWatch log groups to query (comma-separated) |
| `CAUSA_AZURE_WORKSPACE_ID` | No | — | Log Analytics workspace ID |
| `CAUSA_AZURE_RESOURCE_ID` | No | — | Azure resource ID for metrics |
| `CAUSA_GCP_PROJECT_ID` | No | auto-detected | GCP project ID |

> **Note:** The legacy `RCABOT_` prefix is still accepted for all variables — existing deployments continue to work without any changes.

---

## Security

- **Outbound only** — the agent connects out to Causa over WSS (port 443). No inbound ports are opened.
- **Read-only** — the agent only reads logs, metrics, and events. It never modifies your infrastructure.
- **Minimal permissions** — the Kubernetes RBAC role grants `get`, `list`, and `watch` on pods, events, nodes, and deployments. No write access.
- **No credential storage** — cloud credentials are sourced from the instance role at runtime.
- **Auditable** — this repository is the complete source. No obfuscated code.

---

## Optional cloud dependencies

The core agent works without any cloud SDKs. Install only what you need:

```bash
# AWS CloudWatch / CloudTrail
pip install boto3

# Azure Monitor / Log Analytics
pip install azure-identity azure-monitor-query azure-mgmt-monitor

# GCP Cloud Logging / Monitoring
pip install google-cloud-logging google-cloud-monitoring
```

---

## Self-hosting

The agent connects to `causa.infranexis.com` by default. If you are running a self-hosted Causa instance, set:

```bash
CAUSA_SERVER_URL=wss://your-causa-instance.com/agent/ws
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large PR so we can discuss the approach.

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes
4. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Infranexis](https://infranexis.com).
