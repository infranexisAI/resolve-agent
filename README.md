# Infranexis Resolve Agent

Open-source agent for [Infranexis Resolve](https://app.infranexis.com) — AI-powered incident root cause analysis.

The agent runs on your infrastructure (Linux host or Kubernetes cluster), makes a single outbound WebSocket connection to Resolve, and collects read-only context when an incident occurs: pod logs, Kubernetes events, system metrics, cloud alarms, and more. **Nothing is stored on your servers. No inbound ports required.**

## Install

### Linux / VM (one-liner)

Get your install command from the Resolve dashboard → **Agents** tab.

```bash
curl -fsSL https://app.infranexis.com/dashboard/install/<your-id>.sh | sudo bash
```

Installs as a systemd service under `/opt/infranexis/resolve-agent`.

### Kubernetes

```bash
kubectl apply -f https://app.infranexis.com/dashboard/install/<your-id>.yaml
```

## What the agent collects

| Source | Data |
|--------|------|
| Kubernetes | Pod logs, events, deployment status, node info |
| System | CPU, memory, disk, load average, systemd service status, journal logs |
| AWS | CloudWatch alarms, metrics, CloudTrail events, Log Insights |
| Azure | Monitor metrics, Log Analytics logs, Activity Log |
| GCP | Cloud Logging, Cloud Monitoring metrics |

All collection is **read-only**. Cloud credentials are never stored — the agent uses your existing instance role / workload identity.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RCABOT_SERVER_URL` | Yes | `wss://app.infranexis.com/agent/ws` |
| `RCABOT_API_KEY` | Yes | Your API key from the Resolve dashboard |
| `RCABOT_CUSTOMER_ID` | Yes | Your customer ID |
| `RCABOT_NAMESPACES` | No | Kubernetes namespaces to watch (default: `default`) |
| `RCABOT_HOSTNAME` | No | Override reported hostname |
| `RCABOT_LABELS` | No | Extra labels e.g. `env=prod,role=webserver` |
| `RCABOT_AWS_REGION` | No | AWS region (auto-detected on EC2/EKS) |
| `RCABOT_AWS_LOG_GROUPS` | No | CloudWatch log groups to query |
| `RCABOT_AZURE_WORKSPACE_ID` | No | Log Analytics workspace ID |
| `RCABOT_GCP_PROJECT_ID` | No | GCP project ID (auto-detected on GCE/GKE) |

## Run with Docker

```bash
docker run -d \
  -e RCABOT_SERVER_URL=wss://app.infranexis.com/agent/ws \
  -e RCABOT_API_KEY=rbk_live_xxx \
  -e RCABOT_CUSTOMER_ID=your-id \
  ghcr.io/infranexisai/resolve-agent:latest
```

## Build from source

```bash
git clone https://github.com/infranexisAI/resolve-agent
cd resolve-agent
pip install -r requirements.txt
python agent.py
```

## License

MIT — see [LICENSE](LICENSE)
