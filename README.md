# Security Monitor Sub-Agent

**Read-only security monitoring agent for Linux servers**

A safe, read-only sub-agent that monitors Linux server security without making any changes to the system. Designed to be integrated with any agent orchestration system.

## Features

- ✅ **Package Updates**: Check available updates (apt/dnf)
- ✅ **SSH Configuration Audit**: PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries
- ✅ **Listening Ports**: Scan network ports exposed to the network
- ✅ **Firewall Status**: Check ufw, nftables, or iptables
- ✅ **Failed SSH Logins**: Analyze auth.log or journalctl for failed attempts (last 24h)
- ✅ **UID 0 Users**: Find accounts with root privileges
- ✅ **Sudo/Wheel Groups**: List members of admin groups
- ✅ **Failed Systemd Units**: Detect failed services
- ✅ **Fail2ban Status**: Check if fail2ban is running
- ✅ **Disk Usage**: Monitor disk space (alerts at 80% and 90%)
- ✅ **Docker Containers**: List running containers (if Docker is installed)

## Safety Guarantees

This agent is **strictly read-only**:

- ❌ No configuration changes
- ❌ No package installations
- ❌ No service restarts
- ❌ No IP blocking
- ❌ No secret exfiltration (no /etc/shadow, private keys, passwords)
- ✅ Report-only mode

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/security-monitor.git
cd security-monitor

# Copy to system location
sudo mkdir -p /opt/security-monitor
sudo cp security_monitor.py /opt/security-monitor/
sudo chmod +x /opt/security-monitor/security_monitor.py
```

### Run Manual Check

```bash
# Markdown output (human-readable)
sudo python3 /opt/security-monitor/security_monitor.py --format markdown

# JSON output (for agents/APIs)
sudo python3 /opt/security-monitor/security_monitor.py --format json

# Exit with code 2 if critical findings
sudo python3 /opt/security-monitor/security_monitor.py --format json --fail-on critical
```

### Scheduled Execution (systemd timer)

```bash
# Install systemd service and timer
sudo cp systemd/security-monitor.service /etc/systemd/system/
sudo cp systemd/security-monitor.timer /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now security-monitor.timer

# Check status
systemctl list-timers | grep security-monitor
journalctl -u security-monitor.service
```

### Scheduled Execution (cron)

```bash
# Edit crontab
sudo crontab -e

# Add this line (runs every 30 minutes)
*/30 * * * * /usr/bin/python3 /opt/security-monitor/security_monitor.py --format markdown >> /var/log/security-monitor.log 2>&1
```

## Output Formats

### Markdown (Human-Readable)

```markdown
# Отчет саб-агента безопасности сервера

- generated_at: 2025-01-15T10:30:00+00:00
- agent: security-monitor
- mode: read-only

## HIGH (1)

### Firewall: UFW установлен, но выключен

Status: inactive
...

Рекомендация: Настройте правила и выполните sudo ufw enable. Сначала разрешите SSH, чтобы не потерять доступ.

## MEDIUM (2)
...
```

### JSON (Machine-Readable)

```json
{
  "meta": {
    "generated_at": "2025-01-15T10:30:00+00:00",
    "agent": "security-monitor",
    "mode": "read-only",
    "uname": "Linux server 5.15.0...",
    "os": "Ubuntu 22.04.3 LTS"
  },
  "findings": [
    {
      "severity": "high",
      "title": "Firewall: UFW установлен, но выключен",
      "detail": "Status: inactive",
      "remediation": "Настройте правила и выполните sudo ufw enable..."
    }
  ]
}
```

## Severity Levels

| Level | Description |
|-------|-------------|
| **critical** | Immediate action required (e.g., UID 0 users besides root, empty passwords allowed) |
| **high** | Serious risk (e.g., firewall disabled, root login enabled) |
| **medium** | Notable risk (e.g., password auth enabled, many failed logins) |
| **low** | Minor issues (e.g., X11 forwarding enabled, fail2ban not installed) |
| **info** | Informational findings |

## Integration with Agent Orchestrators

### Hermes Framework

Import the sub-agent using the Hermes configuration file:

```bash
# Copy the Hermes agent card to your Hermes configuration directory
cp hermes-agent-card.json /etc/hermes/agents/security-monitor.json

# Or load via Hermes API
curl -X POST http://hermes-host:8080/api/v1/agents/import \
  -H "Content-Type: application/json" \
  -d @hermes-agent-card.json
```

**Hermes Configuration Features:**
- `hermes_config.agent_type`: Defines as sub-agent with sandboxed execution
- `hermes_config.permissions`: Fine-grained filesystem, network, and process permissions
- `hermes_config.tools`: Three tool variants (JSON, Markdown, Strict mode)
- `hermes_config.constraints`: Enforces read-only, no-modification policies
- `hermes_config.alerting`: Automatic alerts for critical/high findings
- `hermes_config.response_schema`: Structured JSON output validation

### OpenClaw Framework

Import the sub-agent using the OpenClaw configuration file:

```bash
# Copy the OpenClaw agent card to your OpenClaw agents directory
cp openclaw-agent-card.json /etc/openclaw/agents/security-monitor.json

# Or register via OpenClaw CLI
openclaw agent register --config openclaw-agent-card.json
```

**OpenClaw Configuration Features:**
- `openclaw_config.interface.tools`: Three audit tools with input/output schemas
- `openclaw_config.interface.actions`: Pre-defined actions (full audit, critical check, report generation)
- `openclaw_config.permissions`: Detailed filesystem paths, denied paths, environment masking
- `openclaw_config.monitoring.alerting`: P0/P1/P2 priority alert rules
- `openclaw_config.integration`: API endpoints and webhook support
- `openclaw_config.behavior`: System prompt and error handling policies

### Generic Agent Card (Backward Compatible)

For other frameworks or custom integrations, use the simplified agent card:

```json
{
  "name": "security-monitor",
  "description": "Read-only sub-agent for Linux server security monitoring",
  "system_prompt": "Ты — саб-агент безопасности сервера. Твоя задача — только мониторинг, диагностика и рекомендации...",
  "tools": [
    {
      "name": "security_audit",
      "description": "Runs read-only Linux security checks and returns JSON or Markdown report",
      "command": "python3 /opt/security-monitor/security_monitor.py --format json",
      "timeout_sec": 120,
      "read_only": true
    }
  ],
  "constraints": [
    "no_modification",
    "no_package_install",
    "no_service_restart",
    "no_ip_blocking",
    "no_secret_exfiltration",
    "report_only"
  ]
}
```

See `examples/agent-card.json` for the complete generic configuration.

### Example Agent Prompt

```text
Запусти security_audit и проанализируй безопасность сервера.
Если есть critical или high находки, выведи их первыми.
Для каждой находки укажи риск и рекомендацию.
Ничего не меняй на сервере.
```

## Requirements

- Python 3.7+
- Linux server (Debian/Ubuntu, RHEL/CentOS/Fedora supported)
- Root or sudo access for some checks (journalctl, iptables, fail2ban)

### Optional Dependencies

- `ufw` or `nftables` or `iptables` — firewall status
- `fail2ban` — intrusion prevention status
- `docker` — container monitoring
- `sshd` — SSH configuration audit

## Project Structure

```
security-monitor/
├── security_monitor.py       # Main script
├── README.md                 # This file
├── LICENSE                   # MIT License
├── .gitignore
├── hermes-agent-card.json    # Hermes framework configuration
├── openclaw-agent-card.json  # OpenClaw framework configuration
├── systemd/
│   ├── security-monitor.service
│   └── security-monitor.timer
└── examples/
    ├── agent-card.json           # Generic agent card
    ├── hermes-agent-card.json    # Hermes configuration (copy)
    └── openclaw-agent-card.json  # OpenClaw configuration (copy)
```

## CLI Options

```bash
python3 security_monitor.py --help

usage: security_monitor.py [-h] [--format {json,markdown}] [--fail-on {none,high,critical}]

options:
  -h, --help            show this help message and exit
  --format {json,markdown}
                        Output format (default: markdown)
  --fail-on {none,high,critical}
                        Exit code 2 if findings reach selected severity (default: none)
```

## Extending the Agent

You can extend this agent to add:

- `sshd -T` effective configuration audit
- `sudoers` file audit
- Cron jobs security check
- SUID/SGID file scan
- Docker security audit (privileged containers, exposed ports)
- External port scanner integration
- SIEM integration
- Telegram/Slack/PagerDuty alerts
- Automatic incident ticket creation
- Remediation agent with human approval workflow

## License

MIT License — see [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## Support

For issues, feature requests, or questions, please open an issue on GitHub.

---

**Built for secure, automated Linux server monitoring.**
