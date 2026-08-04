#!/usr/bin/env python3
"""
Linux Security Monitor Sub-Agent (Русская версия)
Режим: Только критические и опасные события
Отчетность: Сводка один раз в день с указанием сервера

Этот агент сканирует систему на предмет угроз безопасности и генерирует
отчет только при обнаружении проблем уровня HIGH или CRITICAL.
Включает имя сервера (hostname) для идентификации в общих чатах.
Поддерживает режим daily-summary для интеграции с Hermes/OpenClaw.
"""

import subprocess
import json
import os
import sys
import socket
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field

# Константы
STATE_DIR = Path("/var/lib/security-monitor")
PORT_STATE_FILE = STATE_DIR / "port_state.json"
FINDINGS_CACHE_FILE = STATE_DIR / "findings_cache.json"
MIN_SEVERITY_LEVEL = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    check: str
    severity: str
    summary: str
    details: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    server_hostname: str = ""
    server_ip: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def hash(self) -> str:
        """Создает хеш для дедупликации"""
        content = f"{self.check}:{self.severity}:{self.summary}:{self.details}"
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class SecurityReport:
    timestamp: str
    mode: str
    schedule: str
    server_hostname: str
    server_ip: List[str]
    total_findings: int
    critical_count: int
    high_count: int
    status: str
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "mode": self.mode,
            "schedule": self.schedule,
            "server_hostname": self.server_hostname,
            "server_ip": self.server_ip,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
        }


def run_command(cmd: List[str], timeout: int = 30) -> tuple:
    """Выполняет команду и возвращает (stdout, stderr, returncode)"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1


def get_server_info() -> tuple:
    """Получает информацию о сервере"""
    hostname = socket.gethostname()
    ips = []

    # Получаем IP адреса
    stdout, _, _ = run_command(["ip", "-j", "addr"])
    if stdout:
        try:
            data = json.loads(stdout)
            for iface in data:
                for addr in iface.get("addr_info", []):
                    if addr.get("family") == "inet":
                        ip = addr.get("local")
                        if ip and not ip.startswith("127."):
                            ips.append(ip)
        except:
            pass

    if not ips:
        # Fallback
        try:
            ips = [socket.gethostbyname(hostname)]
        except:
            ips = ["unknown"]

    return hostname, ips


def load_json_file(path: Path) -> Optional[dict]:
    """Загружает JSON файл"""
    if path.exists():
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            pass
    return None


def save_json_file(path: Path, data: dict):
    """Сохраняет JSON файл"""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save {path}: {e}", file=sys.stderr)


def should_suppress_finding(finding: Finding) -> bool:
    """Проверяет, нужно ли подавить finding из-за anti-spam"""
    if not FINDINGS_CACHE_FILE.exists():
        return False

    cache = load_json_file(FINDINGS_CACHE_FILE)
    if not cache:
        return False

    finding_hash = finding.hash()
    now = datetime.now(timezone.utc)

    # Проверяем дедупликацию (24 часа)
    for cached in cache.get("findings", []):
        if cached.get("hash") == finding_hash:
            cached_time_str = cached["timestamp"].replace("Z", "+00:00")
            try:
                cached_time = datetime.fromisoformat(cached_time_str)
                # Делаем now timezone-aware если это не так
                if cached_time.tzinfo and now.tzinfo is None:
                    now = now.replace(tzinfo=timezone.utc)
                if now.tzinfo is None and cached_time.tzinfo:
                    cached_time = cached_time.replace(tzinfo=None)
                if now - cached_time < timedelta(hours=24):
                    return True
            except:
                pass

    return False


def update_findings_cache(findings: List[Finding]):
    """Обновляет кэш findings"""
    cache = {
        "updated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "findings": [
            {"hash": f.hash(), "timestamp": f.timestamp, "severity": f.severity}
            for f in findings
        ],
    }
    save_json_file(FINDINGS_CACHE_FILE, cache)


def check_updates() -> List[Finding]:
    """Проверка доступных обновлений безопасности"""
    findings = []
    hostname, ips = get_server_info()

    # Debian/Ubuntu
    stdout, _, rc = run_command(["apt-get", "--simulate", "upgrade"])
    if rc == 0 and ("upgraded" in stdout or "installed" in stdout):
        count = stdout.count("upgraded") + stdout.count("installed")
        if count > 0:
            findings.append(
                Finding(
                    check="package_updates",
                    severity="high",
                    summary=f"Доступно {count} обновлений пакетов",
                    details="Некоторые пакеты могут содержать исправления безопасности",
                    remediation="Выполните: apt-get update && apt-get upgrade",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    # RHEL/CentOS/Fedora
    stdout, _, rc = run_command(["dnf", "check-update", "--quiet"])
    if rc == 100:  # DNF возвращает 100 если есть обновления
        findings.append(
            Finding(
                check="package_updates",
                severity="high",
                summary="Доступны обновления пакетов (dnf)",
                details="Пакеты могут содержать исправления безопасности",
                remediation="Выполните: dnf upgrade",
                server_hostname=hostname,
                server_ip=ips,
            )
        )

    return findings


def check_ssh() -> List[Finding]:
    """Аудит конфигурации SSH"""
    findings = []
    hostname, ips = get_server_info()
    sshd_config = "/etc/ssh/sshd_config"

    if not os.path.exists(sshd_config):
        return findings

    with open(sshd_config, "r") as f:
        config = f.read()

    lines = config.split("\n")
    for line in lines:
        line = line.strip()
        if line.startswith("#") or not line:
            continue

        # PermitEmptyPasswords
        if line.lower().startswith("permitemptypasswords yes"):
            findings.append(
                Finding(
                    check="ssh_empty_passwords",
                    severity="critical",
                    summary="SSH разрешает вход с пустыми паролями",
                    details="Конфигурация: PermitEmptyPasswords yes",
                    remediation="Установите PermitEmptyPasswords no в /etc/ssh/sshd_config",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

        # Protocol 1
        if line.lower().startswith("protocol") and "1" in line:
            findings.append(
                Finding(
                    check="ssh_protocol_v1",
                    severity="critical",
                    summary="SSH использует устаревший Protocol 1",
                    details="Protocol 1 уязвим для атак",
                    remediation="Установите Protocol 2 или удалите директиву Protocol",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

        # PermitRootLogin yes
        if line.lower().startswith("permitrootlogin yes"):
            findings.append(
                Finding(
                    check="ssh_root_login",
                    severity="high",
                    summary="SSH разрешает прямой вход root",
                    details="Конфигурация: PermitRootLogin yes",
                    remediation="Установите PermitRootLogin no или prohibit-password",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

        # PasswordAuthentication yes
        if line.lower().startswith("passwordauthentication yes"):
            findings.append(
                Finding(
                    check="ssh_password_auth",
                    severity="high",
                    summary="SSH разрешает аутентификацию по паролю",
                    details="Рекомендуется использовать только ключи",
                    remediation="Установите PasswordAuthentication no и настройте SSH keys",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    return findings


def check_listening_ports() -> List[Finding]:
    """Мониторинг всех слушающих портов с детекцией изменений"""
    findings = []
    hostname, ips = get_server_info()

    # Получаем все слушающие порты
    stdout, _, rc = run_command(["ss", "-Htuln"])
    if rc != 0:
        return findings

    current_ports = {}
    suspicious_ports = {
        "4444": "Metasploit default",
        "31337": "Back Orifice / Elite",
        "6666": "IRC backdoor",
        "6667": "IRC backdoor",
        "1337": "Common backdoor",
        "9001": "Tor default",
        "8080": "HTTP proxy (часто используется малварью)",
    }

    for line in stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        local_addr = parts[4] if len(parts) > 4 else ""

        # Извлекаем порт
        if ":" in local_addr:
            port = local_addr.rsplit(":", 1)[-1]
            addr = local_addr.rsplit(":", 1)[0]
        else:
            continue

        is_public = addr in ["0.0.0.0", "*", "::", "[::]"]

        current_ports[f"{proto}:{port}:{addr}"] = {
            "protocol": proto,
            "port": port,
            "address": addr,
            "public": is_public,
        }

        # Проверка на подозрительные порты
        if port in suspicious_ports and is_public:
            findings.append(
                Finding(
                    check="suspicious_port",
                    severity="critical",
                    summary=f"Обнаружен подозрительный порт {port} ({suspicious_ports[port]})",
                    details=f"Протокол: {proto}, Адрес: {addr}",
                    remediation=f"Проверьте процесс на порту {port} и завершите при необходимости",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    # Проверка изменений портов
    if PORT_STATE_FILE.exists():
        old_data = load_json_file(PORT_STATE_FILE)
        if old_data:
            old_ports = old_data.get("ports", {})

            # Новые порты
            for key, port_info in current_ports.items():
                if key not in old_ports and port_info["public"]:
                    findings.append(
                        Finding(
                            check="new_port_opened",
                            severity="high",
                            summary=f"Открыт новый публичный порт {port_info['port']}/{port_info['protocol']}",
                            details=f"Адрес: {port_info['address']}",
                            remediation="Проверьте, какой сервис открыл этот порт",
                            server_hostname=hostname,
                            server_ip=ips,
                        )
                    )

            # Закрытые порты
            for key, port_info in old_ports.items():
                if key not in current_ports and port_info.get("public"):
                    findings.append(
                        Finding(
                            check="port_closed",
                            severity="medium",
                            summary=f"Закрыт ранее открытый порт {port_info['port']}/{port_info['protocol']}",
                            details=f"Адрес: {port_info['address']}",
                            remediation="Проверьте, не упал ли важный сервис",
                            server_hostname=hostname,
                            server_ip=ips,
                        )
                    )

    # Сохраняем текущее состояние
    save_json_file(PORT_STATE_FILE, {"ports": current_ports, "timestamp": datetime.now(timezone.utc).isoformat() + "Z"})

    return findings


def check_firewall() -> List[Finding]:
    """Проверка статуса файрвола"""
    findings = []
    hostname, ips = get_server_info()

    # UFW
    stdout, _, rc = run_command(["ufw", "status"])
    if rc == 0:
        if "inactive" in stdout.lower() or "disabled" in stdout.lower():
            findings.append(
                Finding(
                    check="firewall_disabled",
                    severity="high",
                    summary="Файрвол UFW отключен",
                    details="UFW status: inactive",
                    remediation="Включите UFW: ufw enable",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    # nftables
    stdout, _, rc = run_command(["nft", "list", "ruleset"])
    if rc == 0 and not stdout.strip():
        findings.append(
            Finding(
                check="firewall_nft_empty",
                severity="high",
                summary="Правила nftables пусты",
                details="Нет активных правил фильтрации",
                remediation="Настройте правила nftables",
                server_hostname=hostname,
                server_ip=ips,
            )
        )

    # iptables (если нет UFW и nftables)
    stdout, _, rc = run_command(["iptables", "-L", "-n"])
    if rc == 0:
        lines = stdout.split("\n")
        if len(lines) <= 3:  # Только заголовки
            findings.append(
                Finding(
                    check="firewall_iptables_empty",
                    severity="high",
                    summary="Правила iptables пусты",
                    details="Нет активных правил фильтрации",
                    remediation="Настройте правила iptables",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    return findings


def check_failed_logins() -> List[Finding]:
    """Проверка неудачных попыток входа"""
    findings = []
    hostname, ips = get_server_info()

    # journalctl
    stdout, _, rc = run_command(
        ["journalctl", "-u", "sshd", "--since", "1 hour ago", "--no-pager"]
    )
    if rc == 0 and "failed" in stdout.lower():
        count = stdout.lower().count("failed")
        if count > 10:
            findings.append(
                Finding(
                    check="brute_force_detected",
                    severity="high",
                    summary=f"Обнаружено {count} неудачных попыток входа за последний час",
                    details="Возможная атака перебором паролей",
                    remediation="Проверьте логи, настройте fail2ban",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    # auth.log
    if os.path.exists("/var/log/auth.log"):
        stdout, _, _ = run_command(
            ["grep", "-c", "Failed password", "/var/log/auth.log"]
        )
        try:
            count = int(stdout.strip())
            if count > 50:
                findings.append(
                    Finding(
                        check="auth_log_failures",
                        severity="high",
                        summary=f"В логе auth.log найдено {count} неудачных попыток входа",
                        details="Проверьте /var/log/auth.log для деталей",
                        remediation="Настройте fail2ban, рассмотрите блокировку IP",
                        server_hostname=hostname,
                        server_ip=ips,
                    )
                )
        except:
            pass

    return findings


def check_privileged_users() -> List[Finding]:
    """Проверка пользователей с привилегиями"""
    findings = []
    hostname, ips = get_server_info()

    # Пользователи с UID 0
    with open("/etc/passwd", "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 3:
                username = parts[0]
                uid = parts[2]
                if uid == "0" and username != "root":
                    findings.append(
                        Finding(
                            check="non_root_uid_zero",
                            severity="critical",
                            summary=f"Пользователь '{username}' имеет UID 0",
                            details="Любой пользователь с UID 0 имеет полный root доступ",
                            remediation=f"Измените UID пользователя {username} или удалите учетную запись",
                            server_hostname=hostname,
                            server_ip=ips,
                        )
                    )

    # Члены группы sudo/wheel
    for group in ["sudo", "wheel"]:
        stdout, _, rc = run_command(["getent", "group", group])
        if rc == 0 and stdout:
            members = stdout.strip().split(":")[-1].split(",")
            for member in members:
                if member and member != "root":
                    # Это информационное сообщение, не добавляем в findings
                    pass

    return findings


def check_systemd() -> List[Finding]:
    """Проверка упавших systemd сервисов"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(["systemctl", "is-failed"])
    if rc == 0 and stdout.strip():
        failed_services = stdout.strip().split("\n")
        for service in failed_services:
            if service and service != "UNIT":
                findings.append(
                    Finding(
                        check="systemd_failed",
                        severity="high",
                        summary=f"Сервис systemd упал: {service}",
                        details="Сервис находится в состоянии failed",
                        remediation=f"Проверьте статус: systemctl status {service}",
                        server_hostname=hostname,
                        server_ip=ips,
                    )
                )

    return findings


def check_disk() -> List[Finding]:
    """Мониторинг заполненности дисков"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(["df", "-H", "--output=target,pcent"])
    if rc == 0:
        lines = stdout.strip().split("\n")[1:]  # Пропускаем заголовок
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                mount = parts[0]
                percent = parts[1].rstrip("%")
                try:
                    pct = int(percent)
                    if pct >= 90:
                        findings.append(
                            Finding(
                                check="disk_critical",
                                severity="high",
                                summary=f"Критическая заполненность диска {mount}: {pct}%",
                                details="Диск заполнен более чем на 90%",
                                remediation="Очистите место на диске или расширьте файловую систему",
                                server_hostname=hostname,
                                server_ip=ips,
                            )
                        )
                    elif pct >= 80:
                        findings.append(
                            Finding(
                                check="disk_warning",
                                severity="high",
                                summary=f"Высокая заполненность диска {mount}: {pct}%",
                                details="Диск заполнен более чем на 80%",
                                remediation="Рассмотрите очистку места на диске",
                                server_hostname=hostname,
                                server_ip=ips,
                            )
                        )
                except ValueError:
                    pass

    return findings


def check_selinux() -> List[Finding]:
    """Проверка статуса SELinux/AppArmor"""
    findings = []
    hostname, ips = get_server_info()

    # SELinux
    stdout, _, rc = run_command(["getenforce"])
    if rc == 0:
        status = stdout.strip().lower()
        if status == "disabled":
            findings.append(
                Finding(
                    check="selinux_disabled",
                    severity="high",
                    summary="SELinux отключен",
                    details="GetEnforce вернул: Disabled",
                    remediation="Включите SELinux: setenforce 1 и настройте /etc/selinux/config",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )
        elif status == "permissive":
            findings.append(
                Finding(
                    check="selinux_permissive",
                    severity="high",
                    summary="SELinux в режиме Permissive",
                    details="Политики не применяются, только логирование",
                    remediation="Переключите в Enforcing: setenforce 1",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    # AppArmor
    stdout, _, rc = run_command(["aa-status"])
    if rc == 0:
        if "profiles are in complain mode" in stdout:
            findings.append(
                Finding(
                    check="apparmor_complain",
                    severity="high",
                    summary="AppArmor профили в режиме complain",
                    details="Политики не применяются принудительно",
                    remediation="Переключите профили в enforce mode",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    return findings


def check_cron() -> List[Finding]:
    """Поиск подозрительных cron заданий"""
    findings = []
    hostname, ips = get_server_info()
    suspicious_patterns = [
        "wget",
        "curl",
        "/tmp/",
        "base64",
        "eval",
        "nc -",
        "netcat",
        "bash -i",
        "/dev/tcp",
    ]

    crontab_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"]

    for path in crontab_paths:
        if os.path.isdir(path):
            for filename in os.listdir(path):
                filepath = os.path.join(path, filename)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, "r") as f:
                            content = f.read()
                            for pattern in suspicious_patterns:
                                if pattern in content:
                                    findings.append(
                                        Finding(
                                            check="suspicious_cron",
                                            severity="high",
                                            summary=f"Подозрительное cron задание в {filepath}",
                                            details=f"Найдено: {pattern}",
                                            remediation=f"Проверьте содержимое {filepath}",
                                            server_hostname=hostname,
                                            server_ip=ips,
                                        )
                                    )
                    except:
                        pass
        elif os.path.isfile(path):
            try:
                with open(path, "r") as f:
                    content = f.read()
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            findings.append(
                                Finding(
                                    check="suspicious_cron",
                                    severity="high",
                                    summary=f"Подозрительное cron задание в {path}",
                                    details=f"Найдено: {pattern}",
                                    remediation=f"Проверьте содержимое {path}",
                                    server_hostname=hostname,
                                    server_ip=ips,
                                )
                            )
            except:
                pass

    return findings


def check_processes() -> List[Finding]:
    """Проверка процессов на подозрительную активность"""
    findings = []
    hostname, ips = get_server_info()
    suspicious_names = [
        "miner",
        "xmrig",
        "kworker",
        "kinsing",
        "ddos",
        "bot",
        "backdoor",
    ]

    stdout, _, rc = run_command(["ps", "aux"])
    if rc == 0:
        for line in stdout.split("\n"):
            for name in suspicious_names:
                if name in line.lower():
                    findings.append(
                        Finding(
                            check="suspicious_process",
                            severity="critical",
                            summary=f"Обнаружен подозрительный процесс: {line[:100]}",
                            details="Имя процесса содержит подозрительные ключевые слова",
                            remediation="Завершите процесс и проведите расследование",
                            server_hostname=hostname,
                            server_ip=ips,
                        )
                    )

    return findings


def check_env_vars() -> List[Finding]:
    """Проверка переменных окружения на секреты"""
    findings = []
    hostname, ips = get_server_info()
    secret_patterns = ["PASSWORD", "SECRET", "KEY", "TOKEN", "API_KEY"]

    stdout, _, rc = run_command(["env"])
    if rc == 0:
        for line in stdout.split("\n"):
            for pattern in secret_patterns:
                if pattern in line and "=" in line:
                    var_name = line.split("=")[0]
                    # Не показываем значение
                    findings.append(
                        Finding(
                            check="secret_in_env",
                            severity="high",
                            summary=f"Секрет в переменной окружения: {var_name}",
                            details="Переменная содержит потенциально чувствительные данные",
                            remediation="Используйте secure vault вместо переменных окружения",
                            server_hostname=hostname,
                            server_ip=ips,
                        )
                    )

    return findings


def check_oom() -> List[Finding]:
    """Проверка OOM killer событий"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(
        ["dmesg", "-T", "|", "grep", "-i", "out of memory", "|", "tail", "-5"]
    )
    # Упрощенная проверка через journalctl
    stdout, _, rc = run_command(
        ["journalctl", "-k", "--since", "1 hour ago", "-g", "OOM"]
    )
    if rc == 0 and stdout.strip():
        findings.append(
            Finding(
                check="oom_killer",
                severity="high",
                summary="OOM Killer активирован за последний час",
                details="Системе не хватало памяти, процессы были завершены",
                remediation="Увеличьте RAM или оптимизируйте использование памяти",
                server_hostname=hostname,
                server_ip=ips,
            )
        )

    return findings


def check_zombie_processes() -> List[Finding]:
    """Проверка zombie процессов"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(["ps", "aux"])
    if rc == 0:
        zombie_count = sum(1 for line in stdout.split("\n") if "<defunct>" in line)
        if zombie_count > 5:
            findings.append(
                Finding(
                    check="zombie_processes",
                    severity="high",
                    summary=f"Обнаружено {zombie_count} zombie процессов",
                    details="Zombie процессы потребляют ресурсы системы",
                    remediation="Перезапустите родительские процессы или перезагрузите систему",
                    server_hostname=hostname,
                    server_ip=ips,
                )
            )

    return findings


def check_promiscuous_mode() -> List[Finding]:
    """Проверка интерфейсов в promiscuous mode"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(["ip", "link"])
    if rc == 0:
        lines = stdout.split("\n")
        for i, line in enumerate(lines):
            if "PROMISC" in line:
                # Находим имя интерфейса
                iface = line.split(":")[1].strip().split("@")[0] if ":" in line else "unknown"
                findings.append(
                    Finding(
                        check="promiscuous_mode",
                        severity="high",
                        summary=f"Интерфейс {iface} в режиме promiscuous",
                        details="Интерфейс перехватывает весь сетевой трафик",
                        remediation="Проверьте, легально ли это (Wireshark, tcpdump) или удалите флаг",
                        server_hostname=hostname,
                        server_ip=ips,
                    )
                )

    return findings


def check_audit_status() -> List[Finding]:
    """Проверка статуса auditd"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(["systemctl", "is-active", "auditd"])
    if rc != 0 or "inactive" in stdout.lower():
        findings.append(
            Finding(
                check="auditd_inactive",
                severity="high",
                summary="Служба auditd не активна",
                details="Системный аудит отключен",
                remediation="Включите auditd: systemctl enable --now auditd",
                server_hostname=hostname,
                server_ip=ips,
            )
        )

    return findings


def check_failed_services_startup() -> List[Finding]:
    """Проверка сервисов с ошибками при загрузке"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(
        ["systemctl", "list-units", "--state=failed", "--no-pager"]
    )
    if rc == 0 and stdout.strip():
        lines = stdout.strip().split("\n")[1:]  # Пропускаем заголовок
        for line in lines:
            if line.strip():
                parts = line.split()
                if parts:
                    service = parts[0]
                    findings.append(
                        Finding(
                            check="startup_failure",
                            severity="high",
                            summary=f"Сервис {service} не запустился при загрузке",
                            details="Сервис находится в состоянии failed после загрузки",
                            remediation=f"Проверьте: systemctl status {service}",
                            server_hostname=hostname,
                            server_ip=ips,
                        )
                    )

    return findings


def check_inode_usage() -> List[Finding]:
    """Проверка исчерпания inode"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(["df", "-i", "--output=target,pcent"])
    if rc == 0:
        lines = stdout.strip().split("\n")[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                mount = parts[0]
                percent = parts[1].rstrip("%")
                try:
                    pct = int(percent)
                    if pct >= 90:
                        findings.append(
                            Finding(
                                check="inode_critical",
                                severity="high",
                                summary=f"Критическое использование inode на {mount}: {pct}%",
                                details="Файловая система может стать недоступной для записи",
                                remediation="Удалите мелкие файлы или расширьте файловую систему",
                                server_hostname=hostname,
                                server_ip=ips,
                            )
                        )
                except ValueError:
                    pass

    return findings


def check_time_changes() -> List[Finding]:
    """Проверка изменений системного времени"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(
        ["journalctl", "-u", "systemd-timesyncd", "--since", "1 hour ago", "-g", "time"]
    )
    if rc == 0 and "time jump" in stdout.lower():
        findings.append(
            Finding(
                check="time_jump_detected",
                severity="high",
                summary="Обнаружен скачок системного времени",
                details="Время системы было резко изменено",
                remediation="Проверьте настройки NTP и журналы на предмет манипуляций",
                server_hostname=hostname,
                server_ip=ips,
            )
        )

    return findings


def check_network_errors() -> List[Finding]:
    """Проверка сетевых ошибок"""
    findings = []
    hostname, ips = get_server_info()

    stdout, _, rc = run_command(["ip", "-s", "link"])
    if rc == 0:
        if "errors" in stdout.lower() or "dropped" in stdout.lower():
            # Более детальная проверка
            stdout, _, _ = run_command(["netstat", "-i"])
            if "error" in stdout.lower():
                findings.append(
                    Finding(
                        check="network_errors",
                        severity="high",
                        summary="Обнаружены сетевые ошибки",
                        details="Пакеты теряются или повреждаются",
                        remediation="Проверьте сетевое оборудование и драйверы",
                        server_hostname=hostname,
                        server_ip=ips,
                    )
                )

    return findings


def run_all_checks() -> List[Finding]:
    """Запускает все проверки и собирает findings"""
    all_findings = []

    checks = [
        check_updates,
        check_ssh,
        check_listening_ports,
        check_firewall,
        check_failed_logins,
        check_privileged_users,
        check_systemd,
        check_disk,
        check_selinux,
        check_cron,
        check_processes,
        check_env_vars,
        check_oom,
        check_zombie_processes,
        check_promiscuous_mode,
        check_audit_status,
        check_failed_services_startup,
        check_inode_usage,
        check_time_changes,
        check_network_errors,
    ]

    for check_func in checks:
        try:
            findings = check_func()
            all_findings.extend(findings)
        except Exception as e:
            # Игнорируем ошибки отдельных проверок
            print(f"Warning: {check_func.__name__} failed: {e}", file=sys.stderr)

    return all_findings


def filter_findings(findings: List[Finding], min_severity: str = "high") -> List[Finding]:
    """Фильтрует findings по минимальному уровню серьезности"""
    min_level = MIN_SEVERITY_LEVEL.get(min_severity, 1)
    return [f for f in findings if MIN_SEVERITY_LEVEL.get(f.severity, 4) <= min_level]


def generate_report(findings: List[Finding], format: str = "json") -> str:
    """Генерирует отчет"""
    hostname, ips = get_server_info()

    # Фильтруем только critical и high
    filtered = filter_findings(findings, "high")

    # Применяем anti-spam (дедупликацию)
    unique_findings = []
    for f in filtered:
        if not should_suppress_finding(f):
            unique_findings.append(f)

    critical_count = sum(1 for f in unique_findings if f.severity == "critical")
    high_count = sum(1 for f in unique_findings if f.severity == "high")

    report = SecurityReport(
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        mode="critical_high_only",
        schedule="daily",
        server_hostname=hostname,
        server_ip=ips,
        total_findings=len(unique_findings),
        critical_count=critical_count,
        high_count=high_count,
        status="issues_found" if unique_findings else "clean",
        findings=unique_findings,
    )

    # Обновляем кэш
    update_findings_cache(unique_findings)

    if format == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    else:
        # Markdown формат
        md = f"# 🛡️ Отчет Security Monitor\n\n"
        md += f"**Сервер:** {hostname} ({', '.join(ips)})\n"
        md += f"**Время:** {report.timestamp}\n"
        md += f"**Статус:** {'⚠️ Найдены проблемы' if report.status == 'issues_found' else '✅ чисто'}\n\n"
        md += f"## Сводка\n"
        md += f"- **Всего проблем:** {report.total_findings}\n"
        md += f"- **Critical:** {report.critical_count}\n"
        md += f"- **High:** {report.high_count}\n\n"

        if unique_findings:
            md += "## Детали\n\n"
            for i, f in enumerate(unique_findings, 1):
                emoji = "🔴" if f.severity == "critical" else "🟠"
                md += f"### {i}. {emoji} [{f.severity.upper()}] {f.summary}\n"
                md += f"- **Проверка:** {f.check}\n"
                if f.details:
                    md += f"- **Детали:** {f.details}\n"
                if f.remediation:
                    md += f"- **Решение:** {f.remediation}\n"
                md += "\n"
        else:
            md += "**Проблем не обнаружено.**\n"

        return md


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Linux Security Monitor Sub-Agent")
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="markdown",
        help="Формат вывода (по умолчанию: markdown)",
    )
    parser.add_argument(
        "--daily-summary",
        action="store_true",
        help="Режим ежедневной сводки (подавляет чистые отчеты)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Принудительный запуск без anti-spam проверок",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high"],
        help="Exit code 2 если найдены проблемы указанного уровня",
    )

    args = parser.parse_args()

    # Создаем директорию для состояния
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Запускаем проверки
    all_findings = run_all_checks()

    # Генерируем отчет
    report_str = generate_report(all_findings, args.format)

    # Выводим отчет
    print(report_str)

    # Определяем exit code
    if args.fail_on:
        hostname, _ = get_server_info()
        filtered = filter_findings(all_findings, args.fail_on)
        if filtered:
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
