#!/usr/bin/env python3
import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

TIMEOUT = 20

ALLOWED_COMMANDS = {
    "uname": ["uname", "-a"],
    "disk": ["df", "-hT"],
    "memory": ["free", "-m"],
    "listening": ["ss", "-Htuln"],
    "failed_units": ["systemctl", "--failed", "--no-legend"],
    "ufw_status": ["ufw", "status", "verbose"],
    "nft_rules": ["nft", "list", "ruleset"],
    "iptables_rules": ["iptables", "-S"],
    "journal_ssh": [
        "journalctl",
        "-u", "ssh",
        "-u", "sshd",
        "--since", "24 hours ago",
        "--no-pager"
    ],
    "auth_log": ["tail", "-n", "5000", "/var/log/auth.log"],
    "uid0": ["awk", "-F:", "$3==0 {print $1}", "/etc/passwd"],
    "sudo_group": ["getent", "group", "sudo"],
    "wheel_group": ["getent", "group", "wheel"],
    "apt_upgradable": [
        "apt-get",
        "-s",
        "-o", "Debug::NoLocking=true",
        "upgrade"
    ],
    "dnf_check_update": ["dnf", "-q", "check-update"],
    "fail2ban_status": ["fail2ban-client", "status"],
    "docker_ps": [
        "docker",
        "ps",
        "--format",
        "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
    ],
    "selinux_status": ["getenforce"],
    "apparmor_status": ["aa-status", "--enabled"],
    "sysctl_security": [
        "sysctl",
        "-n",
        "kernel.randomize_va_space",
        "kernel.dmesg_restrict",
        "kernel.kptr_restrict",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.icmp_echo_ignore_broadcasts"
    ],
    "last_logins": ["last", "-n", "20"],
    "active_sessions": ["who"],
    "cron_root": ["cat", "/etc/crontab"],
    "cron_list": ["crontab", "-l"],
    "opened_files": ["lsof", "-i", "-nP"],
    "processes": ["ps", "auxww"],
    "environment_vars": ["env"],
}

ALLOWED_FILES = {
    "/etc/os-release",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    remediation: str = ""


def add(
    findings: List[Finding],
    severity: str,
    title: str,
    detail: str = "",
    remediation: str = ""
) -> None:
    findings.append(
        Finding(
            severity=severity.lower(),
            title=title.strip(),
            detail=detail.strip(),
            remediation=remediation.strip(),
        )
    )


def run_cmd(name: str) -> Dict[str, Any]:
    argv = ALLOWED_COMMANDS.get(name)
    if not argv:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"unknown command: {name}",
        }

    exe = argv[0]
    if shutil.which(exe) is None:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"executable not found: {exe}",
        }

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            shell=False,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"timeout after {TIMEOUT}s",
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }


def read_allowed_file(path: str) -> Optional[str]:
    if path not in ALLOWED_FILES:
        return None

    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        return None


def basic_meta() -> Dict[str, str]:
    meta = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "agent": "security-monitor",
        "mode": "read-only",
    }

    res = run_cmd("uname")
    if res["ok"]:
        meta["uname"] = res["stdout"].strip()

    os_release = read_allowed_file("/etc/os-release")
    if os_release:
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                meta["os"] = line.split("=", 1)[1].strip().strip('"')

    return meta


def check_updates(findings: List[Finding]) -> None:
    if shutil.which("apt-get"):
        res = run_cmd("apt_upgradable")
        if res["ok"]:
            pkgs = [
                line
                for line in res["stdout"].splitlines()
                if line.startswith("Inst")
            ]
            if pkgs:
                detail = "\n".join(pkgs[:30])
                if len(pkgs) > 30:
                    detail += f"\n... and {len(pkgs) - 30} more"
                add(
                    findings,
                    "medium",
                    f"APT: доступны обновления пакетов ({len(pkgs)})",
                    detail,
                    "Выполните: sudo apt update && sudo apt upgrade. Для продакшена настройте unattended-upgrades для security-обновлений.",
                )
            else:
                add(
                    findings,
                    "info",
                    "APT: ожидающих обновлений не найдено",
                    "",
                    "Проверьте, включены ли автоматические security-обновления.",
                )
        else:
            add(
                findings,
                "low",
                "APT: не удалось проверить обновления",
                res["stderr"],
                "Запустите агент с правами, достаточными для apt-get -s upgrade, или настройте ограниченный sudoers.",
            )
        return

    if shutil.which("dnf"):
        res = run_cmd("dnf_check_update")
        if res["returncode"] in (0, 100):
            lines = [
                line
                for line in res["stdout"].splitlines()
                if line.strip() and not line.lower().startswith("last metadata")
            ]
            if lines:
                detail = "\n".join(lines[:30])
                if len(lines) > 30:
                    detail += f"\n... and {len(lines) - 30} more"
                add(
                    findings,
                    "medium",
                    f"DNF: доступны обновления пакетов ({len(lines)})",
                    detail,
                    "Выполните: sudo dnf upgrade. Настройте dnf-automatic для security-обновлений.",
                )
            else:
                add(
                    findings,
                    "info",
                    "DNF: ожидающих обновлений не найдено",
                    "",
                    "Проверьте, включены ли автоматические security-обновления.",
                )
        else:
            add(
                findings,
                "low",
                "DNF: не удалось проверить обновления",
                res["stderr"],
                "Запустите агент с правами, достаточными для dnf check-update.",
            )
        return

    add(
        findings,
        "info",
        "Менеджер пакетов не распознан",
        "Поддерживаются apt и dnf. Для другого дистрибутива добавьте соответствующую проверку.",
        "",
    )


def get_ssh_options(text: str) -> Dict[str, str]:
    options: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 1)
        if len(parts) != 2:
            continue

        key = parts[0].lower()
        if key not in options:
            options[key] = parts[1].strip()

    return options


def check_ssh(findings: List[Finding]) -> None:
    text = read_allowed_file("/etc/ssh/sshd_config")
    if not text:
        add(
            findings,
            "info",
            "SSH: не удалось прочитать /etc/ssh/sshd_config",
            "",
            "Проверьте права доступа к файлу или используйте sshd -T от root для полного effective-config аудита.",
        )
        return

    opts = get_ssh_options(text)

    root_login = opts.get("permitrootlogin", "").lower()
    password_auth = opts.get("passwordauthentication", "").lower()
    empty_passwords = opts.get("permitemptypasswords", "").lower()
    protocol = opts.get("protocol", "").lower()
    x11 = opts.get("x11forwarding", "").lower()
    max_auth_tries = opts.get("maxauthtries", "").lower()

    if empty_passwords == "yes":
        add(
            findings,
            "critical",
            "SSH: разрешены пустые пароли",
            "PermitEmptyPasswords yes",
            "Установите PermitEmptyPasswords no и перезапустите sshd после проверки конфигурации.",
        )

    if protocol.startswith("1"):
        add(
            findings,
            "critical",
            "SSH: включён устаревший protocol version 1",
            "Protocol 1 небезопасен.",
            "Удалите строку Protocol 1 или установите Protocol 2.",
        )

    if root_login == "yes":
        add(
            findings,
            "high",
            "SSH: прямой root-вход разрешён",
            "PermitRootLogin yes",
            "Установите PermitRootLogin no или prohibit-password и используйте sudo/доменную модель доступа.",
        )
    elif root_login == "":
        add(
            findings,
            "info",
            "SSH: PermitRootLogin не задан явно",
            "Значение по умолчанию зависит от версии OpenSSH.",
            "Явно установите PermitRootLogin no или prohibit-password.",
        )

    if password_auth == "yes":
        add(
            findings,
            "medium",
            "SSH: включена парольная аутентификация",
            "PasswordAuthentication yes",
            "Если возможно, перейдите на SSH-ключи: PasswordAuthentication no, PubkeyAuthentication yes.",
        )

    if x11 == "yes":
        add(
            findings,
            "low",
            "SSH: включён X11Forwarding",
            "X11Forwarding yes",
            "Если X11 forwarding не нужен, установите X11Forwarding no.",
        )

    if max_auth_tries.isdigit() and int(max_auth_tries) > 5:
        add(
            findings,
            "low",
            "SSH: MaxAuthTries выше 5",
            f"MaxAuthTries {max_auth_tries}",
            "Рекомендуется значение 3-5 для снижения brute-force риска.",
        )

    if not any(
        [
            root_login == "yes",
            password_auth == "yes",
            empty_passwords == "yes",
            protocol.startswith("1"),
        ]
    ):
        add(
            findings,
            "info",
            "SSH: грубых ошибок в sshd_config не найдено",
            "Проверены PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, Protocol.",
            "Для полного аудита используйте sshd -T, так как конфиг может содержать Include.",
        )


def check_listening_ports(findings: List[Finding]) -> None:
    res = run_cmd("listening")
    if not res["ok"]:
        add(
            findings,
            "info",
            "Порты: не удалось получить список слушающих сокетов",
            res["stderr"],
            "Установите iproute2 и убедитесь, что команда ss доступна.",
        )
        return

    ports = []
    for line in res["stdout"].splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        state = parts[1].upper() if len(parts) > 1 else ""
        local = parts[4]

        if proto.startswith("tcp") and state != "LISTEN":
            continue

        if local.startswith("127.") or local.startswith("[::1]"):
            continue

        ports.append(f"{proto} {local}")

    ports = sorted(set(ports))

    if not ports:
        add(
            findings,
            "info",
            "Порты: публичные слушающие сервисы не найдены",
            "",
            "",
        )
    else:
        add(
            findings,
            "info",
            f"Порты: найдено {len(ports)} слушающих адресов",
            "\n".join(ports[:100]),
            "Проверьте, какие сервисы действительно должны быть доступны из сети.",
        )

    exposed_ssh = [
        p
        for p in ports
        if ":22" in p and ("0.0.0.0" in p or "[::]" in p or p.endswith("*:22"))
    ]

    if exposed_ssh:
        add(
            findings,
            "medium",
            "SSH доступен на всех сетевых интерфейсах",
            "\n".join(exposed_ssh),
            "Ограничьте доступ firewall'ом, VPN, ListenAddress, включите fail2ban и SSH-ключи.",
        )


def check_firewall(findings: List[Finding]) -> None:
    if shutil.which("ufw"):
        res = run_cmd("ufw_status")
        out = res["stdout"]

        if "Status: active" in out:
            add(
                findings,
                "info",
                "Firewall: UFW активен",
                out[:1000],
                "Проверьте правила по умолчанию и список открытых портов.",
            )
        elif "Status: inactive" in out:
            add(
                findings,
                "high",
                "Firewall: UFW установлен, но выключен",
                out[:500],
                "Настройте правила и выполните sudo ufw enable. Сначала разрешите SSH, чтобы не потерять доступ.",
            )
        else:
            add(
                findings,
                "medium",
                "Firewall: не удалось определить статус UFW",
                res["stderr"],
                "Запустите с правами root или проверьте установку ufw.",
            )
        return

    if shutil.which("nft"):
        res = run_cmd("nft_rules")
        if res["ok"] and res["stdout"].strip():
            add(
                findings,
                "info",
                "Firewall: nftables правила существуют",
                res["stdout"][:1000],
                "Проверьте default policy и разрешённые порты.",
            )
        else:
            add(
                findings,
                "medium",
                "Firewall: nftables ruleset пуст или недоступен",
                res["stderr"],
                "Настройте nftables. Для сервера обычно используют default deny inbound + разрешённый SSH/HTTPS.",
            )
        return

    if shutil.which("iptables"):
        res = run_cmd("iptables_rules")
        if res["ok"]:
            lines = [line.strip() for line in res["stdout"].splitlines() if line.strip()]
            only_policies = all(line.startswith("-P") for line in lines) if lines else True
            accept_all = any("-P INPUT ACCEPT" in line for line in lines) or not lines

            if only_policies and accept_all:
                add(
                    findings,
                    "medium",
                    "Firewall: iptables без активных правил или с INPUT ACCEPT",
                    res["stdout"][:500],
                    "Настройте iptables/nftables/ufw. Не оставляйте INPUT ACCEPT на публичном сервере.",
                )
            else:
                add(
                    findings,
                    "info",
                    "Firewall: iptables правила найдены",
                    res["stdout"][:1000],
                    "Проверьте правила и политики по умолчанию.",
                )
        else:
            add(
                findings,
                "medium",
                "Firewall: iptables недоступен",
                res["stderr"],
                "Обычно требуется root. Проверьте доступ или используйте nftables/ufw.",
            )
        return

    add(
        findings,
        "medium",
        "Firewall: не найден ufw, nft или iptables",
        "",
        "Установите и настройте firewall.",
    )


def check_failed_ssh_logins(findings: List[Finding]) -> None:
    text = ""
    source = ""

    res = run_cmd("journal_ssh")
    if res["ok"] and res["stdout"].strip():
        text = res["stdout"]
        source = "journalctl"
    else:
        res = run_cmd("auth_log")
        if res["ok"] and res["stdout"].strip():
            text = res["stdout"]
            source = "/var/log/auth.log"

    if not text:
        add(
            findings,
            "info",
            "SSH-логи: не удалось прочитать журналы",
            res.get("stderr", ""),
            "Запустите с правами root или настройте доступ к journalctl/auth.log.",
        )
        return

    failed_count = len(
        re.findall(
            r"failed password|authentication failure|invalid user",
            text,
            re.IGNORECASE,
        )
    )

    detail = f"Источник: {source}; найдено событий: {failed_count}"

    if failed_count > 200:
        add(
            findings,
            "high",
            "Много неудачных SSH-входов",
            detail,
            "Включите fail2ban, отключите пароли, ограничьте источники доступа, используйте VPN/allowlist.",
        )
    elif failed_count > 50:
        add(
            findings,
            "medium",
            "Заметное количество неудачных SSH-входов",
            detail,
            "Проверьте fail2ban и источники подключений.",
        )
    elif failed_count > 0:
        add(
            findings,
            "info",
            "Есть единичные неудачные SSH-входы",
            detail,
            "Обычно нормально, но стоит мониторить динамику.",
        )
    else:
        add(
            findings,
            "info",
            "SSH-логи: неудачные входы не найдены",
            detail,
            "",
        )


def check_users(findings: List[Finding]) -> None:
    res = run_cmd("uid0")
    if res["ok"]:
        users = [u.strip() for u in res["stdout"].splitlines() if u.strip()]
        extra = [u for u in users if u != "root"]

        if extra:
            add(
                findings,
                "critical",
                "Найдены учетные записи с UID 0 кроме root",
                ", ".join(extra),
                "Немедленно проверьте: getent passwd. Это может быть признаком бэкдора или ошибки администрирования.",
            )
        else:
            add(
                findings,
                "info",
                "UID 0: только root",
                "",
                "",
            )
    else:
        add(
            findings,
            "info",
            "UID 0: проверка недоступна",
            res["stderr"],
            "",
        )

    for group in ("sudo", "wheel"):
        res = run_cmd(f"{group}_group")
        if res["ok"] and res["stdout"].strip():
            add(
                findings,
                "info",
                f"Группа {group}: участники",
                res["stdout"].strip(),
                "Проверьте список администраторов.",
            )


def check_systemd_failed(findings: List[Finding]) -> None:
    if not shutil.which("systemctl"):
        return

    res = run_cmd("failed_units")
    if not res["ok"]:
        add(
            findings,
            "info",
            "systemd: не удалось получить failed units",
            res["stderr"],
            "",
        )
        return

    units = [line for line in res["stdout"].splitlines() if line.strip()]
    if units:
        add(
            findings,
            "medium",
            f"systemd: есть failed units ({len(units)})",
            "\n".join(units),
            "Проверьте: systemctl status <unit> и journalctl -u <unit>.",
        )
    else:
        add(
            findings,
            "info",
            "systemd: failed units нет",
            "",
            "",
        )


def check_fail2ban(findings: List[Finding]) -> None:
    if not shutil.which("fail2ban-client"):
        add(
            findings,
            "low",
            "Fail2ban не установлен",
            "",
            "Если SSH доступен из интернета, рекомендуется установить fail2ban и включить sshd jail.",
        )
        return

    res = run_cmd("fail2ban_status")
    if res["ok"]:
        add(
            findings,
            "info",
            "Fail2ban работает",
            res["stdout"][:1000],
            "Проверьте, активен ли jail для sshd.",
        )
    else:
        add(
            findings,
            "medium",
            "Fail2ban установлен, но статус недоступен или сервис не активен",
            res["stderr"],
            "Проверьте: systemctl status fail2ban; fail2ban-client status.",
        )


def check_disk(findings: List[Finding]) -> None:
    res = run_cmd("disk")
    if not res["ok"]:
        add(
            findings,
            "info",
            "Диск: df недоступен",
            res["stderr"],
            "",
        )
        return

    ignore_fs = {
        "tmpfs",
        "devtmpfs",
        "squashfs",
        "iso9660",
    }

    for line in res["stdout"].splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue

        fstype = parts[1]
        use = parts[5].replace("%", "")
        mount = parts[6]

        if fstype in ignore_fs:
            continue

        if not use.isdigit():
            continue

        pct = int(use)

        if pct >= 90:
            add(
                findings,
                "high",
                f"Диск заполнен на {pct}%: {mount}",
                line,
                "Очистите логи, пакеты, Docker-образы или расширьте том.",
            )
        elif pct >= 80:
            add(
                findings,
                "medium",
                f"Диск заполнен на {pct}%: {mount}",
                line,
                "Проверьте свободное место.",
            )


def check_docker(findings: List[Finding]) -> None:
    if not shutil.which("docker"):
        return

    res = run_cmd("docker_ps")
    if res["ok"]:
        if res["stdout"].strip():
            add(
                findings,
                "info",
                "Docker: запущенные контейнеры",
                res["stdout"][:2000],
                "Проверьте привилегированные контейнеры, проброс портов и версии образов.",
            )
        else:
            add(
                findings,
                "info",
                "Docker: нет запущенных контейнеров",
                "",
                "",
            )
    else:
        if "permission denied" in res["stderr"].lower():
            add(
                findings,
                "info",
                "Docker: нет прав на docker ps",
                res["stderr"],
                "Добавлять пользователя в группу docker нужно осторожно: это часто эквивалентно root.",
            )
        else:
            add(
                findings,
                "info",
                "Docker: не удалось получить список контейнеров",
                res["stderr"],
                "",
            )


def check_selinux_apparmor(findings: List[Finding]) -> None:
    """Проверка SELinux и AppArmor статусов."""
    # SELinux
    if shutil.which("getenforce"):
        res = run_cmd("selinux_status")
        if res["ok"]:
            status = res["stdout"].strip().lower()
            if status == "disabled":
                add(
                    findings,
                    "medium",
                    "SELinux отключён",
                    "SELinux status: Disabled",
                    "Рассмотрите включение SELinux в режиме Enforcing для дополнительной защиты.",
                )
            elif status == "permissive":
                add(
                    findings,
                    "low",
                    "SELinux в режиме Permissive",
                    "SELinux status: Permissive",
                    "Режим Permissive полезен для отладки, но для продакшена рекомендуется Enforcing.",
                )
            else:
                add(
                    findings,
                    "info",
                    "SELinux активен (Enforcing)",
                    f"SELinux status: {res['stdout'].strip()}",
                    "",
                )
        else:
            add(
                findings,
                "info",
                "SELinux: не удалось получить статус",
                res["stderr"],
                "",
            )

    # AppArmor
    if shutil.which("aa-status"):
        res = run_cmd("apparmor_status")
        if res["ok"]:
            add(
                findings,
                "info",
                "AppArmor активен",
                res["stdout"][:1000],
                "Проверьте количество профилей и режимы enforcement.",
            )
        else:
            add(
                findings,
                "low",
                "AppArmor установлен, но статус недоступен",
                res["stderr"],
                "Проверьте: aa-status или systemctl status apparmor.",
            )

    if not shutil.which("getenforce") and not shutil.which("aa-status"):
        add(
            findings,
            "low",
            "MAC-системы (SELinux/AppArmor) не обнаружены",
            "",
            "Рассмотрите включение SELinux (RHEL/CentOS) или AppArmor (Debian/Ubuntu).",
        )


def check_sysctl_security(findings: List[Finding]) -> None:
    """Проверка важных kernel security параметров через sysctl."""
    if not shutil.which("sysctl"):
        return

    res = run_cmd("sysctl_security")
    if not res["ok"]:
        add(
            findings,
            "info",
            "Sysctl: не удалось прочитать security параметры",
            res["stderr"],
            "",
        )
        return

    lines = res["stdout"].strip().split("\n")
    if len(lines) < 6:
        return

    try:
        va_space = int(lines[0]) if lines[0].isdigit() else -1
        dmesg_restrict = int(lines[1]) if lines[1].isdigit() else -1
        kptr_restrict = int(lines[2]) if lines[2].isdigit() else -1
        accept_source_route = int(lines[3]) if lines[3].isdigit() else -1
        accept_redirects = int(lines[4]) if lines[4].isdigit() else -1
        send_redirects = int(lines[5]) if lines[5].isdigit() else -1

        if va_space != 2:
            add(
                findings,
                "medium",
                "ASLR отключён или частично включён",
                f"kernel.randomize_va_space = {va_space} (рекомендуется 2)",
                "Выполните: sysctl -w kernel.randomize_va_space=2",
            )

        if dmesg_restrict != 1:
            add(
                findings,
                "low",
                "dmesg restrict не включён",
                f"kernel.dmesg_restrict = {dmesg_restrict} (рекомендуется 1)",
                "Выполните: sysctl -w kernel.dmesg_restrict=1",
            )

        if kptr_restrict not in (1, 2):
            add(
                findings,
                "low",
                "kptr restrict не оптимальен",
                f"kernel.kptr_restrict = {kptr_restrict} (рекомендуется 1 или 2)",
                "Выполните: sysctl -w kernel.kptr_restrict=1",
            )

        if accept_source_route != 0:
            add(
                findings,
                "medium",
                "Accept source route включён",
                f"net.ipv4.conf.all.accept_source_route = {accept_source_route} (рекомендуется 0)",
                "Выполните: sysctl -w net.ipv4.conf.all.accept_source_route=0",
            )

        if accept_redirects != 0:
            add(
                findings,
                "low",
                "Accept redirects включён",
                f"net.ipv4.conf.all.accept_redirects = {accept_redirects} (рекомендуется 0)",
                "Выполните: sysctl -w net.ipv4.conf.all.accept_redirects=0",
            )

        if send_redirects != 0:
            add(
                findings,
                "low",
                "Send redirects включён",
                f"net.ipv4.conf.all.send_redirects = {send_redirects} (рекомендуется 0)",
                "Выполните: sysctl -w net.ipv4.conf.all.send_redirects=0",
            )

    except (ValueError, IndexError) as e:
        add(
            findings,
            "info",
            "Sysctl: ошибка парсинга параметров",
            str(e),
            "",
        )


def check_login_activity(findings: List[Finding]) -> None:
    """Проверка последних входов в систему и активных сессий."""
    # Последние логины
    if shutil.which("last"):
        res = run_cmd("last_logins")
        if res["ok"] and res["stdout"].strip():
            lines = [l for l in res["stdout"].splitlines() if l.strip()][:10]
            if lines:
                # Проверка на root логины
                root_logins = [l for l in lines if "root" in l.split()[0] if l.split()]
                if root_logins:
                    add(
                        findings,
                        "medium",
                        "Обнаружены недавние root-логины",
                        "\n".join(root_logins[:5]),
                        "Используйте sudo вместо прямого root-входа. Проверьте источник подключений.",
                    )

                add(
                    findings,
                    "info",
                    "Последние входы в систему",
                    "\n".join(lines),
                    "Проверьте на наличие подозрительной активности.",
                )
        else:
            add(
                findings,
                "info",
                "Last: не удалось получить историю входов",
                res.get("stderr", ""),
                "",
            )

    # Активные сессии
    if shutil.which("who"):
        res = run_cmd("active_sessions")
        if res["ok"] and res["stdout"].strip():
            sessions = res["stdout"].strip().split("\n")
            add(
                findings,
                "info",
                f"Активные сессии ({len(sessions)})",
                res["stdout"][:1000],
                "Проверьте легитимность активных подключений.",
            )
        elif res["ok"]:
            add(
                findings,
                "info",
                "Активные сессии отсутствуют",
                "",
                "",
            )


def check_cron(findings: List[Finding]) -> None:
    """Проверка cron заданий."""
    # Root crontab
    if shutil.which("cat"):
        res = run_cmd("cron_root")
        if res["ok"] and res["stdout"].strip():
            lines = [l for l in res["stdout"].splitlines() if l.strip() and not l.startswith("#")]
            if lines:
                add(
                    findings,
                    "info",
                    "Root cron задания",
                    "\n".join(lines[:20]),
                    "Проверьте на наличие подозрительных команд или скриптов.",
                )
            else:
                add(
                    findings,
                    "info",
                    "Root cron: заданий нет",
                    "",
                    "",
                )
        elif res["returncode"] != 0 and "permission denied" not in res["stderr"].lower():
            add(
                findings,
                "info",
                "Cron: не удалось прочитать /etc/crontab",
                res["stderr"],
                "",
            )

    # Текущий пользователь crontab
    if shutil.which("crontab"):
        res = run_cmd("cron_list")
        if res["ok"] and res["stdout"].strip():
            lines = [l for l in res["stdout"].splitlines() if l.strip() and not l.startswith("#")]
            if lines:
                add(
                    findings,
                    "info",
                    "Cron задания текущего пользователя",
                    "\n".join(lines[:20]),
                    "Проверьте на наличие подозрительных команд.",
                )
        elif res["returncode"] == 1 or "no crontab" in res["stderr"].lower():
            add(
                findings,
                "info",
                "Cron: у текущего пользователя нет заданий",
                "",
                "",
            )


def check_password_policy(findings: List[Finding]) -> None:
    """Базовая проверка политики паролей."""
    shadow_content = read_allowed_file("/etc/shadow")
    if shadow_content:
        # Проверка на пустые пароли
        empty_password_users = []
        for line in shadow_content.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                username = parts[0]
                password_hash = parts[1]
                if password_hash == "" or password_hash == "!":
                    empty_password_users.append(username)

        if empty_password_users:
            add(
                findings,
                "critical",
                "Обнаружены учетные записи без пароля или заблокированные",
                ", ".join(empty_password_users[:20]),
                "Проверьте: grep ':*:' /etc/shadow и установите пароли или заблокируйте учетки.",
            )
        else:
            add(
                findings,
                "info",
                "Shadow: все учетные записи имеют хэш пароля",
                "",
                "",
            )

    # Проверка sudoers
    sudoers_content = read_allowed_file("/etc/sudoers")
    if sudoers_content:
        # Проверка на NOPASSWD
        nopasswd_lines = [
            l.strip() for l in sudoers_content.splitlines()
            if "NOPASSWD" in l and not l.startswith("#")
        ]
        if nopasswd_lines:
            add(
                findings,
                "medium",
                "Sudoers: найдены правила с NOPASSWD",
                "\n".join(nopasswd_lines[:10]),
                "Проверьте необходимость NOPASSWD для указанных пользователей/групп.",
            )
        else:
            add(
                findings,
                "info",
                "Sudoers: правил NOPASSWD не найдено",
                "",
                "",
            )

    # Проверка hosts.allow / hosts.deny
    hosts_allow = read_allowed_file("/etc/hosts.allow")
    hosts_deny = read_allowed_file("/etc/hosts.deny")

    if hosts_deny and "ALL: ALL" not in hosts_deny:
        add(
            findings,
            "low",
            "TCP Wrappers: hosts.deny не содержит правила по умолчанию",
            "Рекомендуется добавить: ALL: ALL",
            "Настройте TCP Wrappers для ограничения доступа к сервисам.",
        )
    elif hosts_deny:
        add(
            findings,
            "info",
            "TCP Wrappers: hosts.deny настроен",
            hosts_deny[:500],
            "",
        )

    if hosts_allow:
        add(
            findings,
            "info",
            "TCP Wrappers: hosts.allow правила",
            hosts_allow[:500],
            "Проверьте список разрешённых хостов.",
        )


def check_processes_and_connections(findings: List[Finding]) -> None:
    """Проверка процессов и сетевых подключений."""
    # Проверка процессов
    if shutil.which("ps"):
        res = run_cmd("processes")
        if res["ok"] and res["stdout"].strip():
            lines = res["stdout"].splitlines()
            # Ищем подозрительные процессы
            suspicious_patterns = ["nc -l", "netcat", "ncat", "/tmp/", "cryptominer", "xmrig"]
            suspicious_found = []
            for line in lines[1:]:  # Пропускаем заголовок
                for pattern in suspicious_patterns:
                    if pattern.lower() in line.lower():
                        suspicious_found.append(line)
                        break

            if suspicious_found:
                add(
                    findings,
                    "high",
                    "Обнаружены подозрительные процессы",
                    "\n".join(suspicious_found[:10]),
                    "Немедленно проверьте эти процессы. Это может быть признаком компрометации.",
                )
            else:
                add(
                    findings,
                    "info",
                    f"Процессы: всего {len(lines)-1} процессов",
                    "\n".join(lines[:30]),
                    "Проверьте на наличие необычных процессов.",
                )

    # Проверка сетевых подключений
    if shutil.which("lsof"):
        res = run_cmd("opened_files")
        if res["ok"] and res["stdout"].strip():
            lines = res["stdout"].splitlines()
            # Подсчитываем подключения
            connections = [l for l in lines if "TCP" in l or "UDP" in l]
            if len(connections) > 50:
                add(
                    findings,
                    "medium",
                    f"Много сетевых подключений ({len(connections)})",
                    "\n".join(connections[:20]),
                    "Проверьте на наличие аномальной сетевой активности.",
                )
            elif connections:
                add(
                    findings,
                    "info",
                    f"Сетевые подключения ({len(connections)})",
                    "\n".join(connections[:20]),
                    "Проверьте легитимность подключений.",
                )


def check_environment(findings: List[Finding]) -> None:
    """Проверка переменных окружения на безопасность."""
    if shutil.which("env"):
        res = run_cmd("environment_vars")
        if res["ok"] and res["stdout"].strip():
            env_vars = {}
            for line in res["stdout"].splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    env_vars[key] = value

            # Проверка PATH на опасные директории
            path = env_vars.get("PATH", "")
            if ".:" in path or path.startswith(".") or ":." in path:
                add(
                    findings,
                    "medium",
                    "PATH содержит текущую директорию (.)",
                    f"PATH={path}",
                    "Удалите '.' из PATH для предотвращения выполнения вредоносных скриптов.",
                )

            # Проверка на наличие секретов в переменных окружения
            secret_patterns = ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"]
            found_secrets = []
            for key in env_vars:
                for pattern in secret_patterns:
                    if pattern in key.upper() and env_vars[key]:
                        found_secrets.append(key)
                        break

            if found_secrets:
                add(
                    findings,
                    "medium",
                    "Обнаружены секреты в переменных окружения",
                    ", ".join(found_secrets[:10]),
                    "Рассмотрите использование secure secret management вместо переменных окружения.",
                )
            else:
                add(
                    findings,
                    "info",
                    "Переменные окружения проверены",
                    f"Всего переменных: {len(env_vars)}",
                    "",
                )


def render_markdown(meta: Dict[str, str], findings: List[Finding]) -> str:
    lines = [
        "# Отчет саб-агента безопасности сервера",
        "",
    ]

    for key, value in meta.items():
        lines.append(f"- {key}: {value}")

    lines.append("")

    for severity in ["critical", "high", "medium", "low", "info"]:
        items = [f for f in findings if f.severity == severity]
        items.sort(key=lambda x: x.title)

        if not items:
            continue

        lines.append(f"## {severity.upper()} ({len(items)})")
        lines.append("")

        for finding in items:
            lines.append(f"### {finding.title}")

            if finding.detail:
                if "\n" in finding.detail:
                    lines.append("```text")
                    lines.append(finding.detail)
                    lines.append("```")
                else:
                    lines.append(finding.detail)

            if finding.remediation:
                lines.append(f"Рекомендация: {finding.remediation}")

            lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only Linux server security monitoring agent"
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "high", "critical"],
        default="none",
        help="Exit code 2 if findings reach selected severity",
    )
    args = parser.parse_args()

    findings: List[Finding] = []
    meta = basic_meta()

    check_updates(findings)
    check_ssh(findings)
    check_listening_ports(findings)
    check_firewall(findings)
    check_failed_ssh_logins(findings)
    check_users(findings)
    check_systemd_failed(findings)
    check_fail2ban(findings)
    check_disk(findings)
    check_docker(findings)
    check_selinux_apparmor(findings)
    check_sysctl_security(findings)
    check_login_activity(findings)
    check_cron(findings)
    check_password_policy(findings)
    check_processes_and_connections(findings)
    check_environment(findings)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "meta": meta,
                    "findings": [asdict(f) for f in findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(render_markdown(meta, findings))

    if args.fail_on == "critical" and any(f.severity == "critical" for f in findings):
        sys.exit(2)

    if args.fail_on == "high" and any(
        f.severity in ("critical", "high") for f in findings
    ):
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
