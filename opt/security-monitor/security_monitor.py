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
}

ALLOWED_FILES = {
    "/etc/os-release",
    "/etc/ssh/sshd_config",
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
