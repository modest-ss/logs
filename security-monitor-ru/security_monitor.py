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

import argparse
import json
import os
import re
import subprocess
import sys
import socket
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

# Конфигурация уровней серьезности
SEVERITY_LEVELS = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
    'info': 0
}

# Фильтр: показываем только critical и high
REPORT_FILTER = ['critical', 'high']

# Пути для хранения состояния
STATE_DIR = Path('/var/log/security-monitor')
STATE_FILE = STATE_DIR / 'last_report.json'
DEDUP_WINDOW_HOURS = 24


def run_command(cmd: List[str], timeout: int = 10) -> Tuple[str, str, int]:
    """Выполняет команду и возвращает stdout, stderr и код возврата."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1


def get_server_info() -> Dict[str, str]:
    """Получает информацию о сервере для идентификации в отчетах."""
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    
    # Получаем IP адреса
    ip_addresses = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip not in ['127.0.0.1', '::1'] and ip not in ip_addresses:
                ip_addresses.append(ip)
    except Exception:
        pass
    
    # Генерируем уникальный ID сервера
    server_id = hashlib.md5(f"{hostname}{fqdn}".encode()).hexdigest()[:8]
    
    return {
        'hostname': hostname,
        'fqdn': fqdn,
        'ip_addresses': ip_addresses,
        'server_id': f"srv-{server_id}"
    }


def should_skip_report(findings: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """
    Проверяет, нужно ли пропустить отчет из-за anti-spam правил.
    Возвращает (should_skip, reason).
    """
    # Если нет находок - всегда пропускаем (нет новостей)
    if not findings:
        return True, "no_issues_found"
    
    # Создаем хеш текущих находок для deduplication
    current_hash = hashlib.md5(
        json.dumps(sorted([f['summary'] for f in findings]), sort_keys=True).encode()
    ).hexdigest()
    
    # Проверяем предыдущий отчет
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, 'r') as f:
                last_report = json.load(f)
            
            last_time = datetime.fromisoformat(last_report.get('timestamp', ''))
            time_diff = datetime.now() - last_time
            
            # Если прошло меньше 24 часов и находки те же - пропускаем
            if time_diff.total_seconds() < DEDUP_WINDOW_HOURS * 3600:
                last_hash = last_report.get('findings_hash', '')
                if last_hash == current_hash:
                    return True, "duplicate_within_window"
                
                # Если в прошлом отчете не было critical, а сейчас тоже нет - можно пропустить
                if (last_report.get('critical_count', 0) == 0 and 
                    sum(1 for f in findings if f['severity'] == 'critical') == 0):
                    # Проверяем, изменились ли находки значительно
                    last_findings = set(last_report.get('finding_summaries', []))
                    current_findings = set(f['summary'] for f in findings)
                    
                    # Если 80%+ находок совпадают - пропускаем
                    if last_findings and current_findings:
                        overlap = len(last_findings & current_findings) / max(len(last_findings), len(current_findings))
                        if overlap > 0.8:
                            return True, "minimal_changes"
        except Exception:
            pass  # Игнорируем ошибки чтения состояния
    
    return False, "send_report"


def save_report_state(findings: List[Dict[str, Any]], server_info: Dict[str, str]):
    """Сохраняет состояние отчета для future deduplication."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        
        state = {
            'timestamp': datetime.now().isoformat(),
            'server_id': server_info['server_id'],
            'hostname': server_info['hostname'],
            'findings_hash': hashlib.md5(
                json.dumps(sorted([f['summary'] for f in findings]), sort_keys=True).encode()
            ).hexdigest(),
            'finding_summaries': [f['summary'] for f in findings],
            'critical_count': sum(1 for f in findings if f['severity'] == 'critical'),
            'high_count': sum(1 for f in findings if f['severity'] == 'high')
        }
        
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save state: {e}", file=sys.stderr)


def check_updates() -> List[Dict[str, Any]]:
    """Проверяет доступные обновления пакетов."""
    findings = []
    
    # Проверка для Debian/Ubuntu
    stdout, _, rc = run_command(['apt', 'list', '--upgradable'])
    if rc == 0 and stdout.strip():
        lines = stdout.strip().split('\n')
        # Пропускаем заголовок
        if len(lines) > 1:
            count = len(lines) - 1
            # Обновления считаются HIGH только если их много (>50) или есть security обновления
            findings.append({
                'check': 'system_updates',
                'severity': 'high' if count > 50 else 'medium',
                'summary': f'Доступно обновлений пакетов: {count}',
                'details': 'Рекомендуется выполнить обновление системы',
                'remediation': 'sudo apt update && sudo apt upgrade -y'
            })
    
    # Проверка для RHEL/CentOS
    stdout, _, rc = run_command(['dnf', 'check-update', '--quiet'])
    if rc == 100 and stdout.strip():  # DNF возвращает 100 если есть обновления
        lines = [l for l in stdout.strip().split('\n') if l.strip()]
        count = len(lines) // 3  # Примерная оценка
        findings.append({
            'check': 'system_updates',
            'severity': 'high' if count > 50 else 'medium',
            'summary': f'Доступно обновлений пакетов (DNF): ~{count}',
            'details': 'Рекомендуется выполнить обновление системы',
            'remediation': 'sudo dnf upgrade -y'
        })
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_ssh() -> List[Dict[str, Any]]:
    """Аудит конфигурации SSH."""
    findings = []
    ssh_config_path = '/etc/ssh/sshd_config'
    
    if not os.path.exists(ssh_config_path):
        return findings
    
    try:
        with open(ssh_config_path, 'r') as f:
            config_content = f.read()
    except Exception:
        return findings
    
    issues = {
        'PermitEmptyPasswords yes': ('critical', 'Разрешены пустые пароли SSH'),
        'Protocol 1': ('critical', 'Используется устаревший SSH Protocol 1'),
        'PermitRootLogin yes': ('high', 'Разрешен прямой вход root по SSH'),
        'PasswordAuthentication yes': ('medium', 'Разрешена парольная аутентификация SSH'),
        'X11Forwarding yes': ('low', 'Включена X11 переадресация'),
        'MaxAuthTries': ('low', 'Слишком много попыток аутентификации'),
    }
    
    for pattern, (severity, message) in issues.items():
        if severity not in REPORT_FILTER:
            continue
        if pattern in config_content:
            if pattern == 'MaxAuthTries':
                match = re.search(r'MaxAuthTries\s+(\d+)', config_content)
                if match and int(match.group(1)) > 5:
                    findings.append({
                        'check': 'ssh_config',
                        'severity': severity,
                        'summary': message,
                        'details': f'Найдено: MaxAuthTries {match.group(1)}',
                        'remediation': 'Установите MaxAuthTries 3-5 в /etc/ssh/sshd_config'
                    })
            else:
                findings.append({
                    'check': 'ssh_config',
                    'severity': severity,
                    'summary': message,
                    'details': f'Найдено: {pattern}',
                    'remediation': f'Измените настройку в {ssh_config_path}'
                })
    
    return findings


def check_firewall() -> List[Dict[str, Any]]:
    """Проверяет статус файрвола."""
    findings = []
    
    # Проверка UFW
    stdout, _, rc = run_command(['ufw', 'status'])
    if rc == 0 and 'inactive' in stdout.lower():
        findings.append({
            'check': 'firewall',
            'severity': 'high',
            'summary': 'Файрвол UFW отключен',
            'details': 'Система не защищена межсетевым экраном',
            'remediation': 'sudo ufw enable'
        })
    
    # Проверка nftables
    stdout, _, rc = run_command(['nft', 'list', 'ruleset'])
    if rc == 0 and not stdout.strip():
        findings.append({
            'check': 'firewall',
            'severity': 'high',
            'summary': 'Правила nftables отсутствуют',
            'details': 'Файрвол nftables не настроен',
            'remediation': 'Настройте правила nftables'
        })
    
    # Проверка iptables (если нет nftables/ufw)
    stdout, _, rc = run_command(['iptables', '-L', '-n'])
    if rc == 0:
        lines = stdout.strip().split('\n')
        # Если только заголовки без правил
        if len(lines) <= 6:
            findings.append({
                'check': 'firewall',
                'severity': 'high',
                'summary': 'Правила iptables отсутствуют или минимальны',
                'details': 'Файрвол iptables не настроен должным образом',
                'remediation': 'Настройте правила iptables'
            })
    
    return findings


def check_listening_ports() -> List[Dict[str, Any]]:
    """Проверяет слушающие порты."""
    findings = []
    
    stdout, _, rc = run_command(['ss', '-Htuln'])
    if rc != 0:
        return findings
    
    public_ports = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 5:
            local_addr = parts[4]
            if local_addr.startswith('0.0.0.0:') or local_addr.startswith('[::]:') or local_addr.startswith('*:'):
                port = local_addr.split(':')[-1]
                public_ports.append(port)
    
    if public_ports:
        findings.append({
            'check': 'listening_ports',
            'severity': 'high' if len(public_ports) > 5 else 'medium',
            'summary': f'Обнаружено {len(public_ports)} публичных слушающих портов',
            'details': f'Порты: {", ".join(public_ports)}',
            'remediation': 'Проверьте необходимость каждого открытого порта и закройте лишние'
        })
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_failed_ssh_logins() -> List[Dict[str, Any]]:
    """Проверяет неудачные попытки входа по SSH."""
    findings = []
    
    # Попытка через journalctl
    stdout, _, rc = run_command(['journalctl', '-u', 'sshd', '--since', '24 hours ago', '--no-pager'])
    failed_count = 0
    
    if rc == 0:
        failed_count = stdout.lower().count('failed') + stdout.lower().count('invalid')
    
    # Если journalctl не сработал, пробуем auth.log
    if failed_count == 0:
        auth_logs = ['/var/log/auth.log', '/var/log/secure']
        for log_path in auth_logs:
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r') as f:
                        content = f.read()
                        failed_count += content.lower().count('failed password')
                        failed_count += content.lower().count('invalid user')
                except Exception:
                    pass
    
    if failed_count > 100:
        findings.append({
            'check': 'failed_ssh_logins',
            'severity': 'high',
            'summary': f'Обнаружено {failed_count} неудачных попыток входа за 24 часа',
            'details': 'Возможная атака методом перебора',
            'remediation': 'Рассмотрите установку fail2ban и проверку логов'
        })
    elif failed_count > 50:
        findings.append({
            'check': 'failed_ssh_logins',
            'severity': 'medium',
            'summary': f'Обнаружено {failed_count} неудачных попыток входа за 24 часа',
            'details': 'Повышенная активность неудачных входов',
            'remediation': 'Проверьте логи и рассмотрите установку fail2ban'
        })
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_users() -> List[Dict[str, Any]]:
    """Проверяет пользователей с привилегиями."""
    findings = []
    
    # Проверка пользователей с UID 0
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    uid = parts[2]
                    if uid == '0' and username != 'root':
                        findings.append({
                            'check': 'privileged_users',
                            'severity': 'critical',
                            'summary': f'Пользователь {username} имеет UID 0',
                            'details': 'Нерoot пользователь с правами суперпользователя',
                            'remediation': f'Проверьте необходимость прав для {username} и измените UID'
                        })
    except Exception:
        pass
    
    # Проверка групп sudo/wheel
    for group in ['sudo', 'wheel']:
        stdout, _, rc = run_command(['getent', 'group', group])
        if rc == 0 and stdout.strip():
            members = stdout.strip().split(':')[3].split(',')
            non_root_members = [m for m in members if m and m != 'root']
            if non_root_members:
                findings.append({
                    'check': 'privileged_users',
                    'severity': 'medium',
                    'summary': f'Члены группы {group}: {", ".join(non_root_members)}',
                    'details': 'Пользователи с правами sudo',
                    'remediation': 'Проверьте актуальность членства в группе'
                })
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_systemd_failed() -> List[Dict[str, Any]]:
    """Проверяет упавшие systemd сервисы."""
    findings = []
    
    stdout, _, rc = run_command(['systemctl', 'list-units', '--failed', '--no-pager'])
    if rc == 0 and stdout.strip():
        lines = stdout.strip().split('\n')
        # Пропускаем заголовок и итог
        failed_units = [l for l in lines if l.strip() and not l.startswith('UNIT') and not l.startswith('loaded')]
        
        if failed_units:
            unit_names = [l.split()[0] for l in failed_units if l.split()]
            findings.append({
                'check': 'systemd_failed',
                'severity': 'high',
                'summary': f'Упавшие systemd сервисы: {len(unit_names)}',
                'details': f'Сервисы: {", ".join(unit_names[:5])}' + ('...' if len(unit_names) > 5 else ''),
                'remediation': 'Проверьте логи сервисов: journalctl -u <service_name>'
            })
    
    return findings


def check_fail2ban() -> List[Dict[str, Any]]:
    """Проверяет статус fail2ban."""
    findings = []
    
    stdout, _, rc = run_command(['systemctl', 'is-active', 'fail2ban'])
    if rc == 0 and stdout.strip() == 'inactive':
        findings.append({
            'check': 'fail2ban',
            'severity': 'medium',
            'summary': 'Fail2ban не активен',
            'details': 'Система не защищена от brute-force атак',
            'remediation': 'sudo systemctl enable --now fail2ban'
        })
    elif rc != 0:
        findings.append({
            'check': 'fail2ban',
            'severity': 'medium',
            'summary': 'Fail2ban не установлен',
            'details': 'Рекомендуется установить для защиты от перебора',
            'remediation': 'sudo apt install fail2ban || sudo dnf install fail2ban'
        })
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_disk() -> List[Dict[str, Any]]:
    """Проверяет заполненность дисков."""
    findings = []
    
    stdout, _, rc = run_command(['df', '-h'])
    if rc != 0:
        return findings
    
    for line in stdout.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 5:
            usage_str = parts[4].replace('%', '')
            try:
                usage = int(usage_str)
                mount = parts[5]
                
                if usage >= 90:
                    findings.append({
                        'check': 'disk_usage',
                        'severity': 'high',
                        'summary': f'Критическая заполненность диска {mount}: {usage}%',
                        'details': 'Требуется немедленное освобождение места',
                        'remediation': 'Очистите логи, временные файлы или расширьте диск'
                    })
                elif usage >= 80:
                    findings.append({
                        'check': 'disk_usage',
                        'severity': 'medium',
                        'summary': f'Высокая заполненность диска {mount}: {usage}%',
                        'details': 'Рекомендуется планировать очистку',
                        'remediation': 'Проанализируйте использование диска'
                    })
            except ValueError:
                continue
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_docker() -> List[Dict[str, Any]]:
    """Проверяет запущенные Docker контейнеры."""
    findings = []
    
    stdout, _, rc = run_command(['docker', 'ps', '--format', '{{.Names}}: {{.Status}}'])
    if rc == 0 and stdout.strip():
        containers = stdout.strip().split('\n')
        findings.append({
            'check': 'docker_containers',
            'severity': 'medium',
            'summary': f'Запущено Docker контейнеров: {len(containers)}',
            'details': ', '.join(containers[:5]) + ('...' if len(containers) > 5 else ''),
            'remediation': 'Проверьте актуальность и безопасность контейнеров'
        })
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_selinux_apparmor() -> List[Dict[str, Any]]:
    """Проверяет статус SELinux или AppArmor."""
    findings = []
    
    # Проверка SELinux
    stdout, _, rc = run_command(['getenforce'])
    if rc == 0:
        status = stdout.strip().lower()
        if status == 'disabled':
            findings.append({
                'check': 'selinux',
                'severity': 'high',
                'summary': 'SELinux отключен',
                'details': 'Система не защищена мандатным контролем доступа',
                'remediation': 'Включите SELinux: setenforce 1 и настройте /etc/selinux/config'
            })
        elif status == 'permissive':
            findings.append({
                'check': 'selinux',
                'severity': 'medium',
                'summary': 'SELinux в режиме Permissive',
                'details': 'Нарушения логируются но не блокируются',
                'remediation': 'Переключите в режим Enforcing после устранения нарушений'
            })
    
    # Проверка AppArmor (если SELinux не найден)
    if rc != 0:
        stdout, _, rc = run_command(['aa-status'])
        if rc == 0:
            if 'profiles are in complain mode' in stdout:
                findings.append({
                    'check': 'apparmor',
                    'severity': 'medium',
                    'summary': 'AppArmor профили в режиме жалоб',
                    'details': 'Нарушения логируются но не блокируются',
                    'remediation': 'Переведите профили в режим enforcement'
                })
    
    return findings


def check_sysctl_params() -> List[Dict[str, Any]]:
    """Проверяет важные sysctl параметры безопасности."""
    findings = []
    
    params = {
        'net.ipv4.ip_forward': ('high', 'IP пересылка включена'),
        'net.ipv4.conf.all.accept_source_route': ('high', 'Принятие source-routed пакетов'),
        'net.ipv4.icmp_echo_ignore_broadcasts': ('medium', 'ICMP broadcast эхо не игнорируется'),
        'kernel.randomize_va_space': ('high', 'ASLR отключен'),
    }
    
    for param, (severity, message) in params.items():
        if severity not in REPORT_FILTER:
            continue
        
        stdout, _, rc = run_command(['sysctl', '-n', param])
        if rc == 0:
            value = stdout.strip()
            # Ожидаемые безопасные значения: 0 для отключения функций, 2 для ASLR
            expected = '0' if 'accept_source_route' in param or 'ip_forward' in param or 'echo_ignore' in param else '2'
            
            if param == 'net.ipv4.icmp_echo_ignore_broadcasts' and value == '0':
                findings.append({
                    'check': 'sysctl',
                    'severity': severity,
                    'summary': message,
                    'details': f'{param} = {value}',
                    'remediation': f'sudo sysctl -w {param}=1'
                })
            elif param != 'net.ipv4.icmp_echo_ignore_broadcasts' and value != expected:
                findings.append({
                    'check': 'sysctl',
                    'severity': severity,
                    'summary': message,
                    'details': f'{param} = {value}',
                    'remediation': f'sudo sysctl -w {param}={expected}'
                })
    
    return findings


def check_login_activity() -> List[Dict[str, Any]]:
    """Проверяет недавнюю активность входов."""
    findings = []
    
    stdout, _, rc = run_command(['last', '-n', '20'])
    if rc == 0 and stdout.strip():
        # Ищем подозрительные паттерны
        lines = stdout.strip().split('\n')
        suspicious = []
        
        for line in lines:
            if 'still logged in' in line.lower() and len(line) > 100:
                suspicious.append('Длительная сессия')
            if 'reboot' in line.lower():
                suspicious.append('Перезагрузка системы')
        
        if len(suspicious) > 5:
            findings.append({
                'check': 'login_activity',
                'severity': 'medium',
                'summary': 'Подозрительная активность входов',
                'details': f'Найдено аномалий: {len(suspicious)}',
                'remediation': 'Проверьте вывод команды last и авторизованные сессии'
            })
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_cron_jobs() -> List[Dict[str, Any]]:
    """Проверяет cron задания."""
    findings = []
    
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly']
    suspicious_patterns = ['curl', 'wget', 'nc ', 'netcat', 'bash -i', '/dev/tcp', 'base64']
    
    suspicious_found = []
    
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            for filename in os.listdir(cron_dir):
                filepath = os.path.join(cron_dir, filename)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read().lower()
                            for pattern in suspicious_patterns:
                                if pattern in content:
                                    suspicious_found.append(f'{filepath}: {pattern}')
                    except Exception:
                        pass
    
    # Проверка crontab root
    stdout, _, rc = run_command(['crontab', '-l'])
    if rc == 0 and stdout.strip():
        content = stdout.lower()
        for pattern in suspicious_patterns:
            if pattern in content:
                suspicious_found.append(f'root crontab: {pattern}')
    
    if suspicious_found:
        findings.append({
            'check': 'cron_jobs',
            'severity': 'high',
            'summary': f'Подозрительные cron задания: {len(suspicious_found)}',
            'details': '; '.join(suspicious_found[:5]),
            'remediation': 'Проверьте легитимность заданий и удалите вредоносные'
        })
    
    return findings


def check_password_policy() -> List[Dict[str, Any]]:
    """Проверяет политику паролей."""
    findings = []
    
    login_defs_path = '/etc/login.defs'
    if os.path.exists(login_defs_path):
        try:
            with open(login_defs_path, 'r') as f:
                content = f.read()
                
                # Проверка PASS_MAX_DAYS
                match = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                if match:
                    max_days = int(match.group(1))
                    if max_days > 90 or max_days == -1:
                        findings.append({
                            'check': 'password_policy',
                            'severity': 'high',
                            'summary': 'Срок действия пароля не установлен или слишком долгий',
                            'details': f'PASS_MAX_DAYS = {max_days}',
                            'remediation': 'Установите PASS_MAX_DAYS 60-90 в /etc/login.defs'
                        })
                
                # Проверка PASS_MIN_LEN
                match = re.search(r'PASS_MIN_LEN\s+(\d+)', content)
                if match:
                    min_len = int(match.group(1))
                    if min_len < 8:
                        findings.append({
                            'check': 'password_policy',
                            'severity': 'high',
                            'summary': 'Минимальная длина пароля слишком мала',
                            'details': f'PASS_MIN_LEN = {min_len}',
                            'remediation': 'Установите PASS_MIN_LEN 12 в /etc/login.defs'
                        })
        except Exception:
            pass
    
    return [f for f in findings if f['severity'] in REPORT_FILTER]


def check_processes_connections() -> List[Dict[str, Any]]:
    """Проверяет процессы и сетевые подключения."""
    findings = []
    
    stdout, _, rc = run_command(['ss', '-tunap'])
    if rc == 0 and stdout.strip():
        lines = stdout.strip().split('\n')
        suspicious_ports = ['4444', '5555', '6666', '31337', '12345']
        suspicious_found = []
        
        for line in lines:
            for port in suspicious_ports:
                if f':{port}' in line:
                    suspicious_found.append(f'Подозрительный порт {port}')
        
        if suspicious_found:
            findings.append({
                'check': 'processes_connections',
                'severity': 'critical',
                'summary': 'Обнаружены подозрительные сетевые подключения',
                'details': '; '.join(suspicious_found),
                'remediation': 'Немедленно проверьте процессы и изолируйте систему'
            })
    
    return findings


def check_env_vars() -> List[Dict[str, Any]]:
    """Проверяет переменные окружения на наличие секретов."""
    findings = []
    
    # Проверяем только ключевые переменные в /etc/environment и профилях
    env_files = ['/etc/environment', '/etc/profile', '~/.bashrc', '~/.profile']
    secret_patterns = ['PASSWORD', 'SECRET', 'API_KEY', 'PRIVATE_KEY', 'TOKEN']
    
    secrets_found = []
    
    for env_file in env_files:
        filepath = os.path.expanduser(env_file)
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                    for pattern in secret_patterns:
                        if pattern in content.upper() and '=' in content:
                            lines = content.split('\n')
                            for line in lines:
                                if pattern in line.upper() and '=' in line and not line.strip().startswith('#'):
                                    secrets_found.append(f'{filepath}: содержит {pattern}')
            except Exception:
                pass
    
    if secrets_found:
        findings.append({
            'check': 'env_vars',
            'severity': 'high',
            'summary': f'Возможные секреты в переменных окружения: {len(secrets_found)}',
            'details': '; '.join(secrets_found[:5]),
            'remediation': 'Используйте менеджеры секретов вместо хардкода в файлах'
        })
    
    return findings


def run_all_checks() -> List[Dict[str, Any]]:
    """Запускает все проверки и возвращает отфильтрованные результаты."""
    all_findings = []
    
    checks = [
        check_updates,
        check_ssh,
        check_firewall,
        check_listening_ports,
        check_failed_ssh_logins,
        check_users,
        check_systemd_failed,
        check_fail2ban,
        check_disk,
        check_docker,
        check_selinux_apparmor,
        check_sysctl_params,
        check_login_activity,
        check_cron_jobs,
        check_password_policy,
        check_processes_connections,
        check_env_vars,
    ]
    
    for check_func in checks:
        try:
            findings = check_func()
            all_findings.extend(findings)
        except Exception as e:
            all_findings.append({
                'check': check_func.__name__,
                'severity': 'medium',
                'summary': f'Ошибка выполнения проверки: {str(e)}',
                'details': 'Проверка не была выполнена полностью',
                'remediation': 'Проверьте права доступа и зависимости'
            })
    
    # Сортировка по серьезности
    all_findings.sort(key=lambda x: SEVERITY_LEVELS.get(x['severity'], 0), reverse=True)
    
    return all_findings


def generate_markdown_report(findings: List[Dict[str, Any]], server_info: Dict[str, str]) -> str:
    """Генерирует отчет в формате Markdown с информацией о сервере."""
    report = []
    report.append("# 🛡️ Отчет Linux Security Monitor")
    report.append(f"**Дата:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Сервер:** {server_info['hostname']} ({server_info['server_id']})")
    if server_info['ip_addresses']:
        report.append(f"**IP адреса:** {', '.join(server_info['ip_addresses'])}")
    report.append(f"**Режим:** Только критические и опасные события (Critical/High)")
    report.append("")
    
    if not findings:
        report.append("## ✅ Статус: Угроз не обнаружено")
        report.append("")
        report.append("Система не имеет критических или высоких угроз безопасности на момент проверки.")
        report.append("")
        report.append("---")
        report.append("*Следующий запланированный отчет: через 24 часа*")
    else:
        critical_count = sum(1 for f in findings if f['severity'] == 'critical')
        high_count = sum(1 for f in findings if f['severity'] == 'high')
        
        report.append(f"## ⚠️ Обнаружено угроз: {len(findings)}")
        report.append(f"- 🔴 Критические (Critical): {critical_count}")
        report.append(f"- 🟠 Высокие (High): {high_count}")
        report.append("")
        
        for i, finding in enumerate(findings, 1):
            severity_emoji = {'critical': '🔴', 'high': '🟠'}.get(finding['severity'], '⚪')
            report.append(f"### {i}. {severity_emoji} [{finding['severity'].upper()}] {finding['check']}")
            report.append(f"**Проблема:** {finding['summary']}")
            report.append(f"**Детали:** {finding['details']}")
            report.append(f"**Рекомендация:** {finding['remediation']}")
            report.append("")
        
        report.append("---")
        report.append("*Рекомендуется немедленно устранить критические проблемы.*")
    
    return '\n'.join(report)


def generate_json_report(findings: List[Dict[str, Any]], server_info: Dict[str, str], skip_reason: str = None) -> str:
    """Генерирует отчет в формате JSON с информацией о сервере."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'mode': 'critical_high_only',
        'schedule': 'daily',
        'server': server_info,
        'total_findings': len(findings),
        'critical_count': sum(1 for f in findings if f['severity'] == 'critical'),
        'high_count': sum(1 for f in findings if f['severity'] == 'high'),
        'findings': findings,
        'status': 'clean' if not findings else 'issues_found'
    }
    
    if skip_reason:
        report['skipped'] = True
        report['skip_reason'] = skip_reason
    
    return json.dumps(report, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(
        description='Linux Security Monitor Sub-Agent (только Critical/High, ежедневный отчет)'
    )
    parser.add_argument(
        '--format',
        choices=['markdown', 'json'],
        default='markdown',
        help='Формат вывода отчета (по умолчанию: markdown)'
    )
    parser.add_argument(
        '--fail-on',
        choices=['critical', 'high', 'any'],
        default=None,
        help='Код возврата при обнаружении проблем указанной серьезности'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Путь к файлу для сохранения отчета'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Принудительный запуск без anti-spam проверок'
    )
    parser.add_argument(
        '--daily-summary',
        action='store_true',
        help='Режим ежедневной сводки с anti-spam логикой'
    )
    
    args = parser.parse_args()
    
    # Получаем информацию о сервере
    server_info = get_server_info()
    
    # Запуск всех проверок
    findings = run_all_checks()
    
    # Anti-spam логика (если включена)
    skip_reason = None
    if not args.force and (args.daily_summary or True):  # По умолчанию всегда включено
        should_skip, reason = should_skip_report(findings)
        if should_skip:
            skip_reason = reason
            # Даже если пропускаем, генерируем короткий отчет
            findings = []  # Пустой список означает "нет новых проблем"
    
    # Сохраняем состояние (если не force режим)
    if not args.force:
        save_report_state(findings if not skip_reason else [], server_info)
    
    # Генерация отчета
    if args.format == 'json':
        report = generate_json_report(findings, server_info, skip_reason)
    else:
        report = generate_markdown_report(findings, server_info)
    
    # Вывод или сохранение
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Отчет сохранен в {args.output}")
    else:
        print(report)
    
    # Определение кода возврата
    exit_code = 0
    if args.fail_on:
        critical_exists = any(f['severity'] == 'critical' for f in findings)
        high_exists = any(f['severity'] == 'high' for f in findings)
        any_exists = len(findings) > 0
        
        if args.fail_on == 'critical' and critical_exists:
            exit_code = 2
        elif args.fail_on == 'high' and (critical_exists or high_exists):
            exit_code = 2
        elif args.fail_on == 'any' and any_exists:
            exit_code = 1
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
