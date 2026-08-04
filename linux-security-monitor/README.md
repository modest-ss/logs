# 🛡️ Linux Security Monitor Sub-Agent

**Русскоязычный субагент безопасности для мониторинга Linux-серверов**

## 📋 Описание

Автоматизированный инструмент мониторинга безопасности, который:
- **Сканирует систему** на предмет угроз и уязвимостей
- **Фильтрует события** — только CRITICAL и HIGH уровень
- **Защищает от спама** — дедупликация, ежедневные сводки
- **Идентифицирует сервер** — hostname и IP в каждом отчете
- **Работает в режиме read-only** — не изменяет систему

## 🔑 Ключевые особенности

### 1. Anti-Spam система
- ✅ Дедупликация событий (окно 24 часа)
- ✅ Подавление чистых отчетов (если проблем нет)
- ✅ Rate limiting (макс. 1 дайджест в день)
- ✅ Hash-based сравнение находок

### 2. Идентификация сервера
Каждый отчет содержит:
- `server_hostname` — имя сервера
- `server_ip` — список IP адресов
- `timestamp` — время проверки

### 3. Ежедневный режим
- Запуск по cron один раз в сутки (рекомендуется 06:00 UTC)
- Автоматическая генерация сводки
- Интеграция с Hermes и OpenClaw

### 4. Полное покрытие портов
- Мониторинг **всех** слушающих портов (TCP/UDP, IPv4/IPv6)
- Детекция новых открытых портов
- Детекция закрытых портов
- Проверка на подозрительные порты (4444, 31337, 6666, etc.)

## 🚀 Быстрый старт

### Установка

```bash
# Клонируйте репозиторий
git clone <repository_url>
cd linux-security-monitor

# Сделайте скрипт исполняемым
chmod +x security_monitor.py

# Опционально: установите в систему
sudo mkdir -p /opt/security-monitor
sudo cp security_monitor.py /opt/security-monitor/
sudo chmod +x /opt/security-monitor/security_monitor.py
```

### Использование

```bash
# Ручная проверка (Markdown)
python3 security_monitor.py --format markdown

# JSON вывод (для интеграции)
python3 security_monitor.py --format json

# Ежедневная сводка
python3 security_monitor.py --daily-summary --format json

# Принудительный запуск (без anti-spam)
python3 security_monitor.py --force --format markdown

# Exit code 2 при critical проблемах
python3 security_monitor.py --fail-on critical
```

### Настройка cron

```bash
# Откройте crontab
crontab -e

# Добавьте ежедневный запуск в 06:00 UTC
0 6 * * * /opt/security-monitor/security_monitor.py --daily-summary --format json >> /var/log/security-daily.json 2>&1
```

## 📊 Проверки безопасности

### Критические (CRITICAL)
| Проверка | Описание |
|----------|----------|
| `ssh_empty_passwords` | SSH разрешает вход с пустыми паролями |
| `ssh_protocol_v1` | Используется устаревший Protocol 1 |
| `non_root_uid_zero` | Пользователь ≠ root имеет UID 0 |
| `suspicious_port` | Обнаружен подозрительный порт (4444, 31337...) |
| `suspicious_process` | Найден процесс майнера/backdoor |

### Высокие (HIGH)
| Проверка | Описание |
|----------|----------|
| `ssh_root_login` | Прямой вход root разрешен |
| `ssh_password_auth` | Аутентификация по паролю включена |
| `firewall_disabled` | Файрвол (UFW/nftables/iptables) отключен |
| `brute_force_detected` | >10 неудачных попыток входа за час |
| `systemd_failed` | Сервис systemd в состоянии failed |
| `disk_critical` | Диск заполнен ≥90% |
| `disk_warning` | Диск заполнен ≥80% |
| `selinux_disabled` | SELinux отключен |
| `selinux_permissive` | SELinux в режиме Permissive |
| `suspicious_cron` | Подозрительное cron задание |
| `secret_in_env` | Секреты в переменных окружения |
| `oom_killer` | OOM Killer активирован |
| `zombie_processes` | >5 zombie процессов |
| `promiscuous_mode` | Сетевой интерфейс в promiscuous mode |
| `auditd_inactive` | Служба auditd не активна |
| `startup_failure` | Сервис не запустился при загрузке |
| `inode_critical` | Isчерпание inode ≥90% |
| `time_jump_detected` | Скачок системного времени |
| `network_errors` | Сетевые ошибки (packet loss) |
| `new_port_opened` | Открыт новый публичный порт |
| `package_updates` | Доступны обновления безопасности |

## 🔧 Интеграция

### Hermes

```bash
# Импорт агента
hermes import-agent ./hermes-agent-card.json

# Конфигурация включает:
# - daily_summary режим
# - severity_filter: [critical, high]
# - server_identification
# - anti_spam настройки
```

### OpenClaw

```bash
# Импорт агента
openclaw agent import ./openclaw-agent-card.json

# Конфигурация включает:
# - schedule: daily at 06:00 UTC
# - alerting для critical/high
# - шаблоны с {server.hostname}
```

## 📁 Структура проекта

```
linux-security-monitor/
├── security_monitor.py      # Основной скрипт
├── hermes-agent-card.json   # Конфигурация для Hermes
├── openclaw-agent-card.json # Конфигурация для OpenClaw
└── README.md                # Эта документация
```

## 🛡️ Anti-Spam логика

### Дедупликация
- Каждая находка хешируется (check + severity + summary + details)
- Хеш сохраняется в `/var/lib/security-monitor/findings_cache.json`
- Повторяющиеся находки игнорируются 24 часа

### Подача чистых отчетов
- Если проблем не найдено (`status: clean`), отчет не отправляется
- Исключение: принудительный запуск с `--force`

### Rate Limiting
- Максимум 1 дайджест в день
- Максимум 5 алертов в час для critical событий

## 📤 Формат отчета

### JSON
```json
{
  "timestamp": "2025-01-15T06:00:00Z",
  "mode": "critical_high_only",
  "schedule": "daily",
  "server_hostname": "prod-server-01",
  "server_ip": ["192.168.1.100", "10.0.0.5"],
  "total_findings": 3,
  "critical_count": 1,
  "high_count": 2,
  "status": "issues_found",
  "findings": [...]
}
```

### Markdown
```markdown
# 🛡️ Отчет Security Monitor

**Сервер:** prod-server-01 (192.168.1.100, 10.0.0.5)
**Время:** 2025-01-15T06:00:00Z
**Статус:** ⚠️ Найдены проблемы

## Сводка
- **Всего проблем:** 3
- **Critical:** 1
- **High:** 2

## Детали

### 1. 🔴 [CRITICAL] SSH разрешает вход с пустыми паролями
- **Проверка:** ssh_empty_passwords
- **Детали:** Конфигурация: PermitEmptyPasswords yes
- **Решение:** Установите PermitEmptyPasswords no в /etc/ssh/sshd_config
```

## 🔒 Безопасность

- **Read-only режим**: Агент только читает данные, не модифицирует систему
- **Нет сетевых подключений**: Все проверки локальные
- **Нет передачи секретов**: Чувствительные данные не выводятся
- **Песочница**: Рекомендуется запускать в sandboxed среде

## 📝 Требования

- Python 3.6+
- Linux (Debian, Ubuntu, CentOS, RHEL, Fedora)
- Root или sudo доступ для некоторых проверок
- Зависимости:
  - `ss` (iproute2)
  - `systemctl` (systemd)
  - `journalctl` (systemd)
  - Опционально: ufw, nftables, iptables, auditd

## 📄 Лицензия

MIT License

## 👥 Авторы

Security Team для русскоязычного сообщества
