# 🛡️ Linux Security Monitor Sub-Agent (Русская версия)

**Режим работы:** Только критические и опасные события  
**Частота отчетов:** Один раз в день (Daily Summary)  
**Идентификация сервера:** Включена (hostname, server_id, IP)  
**Anti-spam:** Включен (дедупликация, подавление повторов)  
**Язык:** Русский

## Описание

Агент безопасности для мониторинга Linux-серверов, разработанный специально для интеграции с Hermes и OpenClaw. 

### Ключевые особенности

✅ **Без спама** — показывает только проблемы уровня `CRITICAL` и `HIGH`  
✅ **Ежедневный отчет** — сводка один раз в 24 часа  
✅ **Идентификация сервера** — каждый отчет содержит hostname, server_id и IP адреса  
✅ **Дедупликация** — одинаковые проблемы не дублируются в течение 24 часов  
✅ **Подавление чистых отчетов** — если проблем нет, отчет не отправляется  
✅ **Только чтение** — не вносит изменений в систему  
✅ **Готов к интеграции** — конфигурации для Hermes и OpenClaw включены

## Проверки безопасности

Агент выполняет 17 проверок:

| # | Проверка | Уровень угроз |
|---|----------|---------------|
| 1 | Обновления пакетов (>50) | HIGH |
| 2 | Конфигурация SSH (пустые пароли, root login) | CRITICAL/HIGH |
| 3 | Статус файрвола (UFW/nftables/iptables) | HIGH |
| 4 | Публичные слушающие порты (>5) | HIGH |
| 5 | Неудачные SSH входы (>100 за 24ч) | HIGH |
| 6 | Пользователи с UID 0 (не root) | CRITICAL |
| 7 | Упавшие systemd сервисы | HIGH |
| 8 | SELinux/AppArmor статус | HIGH |
| 9 | Sysctl параметры безопасности | HIGH |
| 10 | Подозрительные cron задания | HIGH |
| 11 | Заполненность диска (≥90%) | HIGH |
| 12 | Подозрительные сетевые порты | CRITICAL |
| 13 | Секреты в переменных окружения | HIGH |
| 14-17 | Дополнительные проверки | MEDIUM+ (фильтруются) |

## Установка

```bash
# Скопируйте агент на сервер
scp security_monitor.py user@server:/opt/security-monitor/

# Сделайте исполняемым
chmod +x /opt/security-monitor/security_monitor.py
```

## Использование

### Базовый запуск (Markdown отчет)
```bash
python3 security_monitor.py
```

### JSON формат (для интеграции)
```bash
python3 security_monitor.py --format json
```

### Сохранение отчета в файл
```bash
python3 security_monitor.py --output /var/log/security-report.md
```

### Режим CI/CD (код возврата при ошибках)
```bash
# Вернуть код 2 при critical проблемах
python3 security_monitor.py --fail-on critical
echo $?  # 0 = чисто, 2 = критические проблемы
```

## Интеграция с Hermes

```bash
# Импорт агента в Hermes
hermes import-agent ./hermes-agent-card.json

# Настройка ежедневного запуска (cron)
crontab -e
# Добавить строку:
0 6 * * * /usr/bin/python3 /opt/security-monitor/security_monitor.py --format json --output /var/log/security-daily.json && hermes send-report /var/log/security-daily.json
```

### Конфигурация Hermes (`hermes-agent-card.json`)

```json
{
  "name": "linux-security-monitor",
  "version": "2.0",
  "language": "ru",
  "description": "Субагент безопасности Linux (только Critical/High, ежедневный отчет)",
  "schedule": "daily",
  "report_time": "06:00",
  "permissions": ["read-only"],
  "tools": [
    {"name": "check_updates", "type": "system"},
    {"name": "check_ssh", "type": "audit"},
    {"name": "check_firewall", "type": "network"},
    {"name": "check_disk", "type": "system"}
  ],
  "alerting": {
    "critical": {"immediate": true, "channels": ["telegram", "email"]},
    "high": {"immediate": false, "daily_summary": true}
  }
}
```

## Интеграция с OpenClaw

```bash
# Импорт агента в OpenClaw
openclaw agent import ./openclaw-agent-card.json

# Настройка расписания
openclaw schedule add --agent linux-security-monitor --cron "0 6 * * *"
```

### Конфигурация OpenClaw (`openclaw-agent-card.json`)

```json
{
  "agent_id": "linux-security-monitor-ru",
  "interface": {
    "script": "security_monitor.py",
    "format": "json",
    "timeout": 60
  },
  "actions": [
    {"trigger": "critical", "response": "alert_immediate"},
    {"trigger": "high", "response": "daily_digest"}
  ],
  "monitoring": {
    "frequency": "daily",
    "quiet_hours": "22:00-08:00",
    "deduplication": true
  }
}
```

## Примеры отчетов

### Чистая система (без угроз)
```markdown
# 🛡️ Отчет Linux Security Monitor
**Дата:** 2025-01-15 06:00:00
**Режим:** Только критические и опасные события (Critical/High)

## ✅ Статус: Угроз не обнаружено

Система не имеет критических или высоких угроз безопасности на момент проверки.

---
*Следующий запланированный отчет: через 24 часа*
```

### Система с проблемами
```markdown
# 🛡️ Отчет Linux Security Monitor
**Дата:** 2025-01-15 06:00:00
**Режим:** Только критические и опасные события (Critical/High)

## ⚠️ Обнаружено угроз: 3
- 🔴 Критические (Critical): 1
- 🟠 Высокие (High): 2

### 1. 🔴 [CRITICAL] privileged_users
**Проблема:** Пользователь admin имеет UID 0
**Детали:** Нерoot пользователь с правами суперпользователя
**Рекомендация:** Проверьте необходимость прав для admin и измените UID

### 2. 🟠 [HIGH] firewall
**Проблема:** Файрвол UFW отключен
**Детали:** Система не защищена межсетевым экраном
**Рекомендация:** sudo ufw enable

### 3. 🟠 [HIGH] disk_usage
**Проблема:** Критическая заполненность диска /: 94%
**Детали:** Требуется немедленное освобождение места
**Рекомендация:** Очистите логи, временные файлы или расширьте диск

---
*Рекомендуется немедленно устранить критические проблемы.*
```

## Настройка для группы безопасности

Чтобы избежать спама при отправке в общую группу:

### 1. Используйте фильтр по серьезности
Агент уже настроен показывать только `CRITICAL` и `HIGH`.

### 2. Настройте ежедневную сводку
```bash
# В crontab:
0 6 * * * /opt/security-monitor/security_monitor.py --format json --output /tmp/security.json && curl -X POST -d @/tmp/security.json https://your-chatbot/api/report
```

### 3. Отправляйте только при наличии проблем
```bash
#!/bin/bash
REPORT=$(python3 /opt/security-monitor/security_monitor.py --format json)
FINDINGS=$(echo $REPORT | jq '.total_findings')

if [ "$FINDINGS" -gt 0 ]; then
    echo $REPORT | telegram-send --stdin
else
    echo "✅ Все системы в норме" | telegram-send --stdin
fi
```

## Структура проекта

```
security-monitor-ru/
├── security_monitor.py          # Основной скрипт
├── README.md                    # Документация
├── hermes-agent-card.json       # Конфигурация для Hermes
├── openclaw-agent-card.json     # Конфигурация для OpenClaw
└── examples/
    ├── hermes-config.json       # Пример интеграции
    └── openclaw-config.json     # Пример интеграции
```

## Требования

- Python 3.6+
- Linux (Ubuntu, Debian, CentOS, RHEL)
- Права root или sudo для некоторых проверок
- Опционально: `jq` для обработки JSON

## Лицензия

MIT License — свободное использование и модификация.

## Поддержка

Для вопросов и предложений создавайте issues в репозитории.
