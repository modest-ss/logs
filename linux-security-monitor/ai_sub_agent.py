#!/usr/bin/env python3
"""
AI Sub-Agent Controller для Linux Security Monitor
Этот модуль позволяет ИИ внутри Hermes/OpenClaw управлять субагентом безопасности.

Функции:
- Интеллектуальный анализ результатов проверок
- Автоматическое принятие решений о критичности событий
- Генерация контекстных рекомендаций
- Управление расписанием и anti-spam
- Адаптивная фильтрация событий на основе истории
"""

import json
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

# Импорт основного монитора
try:
    from security_monitor import (
        SecurityReport,
        Finding,
        get_server_info,
        run_command,
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
        load_json_file,
        save_json_file,
        STATE_DIR,
    )
except ImportError:
    print("Ошибка: security_monitor.py не найден", file=sys.stderr)
    sys.exit(1)


@dataclass
class AIDecision:
    """Решение ИИ о действии"""
    action: str  # "alert", "suppress", "escalate", "investigate"
    reason: str
    confidence: float  # 0.0 - 1.0
    priority: int  # 1-10
    recommended_actions: List[str] = field(default_factory=list)


@dataclass
class AIAnalysisResult:
    """Результат анализа ИИ"""
    timestamp: str
    server_hostname: str
    server_ip: List[str]
    total_findings: int
    critical_count: int
    high_count: int
    status: str
    findings: List[Finding]
    decisions: List[AIDecision]
    summary: str
    risk_score: float  # 0-100
    trend: str  # "improving", "stable", "degrading"
    context: Dict[str, Any] = field(default_factory=dict)


class AISecurityAgent:
    """
    ИИ-субагент для управления безопасностью Linux
    
    Этот класс предоставляет интерфейс для ИИ внутри Hermes/OpenClaw
    для интеллектуального управления проверками безопасности.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.history = self._load_history()
        self.hostname, self.ips = get_server_info()
        
    def _load_config(self, path: Optional[str]) -> Dict:
        """Загружает конфигурацию ИИ"""
        default_config = {
            "risk_thresholds": {
                "critical": 80,
                "high": 60,
                "medium": 40,
                "low": 20
            },
            "auto_escalation": True,
            "context_awareness": True,
            "learning_enabled": True,
            "max_findings_per_report": 50,
            "correlation_window_hours": 24
        }
        
        if path:
            try:
                with open(path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Warning: Could not load config: {e}", file=sys.stderr)
        
        return default_config
    
    def _load_history(self) -> Dict:
        """Загружает историю для анализа трендов"""
        history_file = STATE_DIR / "ai_history.json"
        return load_json_file(history_file) or {"reports": [], "trends": {}}
    
    def _save_history(self, history: Dict):
        """Сохраняет историю"""
        history_file = STATE_DIR / "ai_history.json"
        save_json_file(history_file, history)
    
    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Вычисляет общий риск на основе находок"""
        if not findings:
            return 0.0
        
        severity_weights = {
            "critical": 25.0,
            "high": 15.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5
        }
        
        total_score = 0.0
        for finding in findings:
            weight = severity_weights.get(finding.severity, 1.0)
            total_score += weight
        
        # Нормализуем до 0-100
        return min(100.0, total_score)
    
    def _analyze_trend(self) -> str:
        """Анализирует тренд безопасности"""
        if not self.history.get("reports"):
            return "stable"
        
        recent_reports = self.history["reports"][-5:]  # Последние 5 отчетов
        
        if len(recent_reports) < 2:
            return "stable"
        
        # Сравниваем количество проблем
        old_count = sum(r.get("total_findings", 0) for r in recent_reports[:-1]) / (len(recent_reports) - 1)
        new_count = recent_reports[-1].get("total_findings", 0)
        
        if new_count > old_count * 1.2:
            return "degrading"
        elif new_count < old_count * 0.8:
            return "improving"
        else:
            return "stable"
    
    def _make_decision(self, finding: Finding) -> AIDecision:
        """Принимает решение по конкретной находке"""
        # Базовая логика принятия решений
        if finding.severity == "critical":
            return AIDecision(
                action="alert",
                reason=f"Критическая уязвимость: {finding.summary}",
                confidence=0.95,
                priority=10,
                recommended_actions=[
                    finding.remediation,
                    "Немедленно уведомить команду безопасности",
                    "Изолировать систему при необходимости"
                ]
            )
        
        elif finding.severity == "high":
            # Проверяем контекст и историю
            is_recurring = self._is_recurring_issue(finding)
            
            if is_recurring:
                return AIDecision(
                    action="escalate",
                    reason=f"Повторяющаяся проблема высокой важности: {finding.summary}",
                    confidence=0.85,
                    priority=8,
                    recommended_actions=[
                        finding.remediation,
                        "Провести расследование причины повторения",
                        "Обновить процедуры мониторинга"
                    ]
                )
            else:
                return AIDecision(
                    action="alert",
                    reason=f"Проблема высокой важности: {finding.summary}",
                    confidence=0.80,
                    priority=7,
                    recommended_actions=[
                        finding.remediation,
                        "Запланировать исправление в течение 24 часов"
                    ]
                )
        
        else:
            return AIDecision(
                action="suppress",
                reason=f"Низкий приоритет: {finding.summary}",
                confidence=0.70,
                priority=3,
                recommended_actions=["Мониторить в ежедневной сводке"]
            )
    
    def _is_recurring_issue(self, finding: Finding) -> bool:
        """Проверяет, является ли проблема повторяющейся"""
        if not self.history.get("reports"):
            return False
        
        finding_hash = finding.hash()
        
        for report in self.history["reports"][-10:]:  # Последние 10 отчетов
            for prev_finding in report.get("findings", []):
                if prev_finding.get("hash") == finding_hash:
                    return True
        
        return False
    
    def _generate_summary(self, findings: List[Finding], decisions: List[AIDecision]) -> str:
        """Генерирует интеллектуальную сводку"""
        if not findings:
            return "✅ Система безопасна. Критических и высоких угроз не обнаружено."
        
        critical_count = sum(1 for f in findings if f.severity == "critical")
        high_count = sum(1 for f in findings if f.severity == "high")
        
        summary_parts = []
        
        if critical_count > 0:
            summary_parts.append(f"🚨 ТРЕБУЕТСЯ НЕМЕДЛЕННОЕ ВНИМАНИЕ: {critical_count} критических уязвимостей!")
        
        if high_count > 0:
            summary_parts.append(f"⚠️ Обнаружено {high_count} проблем высокой важности.")
        
        # Добавляем топ-3 проблемы
        top_findings = sorted(findings, key=lambda x: {"critical": 0, "high": 1}.get(x.severity, 2))[:3]
        
        if top_findings:
            summary_parts.append("\nНаиболее важные проблемы:")
            for i, f in enumerate(top_findings, 1):
                summary_parts.append(f"{i}. [{f.severity.upper()}] {f.summary}")
        
        # Рекомендации
        alert_decisions = [d for d in decisions if d.action in ["alert", "escalate"]]
        if alert_decisions:
            summary_parts.append("\nРекомендуемые действия:")
            for decision in alert_decisions[:3]:
                if decision.recommended_actions:
                    summary_parts.append(f"• {decision.recommended_actions[0]}")
        
        return "\n".join(summary_parts)
    
    def run_full_scan(self) -> AIAnalysisResult:
        """
        Запускает полную проверку безопасности с ИИ-анализом
        
        Returns:
            AIAnalysisResult: Полный результат анализа с решениями ИИ
        """
        print(f"🔍 Запуск полной проверки безопасности на сервере {self.hostname}...", file=sys.stderr)
        
        # Собираем все проверки
        all_findings: List[Finding] = []
        
        checks = [
            ("Обновления пакетов", check_updates),
            ("SSH конфигурация", check_ssh),
            ("Слушающие порты", check_listening_ports),
            ("Файрвол", check_firewall),
            ("Неудачные входы", check_failed_logins),
            ("Привилегированные пользователи", check_privileged_users),
            ("Systemd сервисы", check_systemd),
            ("Диск", check_disk),
            ("SELinux/AppArmor", check_selinux),
            ("Cron задания", check_cron),
            ("Подозрительные процессы", check_processes),
            ("Переменные окружения", check_env_vars),
            ("OOM события", check_oom),
            ("Zombie процессы", check_zombie_processes),
            ("Promiscuous режим", check_promiscuous_mode),
            ("Audit статус", check_audit_status),
            ("Failed сервисы", check_failed_services_startup),
            ("Inode usage", check_inode_usage),
            ("Изменения времени", check_time_changes),
            ("Сетевые ошибки", check_network_errors),
        ]
        
        for check_name, check_func in checks:
            try:
                findings = check_func()
                all_findings.extend(findings)
                print(f"  ✓ {check_name}: {len(findings)} проблем", file=sys.stderr)
            except Exception as e:
                print(f"  ✗ {check_name}: ошибка - {e}", file=sys.stderr)
        
        # Применяем anti-spam фильтрацию
        filtered_findings = []
        for finding in all_findings:
            # Здесь можно добавить дополнительную логику фильтрации
            filtered_findings.append(finding)
        
        # Принимаем решения ИИ по каждой находке
        decisions = [self._make_decision(f) for f in filtered_findings]
        
        # Вычисляем метрики
        critical_count = sum(1 for f in filtered_findings if f.severity == "critical")
        high_count = sum(1 for f in filtered_findings if f.severity == "high")
        risk_score = self._calculate_risk_score(filtered_findings)
        trend = self._analyze_trend()
        
        # Определяем статус
        if critical_count > 0:
            status = "critical_issues_found"
        elif high_count > 0:
            status = "high_issues_found"
        else:
            status = "clean"
        
        # Генерируем сводку
        summary = self._generate_summary(filtered_findings, decisions)
        
        # Создаем результат
        result = AIAnalysisResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_hostname=self.hostname,
            server_ip=self.ips,
            total_findings=len(filtered_findings),
            critical_count=critical_count,
            high_count=high_count,
            status=status,
            findings=filtered_findings,
            decisions=decisions,
            summary=summary,
            risk_score=risk_score,
            trend=trend,
            context={
                "checks_performed": len(checks),
                "ai_version": "1.0.0",
                "config": self.config
            }
        )
        
        # Сохраняем в историю
        self.history["reports"].append({
            "timestamp": result.timestamp,
            "total_findings": result.total_findings,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "risk_score": result.risk_score,
            "findings": [{"hash": f.hash(), "severity": f.severity} for f in filtered_findings]
        })
        
        # Ограничиваем историю последними 100 отчетами
        self.history["reports"] = self.history["reports"][-100:]
        self._save_history(self.history)
        
        return result
    
    def get_quick_status(self) -> Dict[str, Any]:
        """Быстрый статус без детального анализа"""
        result = self.run_full_scan()
        
        return {
            "hostname": result.server_hostname,
            "ip": result.server_ip,
            "status": result.status,
            "risk_score": result.risk_score,
            "trend": result.trend,
            "total_findings": result.total_findings,
            "critical": result.critical_count,
            "high": result.high_count,
            "summary": result.summary,
            "timestamp": result.timestamp
        }
    
    def to_hermes_format(self, result: AIAnalysisResult) -> Dict:
        """Конвертирует результат в формат Hermes"""
        return {
            "agent_id": "linux-security-monitor-ru",
            "type": "security_report",
            "priority": "critical" if result.critical_count > 0 else "high" if result.high_count > 0 else "normal",
            "data": {
                "timestamp": result.timestamp,
                "server_hostname": result.server_hostname,
                "server_ip": result.server_ip,
                "status": result.status,
                "risk_score": result.risk_score,
                "trend": result.trend,
                "summary": result.summary,
                "findings": [f.to_dict() for f in result.findings],
                "decisions": [
                    {
                        "action": d.action,
                        "reason": d.reason,
                        "confidence": d.confidence,
                        "priority": d.priority,
                        "recommended_actions": d.recommended_actions
                    }
                    for d in result.decisions
                ]
            }
        }
    
    def to_openclaw_format(self, result: AIAnalysisResult) -> Dict:
        """Конвертирует результат в формат OpenClaw"""
        return {
            "agent_id": "linux-security-monitor-ru",
            "action": "security_scan",
            "result": {
                "success": True,
                "server": {
                    "hostname": result.server_hostname,
                    "ip_addresses": result.server_ip
                },
                "scan_result": {
                    "status": result.status,
                    "risk_score": result.risk_score,
                    "trend": result.trend,
                    "findings_count": {
                        "total": result.total_findings,
                        "critical": result.critical_count,
                        "high": result.high_count
                    },
                    "summary": result.summary,
                    "findings": [f.to_dict() for f in result.findings],
                    "ai_decisions": [
                        {
                            "action": d.action,
                            "reason": d.reason,
                            "priority": d.priority
                        }
                        for d in result.decisions
                    ]
                },
                "timestamp": result.timestamp
            }
        }


def main():
    """Точка входа для ИИ-субагента"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI Security Sub-Agent Controller")
    parser.add_argument("--format", choices=["json", "markdown", "hermes", "openclaw"], 
                       default="json", help="Формат вывода")
    parser.add_argument("--quick", action="store_true", help="Быстрый статус")
    parser.add_argument("--config", type=str, help="Путь к конфигурации ИИ")
    
    args = parser.parse_args()
    
    agent = AISecurityAgent(config_path=args.config)
    
    if args.quick:
        result = agent.get_quick_status()
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        analysis = agent.run_full_scan()
        
        if args.format == "json":
            output = {
                "timestamp": analysis.timestamp,
                "server_hostname": analysis.server_hostname,
                "server_ip": analysis.server_ip,
                "status": analysis.status,
                "risk_score": analysis.risk_score,
                "trend": analysis.trend,
                "summary": analysis.summary,
                "total_findings": analysis.total_findings,
                "critical_count": analysis.critical_count,
                "high_count": analysis.high_count,
                "findings": [f.to_dict() for f in analysis.findings],
                "decisions": [
                    {
                        "action": d.action,
                        "reason": d.reason,
                        "confidence": d.confidence,
                        "priority": d.priority,
                        "recommended_actions": d.recommended_actions
                    }
                    for d in analysis.decisions
                ]
            }
            print(json.dumps(output, indent=2, ensure_ascii=False))
        
        elif args.format == "hermes":
            output = agent.to_hermes_format(analysis)
            print(json.dumps(output, indent=2, ensure_ascii=False))
        
        elif args.format == "openclaw":
            output = agent.to_openclaw_format(analysis)
            print(json.dumps(output, indent=2, ensure_ascii=False))
        
        elif args.format == "markdown":
            print(f"# 🛡️ Отчет ИИ-субагента безопасности\n")
            print(f"**Сервер:** {analysis.server_hostname} ({', '.join(analysis.server_ip)})\n")
            print(f"**Время:** {analysis.timestamp}\n")
            print(f"**Статус:** {analysis.status.upper()}\n")
            print(f"**Оценка риска:** {analysis.risk_score:.1f}/100\n")
            print(f"**Тренд:** {analysis.trend}\n")
            print(f"\n## Сводка\n{analysis.summary}\n")
            
            if analysis.findings:
                print(f"\n## Найденные проблемы ({analysis.total_findings})\n")
                for i, finding in enumerate(analysis.findings, 1):
                    print(f"### {i}. [{finding.severity.upper()}] {finding.check}")
                    print(f"**Проблема:** {finding.summary}\n")
                    if finding.details:
                        print(f"**Детали:** {finding.details}\n")
                    if finding.remediation:
                        print(f"**Решение:** {finding.remediation}\n")
                    print("---\n")


if __name__ == "__main__":
    main()
