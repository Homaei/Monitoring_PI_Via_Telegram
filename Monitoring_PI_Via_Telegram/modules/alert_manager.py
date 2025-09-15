"""
Alert Manager Module - Alert system and notifications

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive alert management and notification capabilities including alert creation, severity management, and multi-channel notifications.
License: For educational and personal use
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from enum import Enum
import requests

from config.settings import (
    BOT_TOKEN, ADMIN_USER_ID, AUTHORIZED_USERS, THRESHOLDS,
    DATA_DIR, MONITORING_CONFIG
)
from utils.helpers import safe_execute

logger = logging.getLogger('monitoring.alert_manager')


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status types"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AlertManager:
    """Alert management and notification class"""

    def __init__(self):
        """Initialize the alert manager"""
        self.logger = logger
        self._alerts_file = DATA_DIR / "alerts.json"
        self._active_alerts = {}  # alert_id -> alert_data
        self._alert_history = []
        self._alert_rules = []
        self._notification_channels = []
        self._max_history = 1000
        self._cooldown_periods = {}  # alert_type -> last_sent_time

    async def initialize(self) -> bool:
        """Initialize the alert manager"""
        try:
            self.logger.info("🚀 Initializing Alert Manager...")

            # Ensure alerts directory exists
            self._alerts_file.parent.mkdir(parents=True, exist_ok=True)

            # Load existing alerts and history
            await self._load_alerts()

            # Initialize default alert rules
            await self._setup_default_rules()

            # Setup notification channels
            await self._setup_notification_channels()

            # Clean up old alerts
            await self._cleanup_old_alerts()

            self.logger.info(f"✅ Alert Manager initialized - {len(self._active_alerts)} active alerts")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Alert Manager: {e}")
            return False

    @safe_execute
    async def _load_alerts(self):
        """Load alerts from storage"""
        try:
            if self._alerts_file.exists():
                with open(self._alerts_file, 'r') as f:
                    data = json.load(f)
                    self._active_alerts = data.get('active_alerts', {})
                    self._alert_history = data.get('alert_history', [])
                    self._alert_rules = data.get('alert_rules', [])
                    self.logger.info(f"Loaded {len(self._active_alerts)} active alerts from storage")
            else:
                self._active_alerts = {}
                self._alert_history = []
                self._alert_rules = []

        except Exception as e:
            self.logger.error(f"Error loading alerts: {e}")
            self._active_alerts = {}
            self._alert_history = []
            self._alert_rules = []

    @safe_execute
    async def _save_alerts(self):
        """Save alerts to storage"""
        try:
            data = {
                'active_alerts': self._active_alerts,
                'alert_history': self._alert_history[-self._max_history:],  # Keep only recent history
                'alert_rules': self._alert_rules,
                'last_updated': datetime.now().isoformat(),
                'version': '1.0'
            }

            with open(self._alerts_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Error saving alerts: {e}")

    @safe_execute
    async def _setup_default_rules(self):
        """Setup default alert rules"""
        try:
            if not self._alert_rules:  # Only setup if no rules exist
                default_rules = [
                    {
                        'name': 'High CPU Usage',
                        'type': 'cpu_usage',
                        'condition': lambda data: data.get('cpu_usage', 0) > 90,
                        'severity': AlertSeverity.HIGH.value,
                        'message': 'CPU usage is critically high: {cpu_usage:.1f}%',
                        'cooldown': 300,  # 5 minutes
                        'enabled': True
                    },
                    {
                        'name': 'High Memory Usage',
                        'type': 'memory_usage',
                        'condition': lambda data: data.get('memory_usage', 0) > 95,
                        'severity': AlertSeverity.CRITICAL.value,
                        'message': 'Memory usage is critically high: {memory_usage:.1f}%',
                        'cooldown': 300,
                        'enabled': True
                    },
                    {
                        'name': 'Disk Space Low',
                        'type': 'disk_usage',
                        'condition': lambda data: data.get('disk_usage', 0) > 95,
                        'severity': AlertSeverity.CRITICAL.value,
                        'message': 'Disk space critically low: {disk_usage:.1f}% used',
                        'cooldown': 600,  # 10 minutes
                        'enabled': True
                    },
                    {
                        'name': 'High Temperature',
                        'type': 'temperature',
                        'condition': lambda data: data.get('cpu_temperature', 0) > 80,
                        'severity': AlertSeverity.HIGH.value,
                        'message': 'CPU temperature is high: {cpu_temperature:.1f}°C',
                        'cooldown': 300,
                        'enabled': True
                    },
                    {
                        'name': 'Service Failed',
                        'type': 'service_failure',
                        'condition': lambda data: len(data.get('failed_services', [])) > 0,
                        'severity': AlertSeverity.HIGH.value,
                        'message': 'Critical services have failed: {failed_services}',
                        'cooldown': 900,  # 15 minutes
                        'enabled': True
                    },
                    {
                        'name': 'Network Connectivity',
                        'type': 'network_down',
                        'condition': lambda data: not data.get('internet_connected', True),
                        'severity': AlertSeverity.MEDIUM.value,
                        'message': 'Internet connectivity lost',
                        'cooldown': 600,
                        'enabled': True
                    },
                    {
                        'name': 'Security Alert',
                        'type': 'security_issue',
                        'condition': lambda data: data.get('security_score', 100) < 50,
                        'severity': AlertSeverity.CRITICAL.value,
                        'message': 'Security issues detected - Score: {security_score:.1f}/100',
                        'cooldown': 3600,  # 1 hour
                        'enabled': True
                    }
                ]

                self._alert_rules = default_rules
                await self._save_alerts()
                self.logger.info(f"Setup {len(default_rules)} default alert rules")

        except Exception as e:
            self.logger.error(f"Error setting up default rules: {e}")

    @safe_execute
    async def _setup_notification_channels(self):
        """Setup notification channels"""
        try:
            self._notification_channels = [
                {
                    'name': 'telegram',
                    'type': 'telegram',
                    'enabled': bool(BOT_TOKEN),
                    'config': {
                        'bot_token': BOT_TOKEN,
                        'chat_ids': AUTHORIZED_USERS
                    }
                }
            ]

            enabled_channels = [ch['name'] for ch in self._notification_channels if ch['enabled']]
            self.logger.info(f"Setup notification channels: {', '.join(enabled_channels)}")

        except Exception as e:
            self.logger.error(f"Error setting up notification channels: {e}")

    @safe_execute
    async def create_alert(self, alert_type: str, severity: AlertSeverity, message: str,
                          details: Dict[str, Any] = None, source: str = None) -> str:
        """Create a new alert"""
        try:
            alert_id = f"{alert_type}_{int(time.time())}"

            alert_data = {
                'id': alert_id,
                'type': alert_type,
                'severity': severity.value,
                'message': message,
                'details': details or {},
                'source': source or 'system',
                'status': AlertStatus.ACTIVE.value,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'acknowledged_at': None,
                'acknowledged_by': None,
                'resolved_at': None,
                'notification_sent': False
            }

            # Check if similar alert already exists
            similar_alert = self._find_similar_alert(alert_type, message)
            if similar_alert:
                # Update existing alert instead of creating new one
                similar_alert['updated_at'] = datetime.now().isoformat()
                similar_alert['details'].update(details or {})
                await self._save_alerts()
                return similar_alert['id']

            # Add to active alerts
            self._active_alerts[alert_id] = alert_data

            # Add to history
            self._alert_history.append({
                'id': alert_id,
                'type': alert_type,
                'severity': severity.value,
                'message': message,
                'action': 'created',
                'timestamp': datetime.now().isoformat()
            })

            await self._save_alerts()

            # Send notification
            await self._send_notification(alert_data)

            self.logger.info(f"Created alert: {alert_id} - {message}")
            return alert_id

        except Exception as e:
            self.logger.error(f"Error creating alert: {e}")
            return None

    def _find_similar_alert(self, alert_type: str, message: str) -> Optional[Dict[str, Any]]:
        """Find similar active alert"""
        try:
            for alert in self._active_alerts.values():
                if (alert['type'] == alert_type and
                    alert['status'] == AlertStatus.ACTIVE.value and
                    alert['message'] == message):
                    return alert
            return None
        except Exception as e:
            self.logger.error(f"Error finding similar alert: {e}")
            return None

    @safe_execute
    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an alert"""
        try:
            if alert_id not in self._active_alerts:
                return False

            alert = self._active_alerts[alert_id]
            alert['status'] = AlertStatus.ACKNOWLEDGED.value
            alert['acknowledged_at'] = datetime.now().isoformat()
            alert['acknowledged_by'] = acknowledged_by
            alert['updated_at'] = datetime.now().isoformat()

            # Add to history
            self._alert_history.append({
                'id': alert_id,
                'type': alert['type'],
                'severity': alert['severity'],
                'message': alert['message'],
                'action': 'acknowledged',
                'by': acknowledged_by,
                'timestamp': datetime.now().isoformat()
            })

            await self._save_alerts()
            self.logger.info(f"Alert acknowledged: {alert_id} by {acknowledged_by}")
            return True

        except Exception as e:
            self.logger.error(f"Error acknowledging alert {alert_id}: {e}")
            return False

    @safe_execute
    async def resolve_alert(self, alert_id: str, resolved_by: str = 'system') -> bool:
        """Resolve an alert"""
        try:
            if alert_id not in self._active_alerts:
                return False

            alert = self._active_alerts[alert_id]
            alert['status'] = AlertStatus.RESOLVED.value
            alert['resolved_at'] = datetime.now().isoformat()
            alert['updated_at'] = datetime.now().isoformat()

            # Add to history
            self._alert_history.append({
                'id': alert_id,
                'type': alert['type'],
                'severity': alert['severity'],
                'message': alert['message'],
                'action': 'resolved',
                'by': resolved_by,
                'timestamp': datetime.now().isoformat()
            })

            # Move to history and remove from active
            del self._active_alerts[alert_id]

            await self._save_alerts()
            self.logger.info(f"Alert resolved: {alert_id} by {resolved_by}")
            return True

        except Exception as e:
            self.logger.error(f"Error resolving alert {alert_id}: {e}")
            return False

    @safe_execute
    async def check_conditions(self, monitoring_data: Dict[str, Any]):
        """Check alert conditions against monitoring data"""
        try:
            triggered_alerts = []

            for rule in self._alert_rules:
                if not rule.get('enabled', True):
                    continue

                try:
                    # Check cooldown period
                    rule_type = rule['type']
                    if rule_type in self._cooldown_periods:
                        last_sent = self._cooldown_periods[rule_type]
                        cooldown = rule.get('cooldown', 300)
                        if (time.time() - last_sent) < cooldown:
                            continue

                    # Evaluate condition
                    if isinstance(rule['condition'], dict):
                        # Simple condition format
                        condition_met = self._evaluate_simple_condition(rule['condition'], monitoring_data)
                    else:
                        # Function condition
                        condition_met = rule['condition'](monitoring_data)

                    if condition_met:
                        # Format message with monitoring data
                        message = rule['message'].format(**monitoring_data)

                        # Create alert
                        alert_id = await self.create_alert(
                            alert_type=rule_type,
                            severity=AlertSeverity(rule['severity']),
                            message=message,
                            details=monitoring_data,
                            source='monitoring'
                        )

                        if alert_id:
                            triggered_alerts.append(alert_id)
                            self._cooldown_periods[rule_type] = time.time()

                except Exception as e:
                    self.logger.error(f"Error evaluating rule {rule.get('name', 'Unknown')}: {e}")

            return triggered_alerts

        except Exception as e:
            self.logger.error(f"Error checking alert conditions: {e}")
            return []

    def _evaluate_simple_condition(self, condition: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """Evaluate simple condition format"""
        try:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')

            if not all([field, operator, value is not None]):
                return False

            data_value = data.get(field, 0)

            if operator == '>':
                return data_value > value
            elif operator == '>=':
                return data_value >= value
            elif operator == '<':
                return data_value < value
            elif operator == '<=':
                return data_value <= value
            elif operator == '==':
                return data_value == value
            elif operator == '!=':
                return data_value != value
            else:
                return False

        except Exception as e:
            self.logger.error(f"Error evaluating simple condition: {e}")
            return False

    @safe_execute
    async def _send_notification(self, alert_data: Dict[str, Any]):
        """Send alert notification through configured channels"""
        try:
            for channel in self._notification_channels:
                if not channel.get('enabled', False):
                    continue

                try:
                    if channel['type'] == 'telegram':
                        await self._send_telegram_notification(alert_data, channel['config'])
                    # Add other notification types here (email, webhook, etc.)

                except Exception as e:
                    self.logger.error(f"Error sending notification via {channel['name']}: {e}")

            # Mark as sent
            alert_data['notification_sent'] = True
            alert_data['notification_sent_at'] = datetime.now().isoformat()

        except Exception as e:
            self.logger.error(f"Error sending notifications: {e}")

    @safe_execute
    async def _send_telegram_notification(self, alert_data: Dict[str, Any], config: Dict[str, Any]):
        """Send Telegram notification"""
        try:
            bot_token = config.get('bot_token')
            chat_ids = config.get('chat_ids', [])

            if not bot_token or not chat_ids:
                return

            # Format alert message
            severity_emoji = {
                'low': '🔵',
                'medium': '🟡',
                'high': '🟠',
                'critical': '🔴'
            }

            emoji = severity_emoji.get(alert_data['severity'], '⚪')

            message = f"{emoji} **ALERT** {emoji}\n\n"
            message += f"**Severity:** {alert_data['severity'].upper()}\n"
            message += f"**Type:** {alert_data['type'].replace('_', ' ').title()}\n"
            message += f"**Message:** {alert_data['message']}\n"
            message += f"**Time:** {datetime.fromisoformat(alert_data['created_at']).strftime('%Y-%m-%d %H:%M:%S')}\n"

            if alert_data.get('source'):
                message += f"**Source:** {alert_data['source']}\n"

            # Add details if available
            details = alert_data.get('details', {})
            if details:
                message += "\n**Details:**\n"
                for key, value in list(details.items())[:5]:  # Limit to 5 details
                    if isinstance(value, (int, float)):
                        if isinstance(value, float):
                            value = f"{value:.2f}"
                    message += f"• {key.replace('_', ' ').title()}: {value}\n"

            # Send to each authorized user
            for chat_id in chat_ids:
                try:
                    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                    payload = {
                        'chat_id': chat_id,
                        'text': message,
                        'parse_mode': 'Markdown'
                    }

                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code != 200:
                        self.logger.error(f"Failed to send Telegram message: {response.text}")

                except Exception as e:
                    self.logger.error(f"Error sending to Telegram chat {chat_id}: {e}")

        except Exception as e:
            self.logger.error(f"Error in Telegram notification: {e}")

    @safe_execute
    async def get_active_alerts(self, severity: str = None) -> List[Dict[str, Any]]:
        """Get active alerts, optionally filtered by severity"""
        try:
            alerts = list(self._active_alerts.values())

            if severity:
                alerts = [alert for alert in alerts if alert['severity'] == severity]

            # Sort by creation time (newest first)
            alerts.sort(key=lambda x: x['created_at'], reverse=True)
            return alerts

        except Exception as e:
            self.logger.error(f"Error getting active alerts: {e}")
            return []

    @safe_execute
    async def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'active_alerts': len(self._active_alerts),
                'total_history': len(self._alert_history),
                'by_severity': {},
                'by_type': {},
                'by_status': {},
                'recent_alerts': 0
            }

            # Count active alerts by severity and type
            for alert in self._active_alerts.values():
                severity = alert.get('severity', 'unknown')
                alert_type = alert.get('type', 'unknown')
                status = alert.get('status', 'unknown')

                stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
                stats['by_type'][alert_type] = stats['by_type'].get(alert_type, 0) + 1
                stats['by_status'][status] = stats['by_status'].get(status, 0) + 1

            # Count recent alerts (last 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)
            for entry in self._alert_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time and entry.get('action') == 'created':
                        stats['recent_alerts'] += 1
                except:
                    continue

            return stats

        except Exception as e:
            self.logger.error(f"Error getting alert statistics: {e}")
            return {}

    @safe_execute
    async def _cleanup_old_alerts(self):
        """Clean up old resolved alerts and history"""
        try:
            # Keep only recent history
            if len(self._alert_history) > self._max_history:
                self._alert_history = self._alert_history[-self._max_history:]

            # Remove very old resolved alerts from active list
            cutoff_time = datetime.now() - timedelta(hours=24)
            old_alerts = []

            for alert_id, alert in self._active_alerts.items():
                if alert['status'] == AlertStatus.RESOLVED.value:
                    try:
                        resolved_time = datetime.fromisoformat(alert.get('resolved_at', alert['created_at']))
                        if resolved_time < cutoff_time:
                            old_alerts.append(alert_id)
                    except:
                        old_alerts.append(alert_id)

            for alert_id in old_alerts:
                del self._active_alerts[alert_id]

            if old_alerts:
                self.logger.info(f"Cleaned up {len(old_alerts)} old alerts")
                await self._save_alerts()

        except Exception as e:
            self.logger.error(f"Error cleaning up old alerts: {e}")

    @safe_execute
    async def generate_report(self) -> str:
        """Generate alert management report"""
        try:
            stats = await self.get_alert_statistics()
            active_alerts = await self.get_active_alerts()

            report_lines = [
                "🚨 ALERT MANAGEMENT REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add alert statistics
            report_lines.extend([
                "",
                "📊 ALERT STATISTICS",
                "-" * 30,
                f"🔴 Active Alerts: {stats.get('active_alerts', 0)}",
                f"📈 Recent Alerts (24h): {stats.get('recent_alerts', 0)}",
                f"📚 Total History: {stats.get('total_history', 0)}",
            ])

            # Add alerts by severity
            by_severity = stats.get('by_severity', {})
            if by_severity:
                report_lines.extend([
                    "",
                    "🎯 ALERTS BY SEVERITY",
                    "-" * 30,
                ])
                severity_emoji = {'low': '🔵', 'medium': '🟡', 'high': '🟠', 'critical': '🔴'}
                for severity, count in by_severity.items():
                    emoji = severity_emoji.get(severity, '⚪')
                    report_lines.append(f"{emoji} {severity.title()}: {count}")

            # Add alerts by type
            by_type = stats.get('by_type', {})
            if by_type:
                report_lines.extend([
                    "",
                    "📋 ALERTS BY TYPE",
                    "-" * 30,
                ])
                for alert_type, count in sorted(by_type.items()):
                    type_display = alert_type.replace('_', ' ').title()
                    report_lines.append(f"🔹 {type_display}: {count}")

            # Add active alerts details
            if active_alerts:
                report_lines.extend([
                    "",
                    "🚨 ACTIVE ALERTS",
                    "-" * 30,
                ])
                for alert in active_alerts[:10]:  # Show top 10
                    severity = alert.get('severity', 'unknown')
                    emoji = {'low': '🔵', 'medium': '🟡', 'high': '🟠', 'critical': '🔴'}.get(severity, '⚪')

                    created_time = alert.get('created_at', '')
                    try:
                        created_dt = datetime.fromisoformat(created_time)
                        time_ago = datetime.now() - created_dt
                        if time_ago.total_seconds() < 3600:
                            time_str = f"{int(time_ago.total_seconds() / 60)}m ago"
                        else:
                            time_str = f"{int(time_ago.total_seconds() / 3600)}h ago"
                    except:
                        time_str = "Unknown"

                    report_lines.append(f"{emoji} {alert.get('message', 'No message')} ({time_str})")

            # Add alert rules status
            enabled_rules = [rule for rule in self._alert_rules if rule.get('enabled', True)]
            report_lines.extend([
                "",
                "⚙️ ALERT RULES",
                "-" * 30,
                f"📊 Total Rules: {len(self._alert_rules)}",
                f"✅ Enabled Rules: {len(enabled_rules)}",
                f"❌ Disabled Rules: {len(self._alert_rules) - len(enabled_rules)}",
            ])

            # Add notification channels
            enabled_channels = [ch for ch in self._notification_channels if ch.get('enabled', False)]
            report_lines.extend([
                "",
                "📡 NOTIFICATION CHANNELS",
                "-" * 30,
            ])
            for channel in self._notification_channels:
                status = "✅ Enabled" if channel.get('enabled') else "❌ Disabled"
                report_lines.append(f"🔹 {channel['name'].title()}: {status}")

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating alert report: {e}")
            return f"❌ Error generating alert report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Alert Manager...")

            # Save any pending data
            await self._save_alerts()

            # Clean up old alerts
            await self._cleanup_old_alerts()

            self.logger.info("✅ Alert Manager cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Alert Manager cleanup: {e}")