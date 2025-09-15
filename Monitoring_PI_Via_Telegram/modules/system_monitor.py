"""
System Monitor Module - Overall system monitoring and coordination

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive system monitoring capabilities including system information, uptime, load averages, and overall system health metrics coordination.
License: For educational and personal use
"""

import asyncio
import logging
import platform
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import psutil

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, format_bytes, format_uptime,
    get_system_uptime, get_load_average, get_raspberry_pi_model
)

logger = logging.getLogger('monitoring.system')


class SystemMonitor:
    """Main system monitoring class that coordinates all system checks"""

    def __init__(self):
        """Initialize the system monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 30  # seconds
        self._cached_data = {}
        self.pi_model = None
        self.system_info = None

    async def initialize(self) -> bool:
        """Initialize the system monitor"""
        try:
            self.logger.info("🚀 Initializing System Monitor...")

            # Get Raspberry Pi model
            self.pi_model = await self._get_pi_model()

            # Get basic system information
            self.system_info = await self._get_system_info()

            self.logger.info("✅ System Monitor initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize System Monitor: {e}")
            return False

    @safe_execute
    async def _get_pi_model(self) -> Optional[str]:
        """Get Raspberry Pi model information"""
        try:
            return await asyncio.to_thread(get_raspberry_pi_model)
        except Exception as e:
            self.logger.error(f"Error getting Pi model: {e}")
            return "Unknown Raspberry Pi"

    @safe_execute
    async def _get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        try:
            system_info = {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'hostname': platform.node(),
                'python_version': platform.python_version(),
            }

            return system_info

        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {}

    @safe_execute
    async def get_system_overview(self) -> Dict[str, Any]:
        """Get comprehensive system overview"""
        try:
            # Check cache
            if self._is_cached_data_valid('overview'):
                return self._cached_data['overview']

            overview = {
                'timestamp': datetime.now().isoformat(),
                'hostname': platform.node(),
                'pi_model': self.pi_model or "Unknown",
                'uptime': await self._get_uptime_info(),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'users': await self._get_user_sessions(),
                'load_average': await self._get_load_info(),
                'system_info': self.system_info or {}
            }

            # Cache the data
            self._cached_data['overview'] = overview
            self._last_update = time.time()

            return overview

        except Exception as e:
            self.logger.error(f"Error getting system overview: {e}")
            return {}

    @safe_execute
    async def _get_uptime_info(self) -> Dict[str, Any]:
        """Get system uptime information"""
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time

            return {
                'seconds': uptime_seconds,
                'formatted': format_uptime(uptime_seconds),
                'boot_time': datetime.fromtimestamp(boot_time).isoformat()
            }

        except Exception as e:
            self.logger.error(f"Error getting uptime: {e}")
            return {'seconds': 0, 'formatted': 'Unknown', 'boot_time': 'Unknown'}

    @safe_execute
    async def _get_load_info(self) -> Dict[str, Any]:
        """Get system load information"""
        try:
            load_avg = os.getloadavg()
            cpu_count = psutil.cpu_count()

            load_info = {
                '1min': load_avg[0],
                '5min': load_avg[1],
                '15min': load_avg[2],
                'cpu_count': cpu_count,
                'load_percentage_1min': (load_avg[0] / cpu_count) * 100 if cpu_count > 0 else 0,
                'load_percentage_5min': (load_avg[1] / cpu_count) * 100 if cpu_count > 0 else 0,
                'load_percentage_15min': (load_avg[2] / cpu_count) * 100 if cpu_count > 0 else 0
            }

            # Add load status
            load_1min_pct = load_info['load_percentage_1min']
            if load_1min_pct < 70:
                load_info['status'] = '🟢 Normal'
                load_info['status_level'] = 'normal'
            elif load_1min_pct < 90:
                load_info['status'] = '🟡 High'
                load_info['status_level'] = 'warning'
            else:
                load_info['status'] = '🔴 Critical'
                load_info['status_level'] = 'critical'

            return load_info

        except Exception as e:
            self.logger.error(f"Error getting load info: {e}")
            return {}

    @safe_execute
    async def _get_user_sessions(self) -> List[Dict[str, Any]]:
        """Get current user sessions"""
        try:
            sessions = []
            for user in psutil.users():
                sessions.append({
                    'name': user.name,
                    'terminal': user.terminal or 'Unknown',
                    'host': user.host or 'localhost',
                    'started': datetime.fromtimestamp(user.started).isoformat()
                })

            return sessions

        except Exception as e:
            self.logger.error(f"Error getting user sessions: {e}")
            return []

    @safe_execute
    async def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        try:
            health = {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'healthy',
                'components': {},
                'alerts': [],
                'score': 100
            }

            # Check various components
            components = ['cpu', 'memory', 'disk', 'temperature', 'services']
            health_scores = []

            for component in components:
                try:
                    component_health = await self._check_component_health(component)
                    health['components'][component] = component_health
                    health_scores.append(component_health.get('score', 100))

                    # Add alerts if any
                    if component_health.get('alerts'):
                        health['alerts'].extend(component_health['alerts'])

                except Exception as e:
                    self.logger.error(f"Error checking {component} health: {e}")
                    health['components'][component] = {
                        'status': 'error',
                        'score': 0,
                        'message': f'Error checking {component}'
                    }
                    health_scores.append(0)

            # Calculate overall score
            if health_scores:
                health['score'] = sum(health_scores) / len(health_scores)

            # Determine overall status
            if health['score'] >= 90:
                health['overall_status'] = '🟢 Healthy'
                health['status_level'] = 'healthy'
            elif health['score'] >= 70:
                health['overall_status'] = '🟡 Warning'
                health['status_level'] = 'warning'
            elif health['score'] >= 50:
                health['overall_status'] = '🟠 Degraded'
                health['status_level'] = 'degraded'
            else:
                health['overall_status'] = '🔴 Critical'
                health['status_level'] = 'critical'

            return health

        except Exception as e:
            self.logger.error(f"Error getting system health: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'overall_status': '❌ Error',
                'status_level': 'error',
                'error': str(e)
            }

    @safe_execute
    async def _check_component_health(self, component: str) -> Dict[str, Any]:
        """Check health of a specific system component"""
        try:
            if component == 'cpu':
                return await self._check_cpu_health()
            elif component == 'memory':
                return await self._check_memory_health()
            elif component == 'disk':
                return await self._check_disk_health()
            elif component == 'temperature':
                return await self._check_temperature_health()
            elif component == 'services':
                return await self._check_services_health()
            else:
                return {'status': 'unknown', 'score': 50}

        except Exception as e:
            self.logger.error(f"Error checking {component} health: {e}")
            return {'status': 'error', 'score': 0}

    @safe_execute
    async def _check_cpu_health(self) -> Dict[str, Any]:
        """Check CPU health"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            load_avg = os.getloadavg()[0]
            cpu_count = psutil.cpu_count()
            load_percent = (load_avg / cpu_count) * 100 if cpu_count > 0 else 0

            alerts = []
            score = 100

            if cpu_percent > 90:
                alerts.append(f"High CPU usage: {cpu_percent:.1f}%")
                score -= 30
            elif cpu_percent > 80:
                score -= 15

            if load_percent > 100:
                alerts.append(f"High system load: {load_percent:.1f}%")
                score -= 20
            elif load_percent > 80:
                score -= 10

            return {
                'status': 'healthy' if score >= 80 else 'warning' if score >= 50 else 'critical',
                'score': max(0, score),
                'cpu_usage': cpu_percent,
                'load_average': load_avg,
                'alerts': alerts
            }

        except Exception as e:
            self.logger.error(f"Error checking CPU health: {e}")
            return {'status': 'error', 'score': 0}

    @safe_execute
    async def _check_memory_health(self) -> Dict[str, Any]:
        """Check memory health"""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            alerts = []
            score = 100

            if memory.percent > 90:
                alerts.append(f"High memory usage: {memory.percent:.1f}%")
                score -= 30
            elif memory.percent > 80:
                score -= 15

            if swap.percent > 50:
                alerts.append(f"High swap usage: {swap.percent:.1f}%")
                score -= 20

            return {
                'status': 'healthy' if score >= 80 else 'warning' if score >= 50 else 'critical',
                'score': max(0, score),
                'memory_usage': memory.percent,
                'swap_usage': swap.percent,
                'alerts': alerts
            }

        except Exception as e:
            self.logger.error(f"Error checking memory health: {e}")
            return {'status': 'error', 'score': 0}

    @safe_execute
    async def _check_disk_health(self) -> Dict[str, Any]:
        """Check disk health"""
        try:
            disk_usage = psutil.disk_usage('/')
            usage_percent = (disk_usage.used / disk_usage.total) * 100

            alerts = []
            score = 100

            if usage_percent > 95:
                alerts.append(f"Critical disk usage: {usage_percent:.1f}%")
                score -= 40
            elif usage_percent > 85:
                alerts.append(f"High disk usage: {usage_percent:.1f}%")
                score -= 20
            elif usage_percent > 75:
                score -= 10

            return {
                'status': 'healthy' if score >= 80 else 'warning' if score >= 50 else 'critical',
                'score': max(0, score),
                'disk_usage': usage_percent,
                'alerts': alerts
            }

        except Exception as e:
            self.logger.error(f"Error checking disk health: {e}")
            return {'status': 'error', 'score': 0}

    @safe_execute
    async def _check_temperature_health(self) -> Dict[str, Any]:
        """Check temperature health"""
        try:
            # Try to get CPU temperature
            temp = None
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        if entries:
                            temp = entries[0].current
                            break

            if temp is None:
                # Try alternative method for Raspberry Pi
                try:
                    with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                        temp = float(f.read().strip()) / 1000
                except:
                    temp = None

            alerts = []
            score = 100

            if temp is not None:
                if temp > 80:
                    alerts.append(f"Critical temperature: {temp:.1f}°C")
                    score -= 40
                elif temp > 70:
                    alerts.append(f"High temperature: {temp:.1f}°C")
                    score -= 20
                elif temp > 60:
                    score -= 10
            else:
                score = 90  # Minor penalty for no temperature reading

            return {
                'status': 'healthy' if score >= 80 else 'warning' if score >= 50 else 'critical',
                'score': max(0, score),
                'temperature': temp,
                'alerts': alerts
            }

        except Exception as e:
            self.logger.error(f"Error checking temperature health: {e}")
            return {'status': 'error', 'score': 0}

    @safe_execute
    async def _check_services_health(self) -> Dict[str, Any]:
        """Check critical services health"""
        try:
            critical_services = ['ssh', 'systemd-logind', 'cron']
            failed_services = []
            score = 100

            for service in critical_services:
                try:
                    stdout, stderr, returncode = await asyncio.to_thread(
                        run_command, f"systemctl is-active {service}"
                    )
                    if returncode != 0:
                        failed_services.append(service)
                        score -= 20
                except:
                    failed_services.append(service)
                    score -= 20

            alerts = []
            if failed_services:
                alerts.append(f"Failed services: {', '.join(failed_services)}")

            return {
                'status': 'healthy' if score >= 80 else 'warning' if score >= 50 else 'critical',
                'score': max(0, score),
                'failed_services': failed_services,
                'alerts': alerts
            }

        except Exception as e:
            self.logger.error(f"Error checking services health: {e}")
            return {'status': 'error', 'score': 0}

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def get_quick_stats(self) -> Dict[str, Any]:
        """Get quick system statistics"""
        try:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100,
                'load_average': os.getloadavg()[0],
                'uptime_seconds': time.time() - psutil.boot_time(),
                'processes': len(psutil.pids()),
                'users': len(psutil.users())
            }

            return stats

        except Exception as e:
            self.logger.error(f"Error getting quick stats: {e}")
            return {}

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive system report"""
        try:
            overview = await self.get_system_overview()
            health = await self.get_system_health()
            stats = await self.get_quick_stats()

            report_lines = [
                "🖥️  SYSTEM MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"🏷️  Hostname: {overview.get('hostname', 'Unknown')}",
                f"🔧 Pi Model: {overview.get('pi_model', 'Unknown')}",
                "",
                "📊 SYSTEM OVERVIEW",
                "-" * 30,
                f"⏱️  Uptime: {overview.get('uptime', {}).get('formatted', 'Unknown')}",
                f"⚡ Load Average: {overview.get('load_average', {}).get('1min', 'Unknown')}",
                f"👥 Active Users: {len(overview.get('users', []))}",
                "",
                "🔍 QUICK STATISTICS",
                "-" * 30,
                f"🖥️  CPU Usage: {stats.get('cpu_usage', 0):.1f}%",
                f"💾 Memory Usage: {stats.get('memory_usage', 0):.1f}%",
                f"💿 Disk Usage: {stats.get('disk_usage', 0):.1f}%",
                f"⚙️  Processes: {stats.get('processes', 0)}",
                "",
                "🏥 SYSTEM HEALTH",
                "-" * 30,
                f"🎯 Overall Status: {health.get('overall_status', 'Unknown')}",
                f"📊 Health Score: {health.get('score', 0):.1f}/100",
            ]

            # Add component health
            components = health.get('components', {})
            if components:
                report_lines.append("\n🔧 COMPONENT HEALTH")
                report_lines.append("-" * 30)
                for comp_name, comp_data in components.items():
                    status = comp_data.get('status', 'unknown')
                    score = comp_data.get('score', 0)
                    status_emoji = {'healthy': '🟢', 'warning': '🟡', 'critical': '🔴', 'error': '❌'}.get(status, '⚪')
                    report_lines.append(f"{status_emoji} {comp_name.title()}: {score:.1f}/100")

            # Add alerts
            alerts = health.get('alerts', [])
            if alerts:
                report_lines.append("\n⚠️  ALERTS")
                report_lines.append("-" * 30)
                for alert in alerts:
                    report_lines.append(f"🚨 {alert}")

            report_lines.append("\n" + "=" * 50)
            report_lines.append("📊 Advanced Raspberry Pi Monitoring System")

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating system report: {e}")
            return f"❌ Error generating system report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up System Monitor...")
            self._cached_data.clear()
            self.logger.info("✅ System Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during cleanup: {e}")