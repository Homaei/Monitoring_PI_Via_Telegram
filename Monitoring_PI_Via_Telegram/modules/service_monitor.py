"""
Service Monitor Module - System service monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive system service monitoring capabilities including service status tracking, health checks, and service management operations.
License: For educational and personal use
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import re

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, format_uptime
)

logger = logging.getLogger('monitoring.service')


class ServiceMonitor:
    """System service monitoring class"""

    def __init__(self):
        """Initialize the service monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 30  # seconds
        self._cached_data = {}
        self._critical_services = [
            'ssh', 'networking', 'systemd-resolved', 'systemd-logind',
            'dbus', 'cron', 'systemd-timesyncd'
        ]
        self._service_history = []
        self._max_history = 100

    async def initialize(self) -> bool:
        """Initialize the service monitor"""
        try:
            self.logger.info("🚀 Initializing Service Monitor...")

            # Test systemctl availability
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, "systemctl --version"
            )

            if returncode == 0:
                self.logger.info("✅ Service Monitor initialized - systemd detected")
                return True
            else:
                self.logger.warning("⚠️ systemctl not available, service monitoring limited")
                return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Service Monitor: {e}")
            return False

    @safe_execute
    async def get_service_list(self, service_type: str = 'all', state: str = 'all') -> List[Dict[str, Any]]:
        """Get list of system services"""
        try:
            # Check cache
            cache_key = f"services_{service_type}_{state}"
            if self._is_cached_data_valid(cache_key):
                return self._cached_data[cache_key]

            services = []

            # Build systemctl command
            cmd_parts = ["systemctl", "list-units"]

            if service_type == 'service':
                cmd_parts.append("--type=service")
            elif service_type == 'timer':
                cmd_parts.append("--type=timer")
            elif service_type == 'socket':
                cmd_parts.append("--type=socket")

            if state == 'active':
                cmd_parts.append("--state=active")
            elif state == 'failed':
                cmd_parts.append("--state=failed")
            elif state == 'inactive':
                cmd_parts.append("--state=inactive")

            cmd_parts.append("--no-pager")

            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, " ".join(cmd_parts)
            )

            if returncode == 0:
                services = await self._parse_systemctl_list(stdout)

                # Get additional details for each service
                for service in services:
                    service['details'] = await self._get_service_details(service['unit'])
                    service['status'] = await self._get_service_status(service['unit'])

            # Cache the data
            self._cached_data[cache_key] = services
            self._last_update = time.time()

            return services

        except Exception as e:
            self.logger.error(f"Error getting service list: {e}")
            return []

    @safe_execute
    async def _parse_systemctl_list(self, output: str) -> List[Dict[str, Any]]:
        """Parse systemctl list-units output"""
        try:
            services = []
            lines = output.strip().split('\n')

            # Skip header and footer
            service_lines = []
            in_service_list = False

            for line in lines:
                if 'UNIT' in line and 'LOAD' in line and 'ACTIVE' in line:
                    in_service_list = True
                    continue
                elif line.strip() == '' or 'LOAD' in line:
                    in_service_list = False
                    continue
                elif in_service_list:
                    service_lines.append(line)

            # Parse each service line
            for line in service_lines:
                parts = line.split()
                if len(parts) >= 4:
                    service_info = {
                        'unit': parts[0],
                        'load': parts[1],
                        'active': parts[2],
                        'sub': parts[3],
                        'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                    }

                    # Determine service name
                    if '.' in service_info['unit']:
                        service_info['name'] = service_info['unit'].split('.')[0]
                        service_info['type'] = service_info['unit'].split('.')[-1]
                    else:
                        service_info['name'] = service_info['unit']
                        service_info['type'] = 'unknown'

                    services.append(service_info)

            return services

        except Exception as e:
            self.logger.error(f"Error parsing systemctl output: {e}")
            return []

    @safe_execute
    async def _get_service_details(self, unit_name: str) -> Dict[str, Any]:
        """Get detailed service information"""
        try:
            details = {}

            # Get service status details
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl show {unit_name}"
            )

            if returncode == 0:
                for line in stdout.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        details[key] = value

            return details

        except Exception as e:
            self.logger.error(f"Error getting service details for {unit_name}: {e}")
            return {}

    @safe_execute
    async def _get_service_status(self, unit_name: str) -> Dict[str, Any]:
        """Get service status information"""
        try:
            status_info = {
                'is_active': False,
                'is_enabled': False,
                'is_failed': False,
                'uptime': 0,
                'memory_usage': 0,
                'pid': None,
                'start_time': None
            }

            # Check if service is active
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl is-active {unit_name}"
            )
            status_info['is_active'] = (returncode == 0 and stdout.strip() == 'active')

            # Check if service is enabled
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl is-enabled {unit_name}"
            )
            status_info['is_enabled'] = (returncode == 0 and stdout.strip() == 'enabled')

            # Check if service has failed
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl is-failed {unit_name}"
            )
            status_info['is_failed'] = (stdout.strip() == 'failed')

            # Get detailed status
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl status {unit_name} --no-pager -l"
            )

            if returncode == 0:
                status_details = await self._parse_service_status(stdout)
                status_info.update(status_details)

            return status_info

        except Exception as e:
            self.logger.error(f"Error getting service status for {unit_name}: {e}")
            return status_info

    @safe_execute
    async def _parse_service_status(self, status_output: str) -> Dict[str, Any]:
        """Parse systemctl status output"""
        try:
            status_info = {}

            # Extract PID and memory usage
            for line in status_output.split('\n'):
                line = line.strip()

                # Extract main PID
                if 'Main PID:' in line:
                    pid_match = re.search(r'Main PID: (\d+)', line)
                    if pid_match:
                        status_info['pid'] = int(pid_match.group(1))

                # Extract memory usage
                elif 'Memory:' in line:
                    memory_match = re.search(r'Memory: ([\d.]+)([KMG]?)', line)
                    if memory_match:
                        memory_value = float(memory_match.group(1))
                        memory_unit = memory_match.group(2)

                        # Convert to bytes
                        if memory_unit == 'K':
                            status_info['memory_usage'] = memory_value * 1024
                        elif memory_unit == 'M':
                            status_info['memory_usage'] = memory_value * 1024 * 1024
                        elif memory_unit == 'G':
                            status_info['memory_usage'] = memory_value * 1024 * 1024 * 1024
                        else:
                            status_info['memory_usage'] = memory_value

                # Extract start time
                elif 'since' in line and ('ago' in line or 'active' in line):
                    # Try to extract timestamp
                    time_match = re.search(r'since (.+?)(?:;|$)', line)
                    if time_match:
                        status_info['start_time_str'] = time_match.group(1).strip()

            return status_info

        except Exception as e:
            self.logger.error(f"Error parsing service status: {e}")
            return {}

    @safe_execute
    async def get_failed_services(self) -> List[Dict[str, Any]]:
        """Get list of failed services"""
        try:
            failed_services = []

            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, "systemctl list-units --state=failed --no-pager"
            )

            if returncode == 0:
                failed_services = await self._parse_systemctl_list(stdout)

                # Get failure details for each service
                for service in failed_services:
                    failure_info = await self._get_failure_info(service['unit'])
                    service['failure_info'] = failure_info

            return failed_services

        except Exception as e:
            self.logger.error(f"Error getting failed services: {e}")
            return []

    @safe_execute
    async def _get_failure_info(self, unit_name: str) -> Dict[str, Any]:
        """Get failure information for a service"""
        try:
            failure_info = {
                'exit_code': None,
                'signal': None,
                'last_logs': []
            }

            # Get service logs
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"journalctl -u {unit_name} --no-pager -n 10"
            )

            if returncode == 0:
                failure_info['last_logs'] = stdout.split('\n')[-10:]

            # Get exit status
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl show {unit_name} -p ExecMainStatus,ExecMainCode"
            )

            if returncode == 0:
                for line in stdout.split('\n'):
                    if 'ExecMainStatus=' in line:
                        status = line.split('=')[1]
                        if status and status != '0':
                            failure_info['exit_code'] = int(status)
                    elif 'ExecMainCode=' in line:
                        code = line.split('=')[1]
                        if code and code != 'exited':
                            failure_info['signal'] = code

            return failure_info

        except Exception as e:
            self.logger.error(f"Error getting failure info for {unit_name}: {e}")
            return {}

    @safe_execute
    async def get_critical_services_status(self) -> Dict[str, Any]:
        """Check status of critical services"""
        try:
            critical_status = {
                'timestamp': datetime.now().isoformat(),
                'all_critical_running': True,
                'services': {},
                'failed_services': [],
                'warnings': []
            }

            for service_name in self._critical_services:
                service_status = await self._get_service_status(f"{service_name}.service")
                critical_status['services'][service_name] = service_status

                if service_status.get('is_failed', False):
                    critical_status['failed_services'].append(service_name)
                    critical_status['all_critical_running'] = False
                elif not service_status.get('is_active', False):
                    # Some services might be inactive but not failed (by design)
                    # Only mark as warning if they should normally be running
                    critical_status['warnings'].append(f"{service_name} is not active")

            return critical_status

        except Exception as e:
            self.logger.error(f"Error checking critical services: {e}")
            return {}

    @safe_execute
    async def restart_service(self, service_name: str) -> Dict[str, Any]:
        """Restart a service"""
        try:
            result = {
                'service': service_name,
                'success': False,
                'message': '',
                'previous_status': None,
                'new_status': None
            }

            # Get status before restart
            result['previous_status'] = await self._get_service_status(service_name)

            # Restart the service
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl restart {service_name}"
            )

            if returncode == 0:
                result['success'] = True
                result['message'] = f"Service {service_name} restarted successfully"

                # Wait a moment for service to start
                await asyncio.sleep(2)

                # Get new status
                result['new_status'] = await self._get_service_status(service_name)
            else:
                result['message'] = f"Failed to restart {service_name}: {stderr}"

            return result

        except Exception as e:
            error_msg = f"Error restarting service {service_name}: {str(e)}"
            self.logger.error(error_msg)
            return {
                'service': service_name,
                'success': False,
                'message': error_msg
            }

    @safe_execute
    async def stop_service(self, service_name: str) -> Dict[str, Any]:
        """Stop a service"""
        try:
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl stop {service_name}"
            )

            return {
                'service': service_name,
                'success': returncode == 0,
                'message': f"Service {service_name} stopped" if returncode == 0 else f"Failed to stop {service_name}: {stderr}"
            }

        except Exception as e:
            return {
                'service': service_name,
                'success': False,
                'message': f"Error stopping service {service_name}: {str(e)}"
            }

    @safe_execute
    async def start_service(self, service_name: str) -> Dict[str, Any]:
        """Start a service"""
        try:
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"systemctl start {service_name}"
            )

            return {
                'service': service_name,
                'success': returncode == 0,
                'message': f"Service {service_name} started" if returncode == 0 else f"Failed to start {service_name}: {stderr}"
            }

        except Exception as e:
            return {
                'service': service_name,
                'success': False,
                'message': f"Error starting service {service_name}: {str(e)}"
            }

    @safe_execute
    async def get_service_logs(self, service_name: str, lines: int = 50) -> Dict[str, Any]:
        """Get service logs"""
        try:
            logs_info = {
                'service': service_name,
                'logs': [],
                'total_lines': 0
            }

            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"journalctl -u {service_name} --no-pager -n {lines}"
            )

            if returncode == 0:
                log_lines = stdout.strip().split('\n')
                logs_info['logs'] = log_lines
                logs_info['total_lines'] = len(log_lines)

            return logs_info

        except Exception as e:
            self.logger.error(f"Error getting logs for {service_name}: {e}")
            return {'service': service_name, 'logs': [], 'error': str(e)}

    @safe_execute
    async def get_systemd_status(self) -> Dict[str, Any]:
        """Get overall systemd status"""
        try:
            systemd_status = {
                'timestamp': datetime.now().isoformat(),
                'is_running': False,
                'failed_units': 0,
                'total_units': 0,
                'active_units': 0,
                'degraded': False
            }

            # Check systemd status
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, "systemctl status --no-pager -l"
            )

            if returncode == 0 or 'degraded' in stdout.lower():
                systemd_status['is_running'] = True
                if 'degraded' in stdout.lower():
                    systemd_status['degraded'] = True

            # Get unit statistics
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, "systemctl list-units --no-pager | tail -1"
            )

            if returncode == 0:
                # Parse summary line
                summary_match = re.search(r'(\d+) loaded units listed', stdout)
                if summary_match:
                    systemd_status['total_units'] = int(summary_match.group(1))

                # Get failed units count
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "systemctl list-units --state=failed --no-pager | wc -l"
                )
                if returncode == 0:
                    # Subtract header lines
                    failed_count = max(0, int(stdout.strip()) - 3)
                    systemd_status['failed_units'] = failed_count

                # Get active units count
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "systemctl list-units --state=active --no-pager | wc -l"
                )
                if returncode == 0:
                    active_count = max(0, int(stdout.strip()) - 3)
                    systemd_status['active_units'] = active_count

            return systemd_status

        except Exception as e:
            self.logger.error(f"Error getting systemd status: {e}")
            return {}

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive service report"""
        try:
            systemd_status = await self.get_systemd_status()
            critical_status = await self.get_critical_services_status()
            failed_services = await self.get_failed_services()
            active_services = await self.get_service_list(service_type='service', state='active')

            report_lines = [
                "⚙️  SERVICE MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add systemd overall status
            systemd_running = "🟢 Running" if systemd_status.get('is_running') else "🔴 Not Running"
            systemd_degraded = " (🟡 Degraded)" if systemd_status.get('degraded') else ""

            report_lines.extend([
                "",
                "🖥️  SYSTEMD STATUS",
                "-" * 30,
                f"📊 Status: {systemd_running}{systemd_degraded}",
                f"📈 Total Units: {systemd_status.get('total_units', 0)}",
                f"✅ Active Units: {systemd_status.get('active_units', 0)}",
                f"❌ Failed Units: {systemd_status.get('failed_units', 0)}",
            ])

            # Add critical services status
            all_critical_ok = critical_status.get('all_critical_running', False)
            critical_status_text = "🟢 All OK" if all_critical_ok else "🔴 Issues Found"

            report_lines.extend([
                "",
                "🔒 CRITICAL SERVICES",
                "-" * 30,
                f"📊 Status: {critical_status_text}",
            ])

            # List critical services
            for service_name, service_status in critical_status.get('services', {}).items():
                if service_status.get('is_active'):
                    status_emoji = "🟢"
                    status_text = "Active"
                elif service_status.get('is_failed'):
                    status_emoji = "🔴"
                    status_text = "Failed"
                else:
                    status_emoji = "🟡"
                    status_text = "Inactive"

                report_lines.append(f"{status_emoji} {service_name}: {status_text}")

            # Add failed services details
            if failed_services:
                report_lines.extend([
                    "",
                    "❌ FAILED SERVICES",
                    "-" * 30,
                ])
                for service in failed_services:
                    service_name = service.get('name', service.get('unit', 'Unknown'))
                    description = service.get('description', 'No description')
                    report_lines.append(f"🔴 {service_name}: {description}")

            # Add service statistics
            service_types = {}
            for service in active_services:
                service_type = service.get('type', 'unknown')
                service_types[service_type] = service_types.get(service_type, 0) + 1

            if service_types:
                report_lines.extend([
                    "",
                    "📊 ACTIVE SERVICES BY TYPE",
                    "-" * 30,
                ])
                for service_type, count in sorted(service_types.items()):
                    report_lines.append(f"🔹 {service_type}: {count}")

            # Add warnings
            warnings = critical_status.get('warnings', [])
            if warnings:
                report_lines.extend([
                    "",
                    "⚠️  WARNINGS",
                    "-" * 30,
                ] + [f"🟡 {warning}" for warning in warnings])

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating service report: {e}")
            return f"❌ Error generating service report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Service Monitor...")
            self._cached_data.clear()
            self._service_history.clear()
            self.logger.info("✅ Service Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Service Monitor cleanup: {e}")