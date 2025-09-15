"""
Report Manager Module - Report generation and management

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive report generation and management capabilities including automated reporting, multiple formats, and report scheduling functionality.
License: For educational and personal use
"""

import asyncio
import json
import logging
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import csv
from enum import Enum

from config.settings import REPORTS_DIR, DATA_DIR, MONITORING_CONFIG
from utils.helpers import safe_execute, format_bytes

logger = logging.getLogger('monitoring.report_manager')


class ReportFormat(Enum):
    """Report output formats"""
    TEXT = "text"
    JSON = "json"
    CSV = "csv"
    HTML = "html"


class ReportType(Enum):
    """Report types"""
    SYSTEM_OVERVIEW = "system_overview"
    PERFORMANCE = "performance"
    SECURITY = "security"
    ALERTS = "alerts"
    USERS = "users"
    COMPREHENSIVE = "comprehensive"
    CUSTOM = "custom"


class ReportManager:
    """Report generation and management class"""

    def __init__(self):
        """Initialize the report manager"""
        self.logger = logger
        self._reports_dir = Path(REPORTS_DIR)
        self._report_templates = {}
        self._scheduled_reports = {}
        self._report_history = []
        self._max_history = 100
        self._generators = {}  # report_type -> generator_function

    async def initialize(self) -> bool:
        """Initialize the report manager"""
        try:
            self.logger.info("🚀 Initializing Report Manager...")

            # Ensure reports directory exists
            self._reports_dir.mkdir(parents=True, exist_ok=True)

            # Setup report generators
            await self._setup_generators()

            # Load report history
            await self._load_report_history()

            # Clean up old reports
            await self._cleanup_old_reports()

            self.logger.info("✅ Report Manager initialized")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Report Manager: {e}")
            return False

    @safe_execute
    async def _setup_generators(self):
        """Setup report generators for different modules"""
        try:
            self._generators = {
                ReportType.SYSTEM_OVERVIEW.value: self._generate_system_overview,
                ReportType.PERFORMANCE.value: self._generate_performance_report,
                ReportType.SECURITY.value: self._generate_security_report,
                ReportType.ALERTS.value: self._generate_alerts_report,
                ReportType.USERS.value: self._generate_users_report,
                ReportType.COMPREHENSIVE.value: self._generate_comprehensive_report
            }
            self.logger.info(f"Setup {len(self._generators)} report generators")

        except Exception as e:
            self.logger.error(f"Error setting up generators: {e}")

    @safe_execute
    async def _load_report_history(self):
        """Load report generation history"""
        try:
            history_file = self._reports_dir / "report_history.json"
            if history_file.exists():
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    self._report_history = data.get('history', [])
                    self._scheduled_reports = data.get('scheduled', {})
        except Exception as e:
            self.logger.error(f"Error loading report history: {e}")
            self._report_history = []
            self._scheduled_reports = {}

    @safe_execute
    async def _save_report_history(self):
        """Save report generation history"""
        try:
            history_file = self._reports_dir / "report_history.json"
            data = {
                'history': self._report_history[-self._max_history:],
                'scheduled': self._scheduled_reports,
                'last_updated': datetime.now().isoformat()
            }
            with open(history_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving report history: {e}")

    @safe_execute
    async def generate_report(self, report_type: str, format: ReportFormat = ReportFormat.TEXT,
                            options: Dict[str, Any] = None, save_to_file: bool = True) -> Dict[str, Any]:
        """Generate a report of specified type and format"""
        try:
            start_time = time.time()
            options = options or {}

            # Check if generator exists
            if report_type not in self._generators:
                return {
                    'success': False,
                    'error': f"Unknown report type: {report_type}",
                    'available_types': list(self._generators.keys())
                }

            # Generate report content
            generator = self._generators[report_type]
            report_content = await generator(options)

            if not report_content:
                return {
                    'success': False,
                    'error': f"Failed to generate {report_type} report"
                }

            # Format report
            formatted_content = await self._format_report(report_content, format, report_type)

            # Save to file if requested
            file_path = None
            if save_to_file:
                file_path = await self._save_report_to_file(
                    formatted_content, report_type, format
                )

            # Record in history
            generation_time = time.time() - start_time
            history_entry = {
                'report_type': report_type,
                'format': format.value,
                'generated_at': datetime.now().isoformat(),
                'generation_time': round(generation_time, 2),
                'file_path': str(file_path) if file_path else None,
                'size_bytes': len(formatted_content) if isinstance(formatted_content, str) else 0,
                'options': options
            }

            self._report_history.append(history_entry)
            await self._save_report_history()

            self.logger.info(
                f"Generated {report_type} report in {generation_time:.2f}s "
                f"({len(formatted_content) if isinstance(formatted_content, str) else 0} chars)"
            )

            return {
                'success': True,
                'report_type': report_type,
                'format': format.value,
                'content': formatted_content,
                'file_path': str(file_path) if file_path else None,
                'generation_time': generation_time,
                'metadata': history_entry
            }

        except Exception as e:
            self.logger.error(f"Error generating {report_type} report: {e}")
            return {
                'success': False,
                'error': str(e),
                'report_type': report_type
            }

    @safe_execute
    async def _generate_system_overview(self, options: Dict[str, Any]) -> str:
        """Generate system overview report"""
        try:
            # This would typically call the system monitor's generate_report method
            # For now, we'll create a basic system overview

            report_lines = [
                "🖥️  SYSTEM OVERVIEW REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "📊 SYSTEM INFORMATION",
                "-" * 30,
                f"🏷️  Hostname: {os.uname().nodename}",
                f"🖥️  System: {os.uname().sysname} {os.uname().release}",
                f"🔧 Architecture: {os.uname().machine}",
                "",
                "⏱️  UPTIME & LOAD",
                "-" * 30,
            ]

            # Add load average if available
            try:
                load_avg = os.getloadavg()
                report_lines.extend([
                    f"📈 Load Average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}",
                ])
            except:
                report_lines.append("📈 Load Average: Not available")

            # Add basic resource info
            try:
                import psutil
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')

                report_lines.extend([
                    "",
                    "💾 RESOURCES",
                    "-" * 30,
                    f"🧠 Memory: {memory.percent:.1f}% used ({format_bytes(memory.used)}/{format_bytes(memory.total)})",
                    f"💿 Disk: {(disk.used/disk.total)*100:.1f}% used ({format_bytes(disk.used)}/{format_bytes(disk.total)})",
                ])
            except:
                pass

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating system overview: {e}")
            return f"❌ Error generating system overview: {e}"

    @safe_execute
    async def _generate_performance_report(self, options: Dict[str, Any]) -> str:
        """Generate performance report"""
        try:
            report_lines = [
                "📊 PERFORMANCE REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "🖥️  CPU PERFORMANCE",
                "-" * 30,
            ]

            try:
                import psutil

                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_count = psutil.cpu_count()
                load_avg = os.getloadavg()

                report_lines.extend([
                    f"📊 CPU Usage: {cpu_percent:.1f}%",
                    f"🔢 CPU Cores: {cpu_count}",
                    f"📈 Load Average: {load_avg[0]:.2f} (1min)",
                    "",
                    "💾 MEMORY PERFORMANCE",
                    "-" * 30,
                ])

                # Memory usage
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()

                report_lines.extend([
                    f"🧠 Memory Usage: {memory.percent:.1f}%",
                    f"📦 Available: {format_bytes(memory.available)}",
                    f"🔄 Swap Usage: {swap.percent:.1f}%",
                    "",
                    "💿 DISK PERFORMANCE",
                    "-" * 30,
                ])

                # Disk usage
                disk = psutil.disk_usage('/')
                disk_io = psutil.disk_io_counters()

                report_lines.extend([
                    f"📊 Disk Usage: {(disk.used/disk.total)*100:.1f}%",
                    f"📖 Read Operations: {disk_io.read_count:,}" if disk_io else "📖 Read Operations: N/A",
                    f"✏️  Write Operations: {disk_io.write_count:,}" if disk_io else "✏️  Write Operations: N/A",
                ])

            except Exception as e:
                report_lines.append(f"❌ Error collecting performance data: {e}")

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating performance report: {e}")
            return f"❌ Error generating performance report: {e}"

    @safe_execute
    async def _generate_security_report(self, options: Dict[str, Any]) -> str:
        """Generate security report"""
        try:
            report_lines = [
                "🔒 SECURITY REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "🛡️  BASIC SECURITY CHECKS",
                "-" * 30,
            ]

            # Basic security checks
            security_items = []

            # Check SSH configuration
            try:
                ssh_config_path = '/etc/ssh/sshd_config'
                if os.path.exists(ssh_config_path):
                    with open(ssh_config_path, 'r') as f:
                        ssh_config = f.read()
                        if 'PermitRootLogin no' in ssh_config:
                            security_items.append("✅ Root SSH login disabled")
                        else:
                            security_items.append("⚠️ Root SSH login may be enabled")

                        if 'PasswordAuthentication no' in ssh_config:
                            security_items.append("✅ Password authentication disabled")
                        else:
                            security_items.append("ℹ️ Password authentication enabled")
                else:
                    security_items.append("❓ SSH configuration not found")
            except Exception as e:
                security_items.append(f"❌ Could not check SSH config: {e}")

            # Check firewall status
            try:
                import subprocess
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if 'Status: active' in result.stdout:
                        security_items.append("✅ UFW firewall is active")
                    else:
                        security_items.append("⚠️ UFW firewall is inactive")
                else:
                    security_items.append("❓ Could not check UFW status")
            except:
                security_items.append("❓ UFW not available or accessible")

            # Check for updates
            try:
                result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    update_count = len(result.stdout.split('\n')) - 2  # Subtract header and empty line
                    if update_count > 0:
                        security_items.append(f"⚠️ {update_count} package updates available")
                    else:
                        security_items.append("✅ System is up to date")
            except:
                security_items.append("❓ Could not check for updates")

            report_lines.extend(security_items)

            report_lines.extend([
                "",
                "📋 RECOMMENDATIONS",
                "-" * 30,
                "• Regularly update system packages",
                "• Use key-based SSH authentication",
                "• Enable and configure firewall",
                "• Monitor system logs for suspicious activity",
                "• Use strong passwords for all accounts",
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating security report: {e}")
            return f"❌ Error generating security report: {e}"

    @safe_execute
    async def _generate_alerts_report(self, options: Dict[str, Any]) -> str:
        """Generate alerts report"""
        try:
            return "🚨 ALERTS REPORT - Integration with Alert Manager needed"
        except Exception as e:
            self.logger.error(f"Error generating alerts report: {e}")
            return f"❌ Error generating alerts report: {e}"

    @safe_execute
    async def _generate_users_report(self, options: Dict[str, Any]) -> str:
        """Generate users report"""
        try:
            return "👥 USERS REPORT - Integration with User Manager needed"
        except Exception as e:
            self.logger.error(f"Error generating users report: {e}")
            return f"❌ Error generating users report: {e}"

    @safe_execute
    async def _generate_comprehensive_report(self, options: Dict[str, Any]) -> str:
        """Generate comprehensive report combining all modules"""
        try:
            report_sections = []

            # Generate individual reports
            system_report = await self._generate_system_overview(options)
            performance_report = await self._generate_performance_report(options)
            security_report = await self._generate_security_report(options)

            # Combine reports
            comprehensive_report = [
                "📊 COMPREHENSIVE SYSTEM REPORT",
                "=" * 60,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                system_report,
                "\n" + "=" * 60 + "\n",
                performance_report,
                "\n" + "=" * 60 + "\n",
                security_report,
                "",
                "=" * 60,
                "📊 Advanced Raspberry Pi Monitoring System - Comprehensive Report Complete"
            ]

            return "\n".join(comprehensive_report)

        except Exception as e:
            self.logger.error(f"Error generating comprehensive report: {e}")
            return f"❌ Error generating comprehensive report: {e}"

    @safe_execute
    async def _format_report(self, content: str, format: ReportFormat, report_type: str) -> Any:
        """Format report content according to specified format"""
        try:
            if format == ReportFormat.TEXT:
                return content

            elif format == ReportFormat.JSON:
                # Convert text report to structured JSON
                return json.dumps({
                    'report_type': report_type,
                    'generated_at': datetime.now().isoformat(),
                    'content': content,
                    'format': 'json'
                }, indent=2)

            elif format == ReportFormat.HTML:
                # Convert to HTML
                html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{report_type.replace('_', ' ').title()} Report</title>
    <style>
        body {{ font-family: monospace; background: #1e1e1e; color: #f0f0f0; padding: 20px; }}
        pre {{ white-space: pre-wrap; line-height: 1.4; }}
        .header {{ color: #4CAF50; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report_type.replace('_', ' ').title()} Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <pre>{content}</pre>
</body>
</html>"""
                return html_content

            elif format == ReportFormat.CSV:
                # Convert to CSV (simplified)
                lines = content.split('\n')
                csv_data = []
                for line in lines:
                    if line.strip() and not line.startswith('=') and not line.startswith('-'):
                        csv_data.append([line.strip()])

                import io
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(['Report Content'])
                writer.writerows(csv_data)
                return output.getvalue()

            else:
                return content

        except Exception as e:
            self.logger.error(f"Error formatting report: {e}")
            return content

    @safe_execute
    async def _save_report_to_file(self, content: Any, report_type: str, format: ReportFormat) -> Optional[Path]:
        """Save report content to file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_{timestamp}.{format.value}"
            file_path = self._reports_dir / filename

            # Write content to file
            mode = 'w' if isinstance(content, str) else 'wb'
            with open(file_path, mode, encoding='utf-8' if mode == 'w' else None) as f:
                f.write(content)

            self.logger.info(f"Saved report to: {file_path}")
            return file_path

        except Exception as e:
            self.logger.error(f"Error saving report to file: {e}")
            return None

    @safe_execute
    async def get_report_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get report generation history"""
        try:
            return self._report_history[-limit:] if limit else self._report_history
        except Exception as e:
            self.logger.error(f"Error getting report history: {e}")
            return []

    @safe_execute
    async def get_available_reports(self) -> List[str]:
        """Get list of available report types"""
        try:
            return list(self._generators.keys())
        except Exception as e:
            self.logger.error(f"Error getting available reports: {e}")
            return []

    @safe_execute
    async def delete_old_reports(self, days_old: int = 30) -> Dict[str, Any]:
        """Delete reports older than specified days"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            deleted_files = []
            deleted_size = 0

            for file_path in self._reports_dir.glob("*"):
                if file_path.is_file():
                    try:
                        file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                        if file_mtime < cutoff_date:
                            file_size = file_path.stat().st_size
                            file_path.unlink()
                            deleted_files.append(str(file_path.name))
                            deleted_size += file_size
                    except Exception as e:
                        self.logger.error(f"Error processing file {file_path}: {e}")

            self.logger.info(f"Deleted {len(deleted_files)} old report files ({format_bytes(deleted_size)})")

            return {
                'deleted_count': len(deleted_files),
                'deleted_size': deleted_size,
                'deleted_files': deleted_files
            }

        except Exception as e:
            self.logger.error(f"Error deleting old reports: {e}")
            return {'deleted_count': 0, 'deleted_size': 0, 'deleted_files': []}

    @safe_execute
    async def _cleanup_old_reports(self):
        """Clean up old reports (called during initialization)"""
        try:
            # Delete reports older than 90 days
            result = await self.delete_old_reports(90)
            if result['deleted_count'] > 0:
                self.logger.info(f"Cleaned up {result['deleted_count']} old report files")
        except Exception as e:
            self.logger.error(f"Error during report cleanup: {e}")

    @safe_execute
    async def get_report_statistics(self) -> Dict[str, Any]:
        """Get report generation statistics"""
        try:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'total_reports': len(self._report_history),
                'by_type': {},
                'by_format': {},
                'avg_generation_time': 0,
                'total_size_bytes': 0,
                'recent_reports': 0
            }

            # Analyze report history
            generation_times = []
            cutoff_time = datetime.now() - timedelta(hours=24)

            for entry in self._report_history:
                # Count by type
                report_type = entry.get('report_type', 'unknown')
                stats['by_type'][report_type] = stats['by_type'].get(report_type, 0) + 1

                # Count by format
                format_type = entry.get('format', 'unknown')
                stats['by_format'][format_type] = stats['by_format'].get(format_type, 0) + 1

                # Collect generation times
                gen_time = entry.get('generation_time', 0)
                if gen_time > 0:
                    generation_times.append(gen_time)

                # Count size
                size = entry.get('size_bytes', 0)
                if size > 0:
                    stats['total_size_bytes'] += size

                # Count recent reports
                try:
                    entry_time = datetime.fromisoformat(entry['generated_at'])
                    if entry_time >= cutoff_time:
                        stats['recent_reports'] += 1
                except:
                    pass

            # Calculate average generation time
            if generation_times:
                stats['avg_generation_time'] = sum(generation_times) / len(generation_times)

            # Get disk usage
            try:
                total_size = sum(f.stat().st_size for f in self._reports_dir.glob("*") if f.is_file())
                stats['disk_usage_bytes'] = total_size
                stats['disk_usage_formatted'] = format_bytes(total_size)
            except:
                stats['disk_usage_bytes'] = 0

            return stats

        except Exception as e:
            self.logger.error(f"Error getting report statistics: {e}")
            return {}

    @safe_execute
    async def generate_report_summary(self) -> str:
        """Generate a summary report about report manager"""
        try:
            stats = await self.get_report_statistics()
            recent_reports = await self.get_report_history(10)

            report_lines = [
                "📊 REPORT MANAGER SUMMARY",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "📈 REPORT STATISTICS",
                "-" * 30,
                f"📊 Total Reports: {stats.get('total_reports', 0)}",
                f"🕐 Recent Reports (24h): {stats.get('recent_reports', 0)}",
                f"⏱️ Avg Generation Time: {stats.get('avg_generation_time', 0):.2f}s",
                f"💾 Disk Usage: {stats.get('disk_usage_formatted', '0 B')}",
            ]

            # Add report types
            by_type = stats.get('by_type', {})
            if by_type:
                report_lines.extend([
                    "",
                    "📋 REPORTS BY TYPE",
                    "-" * 30,
                ])
                for report_type, count in sorted(by_type.items()):
                    type_display = report_type.replace('_', ' ').title()
                    report_lines.append(f"🔹 {type_display}: {count}")

            # Add recent reports
            if recent_reports:
                report_lines.extend([
                    "",
                    "🕐 RECENT REPORTS",
                    "-" * 30,
                ])
                for report in recent_reports[-5:]:  # Show last 5
                    report_type = report.get('report_type', 'unknown').replace('_', ' ').title()
                    gen_time = report.get('generation_time', 0)
                    try:
                        timestamp = datetime.fromisoformat(report['generated_at'])
                        time_str = timestamp.strftime('%H:%M:%S')
                    except:
                        time_str = 'Unknown'

                    report_lines.append(f"🔹 {report_type} at {time_str} ({gen_time:.1f}s)")

            # Add available report types
            available_reports = await self.get_available_reports()
            report_lines.extend([
                "",
                "📚 AVAILABLE REPORT TYPES",
                "-" * 30,
            ])
            for report_type in available_reports:
                type_display = report_type.replace('_', ' ').title()
                report_lines.append(f"🔹 {type_display}")

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating report summary: {e}")
            return f"❌ Error generating report summary: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Report Manager...")

            # Save any pending history
            await self._save_report_history()

            # Clean up old reports
            await self._cleanup_old_reports()

            self.logger.info("✅ Report Manager cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Report Manager cleanup: {e}")