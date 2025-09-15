"""
Process Monitor Module - Process management and monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive process monitoring and management capabilities including process tracking, resource usage analysis, and process lifecycle management.
License: For educational and personal use
"""

import asyncio
import logging
import signal
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import psutil

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, format_bytes, format_uptime
)

logger = logging.getLogger('monitoring.process')


class ProcessMonitor:
    """Process management and monitoring class"""

    def __init__(self):
        """Initialize the process monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 5  # seconds
        self._cached_data = {}
        self._process_history = []
        self._max_history = 100  # Keep 100 process snapshots

    async def initialize(self) -> bool:
        """Initialize the process monitor"""
        try:
            self.logger.info("🚀 Initializing Process Monitor...")

            # Get initial process count
            process_count = len(psutil.pids())
            self.logger.info(f"✅ Process Monitor initialized - {process_count} processes running")

            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Process Monitor: {e}")
            return False

    @safe_execute
    async def get_process_list(self, sort_by: str = 'cpu', limit: int = 50) -> List[Dict[str, Any]]:
        """Get detailed list of running processes"""
        try:
            processes = []

            # Define attributes to collect
            attrs = [
                'pid', 'ppid', 'name', 'username', 'status', 'create_time',
                'cpu_percent', 'memory_percent', 'memory_info', 'num_threads',
                'cmdline', 'cwd', 'exe'
            ]

            for proc in psutil.process_iter(attrs):
                try:
                    pinfo = proc.info

                    # Calculate process uptime
                    create_time = datetime.fromtimestamp(pinfo['create_time'])
                    uptime_seconds = (datetime.now() - create_time).total_seconds()

                    process_data = {
                        'pid': pinfo['pid'],
                        'ppid': pinfo['ppid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'] or 'Unknown',
                        'status': pinfo['status'],
                        'create_time': create_time.isoformat(),
                        'uptime': uptime_seconds,
                        'uptime_formatted': format_uptime(uptime_seconds),
                        'cpu_percent': round(pinfo['cpu_percent'] or 0, 2),
                        'memory_percent': round(pinfo['memory_percent'] or 0, 2),
                        'num_threads': pinfo['num_threads'] or 0,
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                        'cwd': pinfo['cwd'] or 'Unknown',
                        'exe': pinfo['exe'] or 'Unknown'
                    }

                    # Add memory information
                    memory_info = pinfo.get('memory_info')
                    if memory_info:
                        process_data['memory_rss'] = memory_info.rss
                        process_data['memory_vms'] = memory_info.vms
                        process_data['memory_rss_formatted'] = format_bytes(memory_info.rss)
                        process_data['memory_vms_formatted'] = format_bytes(memory_info.vms)
                    else:
                        process_data['memory_rss'] = 0
                        process_data['memory_vms'] = 0
                        process_data['memory_rss_formatted'] = '0 B'
                        process_data['memory_vms_formatted'] = '0 B'

                    # Add process classification
                    process_data['classification'] = await self._classify_process(process_data)

                    processes.append(process_data)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.logger.debug(f"Error processing process info: {e}")
                    continue

            # Sort processes
            if sort_by == 'cpu':
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            elif sort_by == 'memory':
                processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            elif sort_by == 'pid':
                processes.sort(key=lambda x: x['pid'])
            elif sort_by == 'name':
                processes.sort(key=lambda x: x['name'].lower())
            elif sort_by == 'uptime':
                processes.sort(key=lambda x: x['uptime'], reverse=True)

            return processes[:limit]

        except Exception as e:
            self.logger.error(f"Error getting process list: {e}")
            return []

    @safe_execute
    async def _classify_process(self, process_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify process type and importance"""
        try:
            name = process_data.get('name', '').lower()
            cmdline = process_data.get('cmdline', '').lower()
            username = process_data.get('username', '').lower()

            classification = {
                'type': 'user',
                'category': 'other',
                'importance': 'normal',
                'description': 'User process'
            }

            # System processes
            if username in ['root', 'system']:
                classification['type'] = 'system'
                classification['importance'] = 'high'

            # Kernel processes
            if name.startswith('[') and name.endswith(']'):
                classification.update({
                    'type': 'kernel',
                    'category': 'kernel',
                    'importance': 'critical',
                    'description': 'Kernel thread'
                })
                return classification

            # Service processes
            service_indicators = ['systemd', 'daemon', 'service']
            if any(indicator in name for indicator in service_indicators):
                classification.update({
                    'type': 'service',
                    'category': 'service',
                    'importance': 'high',
                    'description': 'System service'
                })

            # Web servers
            web_servers = ['apache', 'nginx', 'httpd', 'lighttpd']
            if any(server in name for server in web_servers):
                classification.update({
                    'category': 'webserver',
                    'description': 'Web server'
                })

            # Database processes
            databases = ['mysql', 'postgres', 'redis', 'mongo', 'sqlite']
            if any(db in name for db in databases):
                classification.update({
                    'category': 'database',
                    'description': 'Database server'
                })

            # Security processes
            security_procs = ['ssh', 'firewall', 'antivirus', 'security']
            if any(sec in name for sec in security_procs):
                classification.update({
                    'category': 'security',
                    'importance': 'high',
                    'description': 'Security process'
                })

            # Container/virtualization
            container_procs = ['docker', 'containerd', 'kubelet', 'qemu', 'kvm']
            if any(container in name for container in container_procs):
                classification.update({
                    'category': 'container',
                    'description': 'Container/VM process'
                })

            # Development tools
            dev_tools = ['python', 'node', 'java', 'ruby', 'php', 'go']
            if any(tool in name for tool in dev_tools):
                classification.update({
                    'category': 'development',
                    'description': 'Development tool'
                })

            return classification

        except Exception as e:
            self.logger.error(f"Error classifying process: {e}")
            return {'type': 'unknown', 'category': 'other', 'importance': 'normal', 'description': 'Unknown'}

    @safe_execute
    async def get_process_summary(self) -> Dict[str, Any]:
        """Get process summary statistics"""
        try:
            # Check cache
            if self._is_cached_data_valid('summary'):
                return self._cached_data['summary']

            summary = {
                'timestamp': datetime.now().isoformat(),
                'total_processes': 0,
                'running_processes': 0,
                'sleeping_processes': 0,
                'stopped_processes': 0,
                'zombie_processes': 0,
                'by_user': {},
                'by_status': {},
                'top_cpu': [],
                'top_memory': [],
                'resource_intensive': []
            }

            cpu_threshold = 10.0  # CPU % threshold
            memory_threshold = 5.0  # Memory % threshold

            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    summary['total_processes'] += 1

                    # Count by status
                    status = pinfo['status']
                    summary['by_status'][status] = summary['by_status'].get(status, 0) + 1

                    if status == 'running':
                        summary['running_processes'] += 1
                    elif status == 'sleeping':
                        summary['sleeping_processes'] += 1
                    elif status == 'stopped':
                        summary['stopped_processes'] += 1
                    elif status == 'zombie':
                        summary['zombie_processes'] += 1

                    # Count by user
                    username = pinfo['username'] or 'Unknown'
                    summary['by_user'][username] = summary['by_user'].get(username, 0) + 1

                    # Track high resource usage
                    cpu_percent = pinfo['cpu_percent'] or 0
                    memory_percent = pinfo['memory_percent'] or 0

                    if cpu_percent >= cpu_threshold or memory_percent >= memory_threshold:
                        summary['resource_intensive'].append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'cpu_percent': cpu_percent,
                            'memory_percent': memory_percent
                        })

                    # Track top processes
                    if cpu_percent > 0:
                        summary['top_cpu'].append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'cpu_percent': cpu_percent
                        })

                    if memory_percent > 0:
                        summary['top_memory'].append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'memory_percent': memory_percent
                        })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Sort and limit top processes
            summary['top_cpu'].sort(key=lambda x: x['cpu_percent'], reverse=True)
            summary['top_cpu'] = summary['top_cpu'][:10]

            summary['top_memory'].sort(key=lambda x: x['memory_percent'], reverse=True)
            summary['top_memory'] = summary['top_memory'][:10]

            summary['resource_intensive'].sort(key=lambda x: x['cpu_percent'] + x['memory_percent'], reverse=True)

            # Cache the data
            self._cached_data['summary'] = summary
            self._last_update = time.time()

            return summary

        except Exception as e:
            self.logger.error(f"Error getting process summary: {e}")
            return {}

    @safe_execute
    async def get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific process"""
        try:
            proc = psutil.Process(pid)

            # Get basic process info
            process_details = {
                'pid': proc.pid,
                'ppid': proc.ppid(),
                'name': proc.name(),
                'exe': proc.exe() if proc.exe() else 'Unknown',
                'cmdline': proc.cmdline(),
                'cwd': proc.cwd() if proc.cwd() else 'Unknown',
                'username': proc.username(),
                'status': proc.status(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'num_threads': proc.num_threads(),
            }

            # Calculate uptime
            create_time = datetime.fromtimestamp(proc.create_time())
            uptime_seconds = (datetime.now() - create_time).total_seconds()
            process_details['uptime'] = uptime_seconds
            process_details['uptime_formatted'] = format_uptime(uptime_seconds)

            # Get resource usage
            try:
                cpu_percent = proc.cpu_percent(interval=1)
                process_details['cpu_percent'] = round(cpu_percent, 2)
            except:
                process_details['cpu_percent'] = 0

            try:
                memory_info = proc.memory_info()
                memory_percent = proc.memory_percent()
                process_details['memory_info'] = {
                    'rss': memory_info.rss,
                    'vms': memory_info.vms,
                    'rss_formatted': format_bytes(memory_info.rss),
                    'vms_formatted': format_bytes(memory_info.vms),
                    'percent': round(memory_percent, 2)
                }
            except:
                process_details['memory_info'] = {}

            # Get I/O information
            try:
                io_counters = proc.io_counters()
                process_details['io_info'] = {
                    'read_count': io_counters.read_count,
                    'write_count': io_counters.write_count,
                    'read_bytes': io_counters.read_bytes,
                    'write_bytes': io_counters.write_bytes,
                    'read_bytes_formatted': format_bytes(io_counters.read_bytes),
                    'write_bytes_formatted': format_bytes(io_counters.write_bytes)
                }
            except:
                process_details['io_info'] = {}

            # Get file descriptors
            try:
                num_fds = proc.num_fds()
                process_details['num_fds'] = num_fds
            except:
                process_details['num_fds'] = 0

            # Get connections
            try:
                connections = proc.connections()
                process_details['connections'] = len(connections)
                process_details['connection_details'] = [
                    {
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    } for conn in connections[:10]  # Limit to first 10
                ]
            except:
                process_details['connections'] = 0
                process_details['connection_details'] = []

            # Get environment variables (limited)
            try:
                environ = proc.environ()
                # Only include safe environment variables
                safe_env_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'PWD']
                process_details['environment'] = {
                    key: environ.get(key) for key in safe_env_vars if key in environ
                }
            except:
                process_details['environment'] = {}

            # Get child processes
            try:
                children = proc.children()
                process_details['children'] = [
                    {'pid': child.pid, 'name': child.name()} for child in children
                ]
            except:
                process_details['children'] = []

            return process_details

        except psutil.NoSuchProcess:
            return None
        except Exception as e:
            self.logger.error(f"Error getting process details for PID {pid}: {e}")
            return None

    @safe_execute
    async def kill_process(self, pid: int, force: bool = False) -> Dict[str, Any]:
        """Kill a process by PID"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()

            result = {
                'pid': pid,
                'name': proc_name,
                'success': False,
                'message': ''
            }

            if force:
                proc.kill()  # SIGKILL
                result['message'] = f'Process {proc_name} (PID: {pid}) forcefully killed'
            else:
                proc.terminate()  # SIGTERM
                result['message'] = f'Process {proc_name} (PID: {pid}) terminated'

            # Wait for process to actually terminate
            try:
                proc.wait(timeout=5)
                result['success'] = True
            except psutil.TimeoutExpired:
                if not force:
                    # Try force kill if terminate didn't work
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                        result['success'] = True
                        result['message'] += ' (forced after timeout)'
                    except psutil.TimeoutExpired:
                        result['message'] = f'Failed to kill process {proc_name} (PID: {pid})'
                else:
                    result['message'] = f'Failed to kill process {proc_name} (PID: {pid})'

            return result

        except psutil.NoSuchProcess:
            return {
                'pid': pid,
                'success': False,
                'message': f'Process with PID {pid} not found'
            }
        except psutil.AccessDenied:
            return {
                'pid': pid,
                'success': False,
                'message': f'Access denied when trying to kill process PID {pid}'
            }
        except Exception as e:
            return {
                'pid': pid,
                'success': False,
                'message': f'Error killing process PID {pid}: {str(e)}'
            }

    @safe_execute
    async def get_zombie_processes(self) -> List[Dict[str, Any]]:
        """Get list of zombie processes"""
        try:
            zombies = []

            for proc in psutil.process_iter(['pid', 'name', 'status', 'ppid', 'create_time']):
                try:
                    if proc.info['status'] == 'zombie':
                        create_time = datetime.fromtimestamp(proc.info['create_time'])
                        zombies.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'ppid': proc.info['ppid'],
                            'create_time': create_time.isoformat(),
                            'age': (datetime.now() - create_time).total_seconds()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            return zombies

        except Exception as e:
            self.logger.error(f"Error getting zombie processes: {e}")
            return []

    @safe_execute
    async def get_process_tree(self, root_pid: Optional[int] = None) -> Dict[str, Any]:
        """Get process tree structure"""
        try:
            if root_pid is None:
                # Get all processes and build tree
                all_processes = {}
                root_processes = []

                for proc in psutil.process_iter(['pid', 'ppid', 'name']):
                    try:
                        pinfo = proc.info
                        all_processes[pinfo['pid']] = {
                            'pid': pinfo['pid'],
                            'ppid': pinfo['ppid'],
                            'name': pinfo['name'],
                            'children': []
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                # Build tree structure
                for pid, proc_info in all_processes.items():
                    ppid = proc_info['ppid']
                    if ppid in all_processes:
                        all_processes[ppid]['children'].append(proc_info)
                    else:
                        root_processes.append(proc_info)

                return {
                    'root_processes': root_processes,
                    'total_processes': len(all_processes)
                }
            else:
                # Get tree for specific process
                try:
                    root_proc = psutil.Process(root_pid)

                    def build_tree(proc):
                        children = []
                        try:
                            for child in proc.children():
                                children.append(build_tree(child))
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                        return {
                            'pid': proc.pid,
                            'name': proc.name(),
                            'children': children
                        }

                    return build_tree(root_proc)

                except psutil.NoSuchProcess:
                    return {'error': f'Process with PID {root_pid} not found'}

        except Exception as e:
            self.logger.error(f"Error getting process tree: {e}")
            return {}

    def _add_to_history(self, summary_data: Dict[str, Any]):
        """Add process summary to history"""
        try:
            history_entry = {
                'timestamp': summary_data['timestamp'],
                'total_processes': summary_data.get('total_processes', 0),
                'running_processes': summary_data.get('running_processes', 0),
                'zombie_processes': summary_data.get('zombie_processes', 0),
                'top_cpu_count': len(summary_data.get('top_cpu', [])),
                'top_memory_count': len(summary_data.get('top_memory', []))
            }

            self._process_history.append(history_entry)

            # Keep only the last N data points
            if len(self._process_history) > self._max_history:
                self._process_history = self._process_history[-self._max_history:]

        except Exception as e:
            self.logger.error(f"Error adding to history: {e}")

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive process report"""
        try:
            summary = await self.get_process_summary()
            zombies = await self.get_zombie_processes()
            top_processes = await self.get_process_list(sort_by='cpu', limit=10)

            report_lines = [
                "⚙️  PROCESS MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add process summary
            report_lines.extend([
                "",
                "📊 PROCESS SUMMARY",
                "-" * 30,
                f"📈 Total Processes: {summary.get('total_processes', 0)}",
                f"🏃 Running: {summary.get('running_processes', 0)}",
                f"💤 Sleeping: {summary.get('sleeping_processes', 0)}",
                f"🛑 Stopped: {summary.get('stopped_processes', 0)}",
                f"🧟 Zombies: {summary.get('zombie_processes', 0)}",
            ])

            # Add process by user breakdown
            by_user = summary.get('by_user', {})
            if by_user:
                report_lines.extend([
                    "",
                    "👥 PROCESSES BY USER",
                    "-" * 30,
                ])
                sorted_users = sorted(by_user.items(), key=lambda x: x[1], reverse=True)
                for username, count in sorted_users[:10]:  # Top 10 users
                    report_lines.append(f"🔹 {username}: {count} processes")

            # Add top CPU processes
            if top_processes:
                report_lines.extend([
                    "",
                    "🖥️  TOP CPU PROCESSES",
                    "-" * 30,
                ])
                for proc in top_processes[:5]:
                    if proc['cpu_percent'] > 0:
                        report_lines.append(
                            f"🔹 {proc['name']} (PID: {proc['pid']}) - "
                            f"CPU: {proc['cpu_percent']:.1f}% | "
                            f"Memory: {proc['memory_percent']:.1f}% | "
                            f"User: {proc['username']}"
                        )

            # Add top memory processes
            memory_processes = sorted(top_processes, key=lambda x: x['memory_percent'], reverse=True)
            report_lines.extend([
                "",
                "💾 TOP MEMORY PROCESSES",
                "-" * 30,
            ])
            for proc in memory_processes[:5]:
                if proc['memory_percent'] > 0:
                    report_lines.append(
                        f"🔹 {proc['name']} (PID: {proc['pid']}) - "
                        f"Memory: {proc['memory_percent']:.1f}% ({proc['memory_rss_formatted']}) | "
                        f"CPU: {proc['cpu_percent']:.1f}% | "
                        f"User: {proc['username']}"
                    )

            # Add zombie processes if any
            if zombies:
                report_lines.extend([
                    "",
                    "🧟 ZOMBIE PROCESSES",
                    "-" * 30,
                ])
                for zombie in zombies:
                    age_hours = zombie['age'] / 3600
                    report_lines.append(
                        f"🔴 {zombie['name']} (PID: {zombie['pid']}, PPID: {zombie['ppid']}) - "
                        f"Age: {age_hours:.1f} hours"
                    )

            # Add resource intensive processes warning
            resource_intensive = summary.get('resource_intensive', [])
            if resource_intensive:
                report_lines.extend([
                    "",
                    "⚠️  HIGH RESOURCE USAGE",
                    "-" * 30,
                ])
                for proc in resource_intensive[:5]:
                    report_lines.append(
                        f"🟡 {proc['name']} (PID: {proc['pid']}) - "
                        f"CPU: {proc['cpu_percent']:.1f}% | "
                        f"Memory: {proc['memory_percent']:.1f}%"
                    )

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating process report: {e}")
            return f"❌ Error generating process report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Process Monitor...")
            self._cached_data.clear()
            self._process_history.clear()
            self.logger.info("✅ Process Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Process Monitor cleanup: {e}")