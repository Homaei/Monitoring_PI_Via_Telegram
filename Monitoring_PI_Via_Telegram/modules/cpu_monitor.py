"""
CPU Monitor Module - CPU monitoring with usage, frequency, and load tracking

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides detailed CPU monitoring and analysis capabilities including usage percentages, frequency monitoring, load tracking, and performance metrics.
License: For educational and personal use
"""

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import psutil

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, format_percentage,
    get_load_average, calculate_percentage
)

logger = logging.getLogger('monitoring.cpu')


class CpuMonitor:
    """CPU monitoring and analysis class"""

    def __init__(self):
        """Initialize the CPU monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 10  # seconds
        self._cached_data = {}
        self._cpu_count = None
        self._cpu_history = []
        self._max_history = 60  # Keep 60 data points

    async def initialize(self) -> bool:
        """Initialize the CPU monitor"""
        try:
            self.logger.info("🚀 Initializing CPU Monitor...")

            # Get CPU information
            self._cpu_count = psutil.cpu_count()
            self.logger.info(f"✅ CPU Monitor initialized - {self._cpu_count} cores detected")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize CPU Monitor: {e}")
            return False

    @safe_execute
    async def get_cpu_info(self) -> Dict[str, Any]:
        """Get detailed CPU information"""
        try:
            # Check cache
            if self._is_cached_data_valid('cpu_info'):
                return self._cached_data['cpu_info']

            # Get CPU frequency information
            cpu_freq = psutil.cpu_freq()
            cpu_info = {
                'timestamp': datetime.now().isoformat(),
                'physical_cores': psutil.cpu_count(logical=False),
                'logical_cores': psutil.cpu_count(logical=True),
                'max_frequency': cpu_freq.max if cpu_freq else None,
                'min_frequency': cpu_freq.min if cpu_freq else None,
                'current_frequency': cpu_freq.current if cpu_freq else None,
            }

            # Get CPU architecture info
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "lscpu"
                )
                if returncode == 0:
                    cpu_info['architecture_info'] = await self._parse_lscpu_output(stdout)
            except Exception as e:
                self.logger.warning(f"Could not get CPU architecture info: {e}")
                cpu_info['architecture_info'] = {}

            # Get CPU flags/features
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    cpu_info['cpu_info'] = await self._parse_cpuinfo(cpuinfo)
            except Exception as e:
                self.logger.warning(f"Could not read /proc/cpuinfo: {e}")
                cpu_info['cpu_info'] = {}

            # Cache the data
            self._cached_data['cpu_info'] = cpu_info
            self._last_update = time.time()

            return cpu_info

        except Exception as e:
            self.logger.error(f"Error getting CPU info: {e}")
            return {}

    @safe_execute
    async def _parse_lscpu_output(self, lscpu_output: str) -> Dict[str, Any]:
        """Parse lscpu command output"""
        try:
            info = {}
            for line in lscpu_output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_').replace('(', '').replace(')', '')
                    value = value.strip()
                    info[key] = value
            return info
        except Exception as e:
            self.logger.error(f"Error parsing lscpu output: {e}")
            return {}

    @safe_execute
    async def _parse_cpuinfo(self, cpuinfo: str) -> Dict[str, Any]:
        """Parse /proc/cpuinfo content"""
        try:
            info = {}
            current_processor = {}

            for line in cpuinfo.split('\n'):
                line = line.strip()
                if not line:
                    if current_processor and 'processor' in current_processor:
                        proc_id = current_processor['processor']
                        info[f'processor_{proc_id}'] = current_processor
                        current_processor = {}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    current_processor[key] = value

            # Add the last processor if exists
            if current_processor and 'processor' in current_processor:
                proc_id = current_processor['processor']
                info[f'processor_{proc_id}'] = current_processor

            # Extract common information
            if 'processor_0' in info:
                first_proc = info['processor_0']
                info['model_name'] = first_proc.get('model_name', 'Unknown')
                info['vendor_id'] = first_proc.get('vendor_id', 'Unknown')
                info['cpu_family'] = first_proc.get('cpu_family', 'Unknown')
                info['model'] = first_proc.get('model', 'Unknown')
                info['stepping'] = first_proc.get('stepping', 'Unknown')
                info['flags'] = first_proc.get('flags', '').split() if first_proc.get('flags') else []

            return info

        except Exception as e:
            self.logger.error(f"Error parsing cpuinfo: {e}")
            return {}

    @safe_execute
    async def get_cpu_usage(self, interval: float = 1.0, per_cpu: bool = False) -> Dict[str, Any]:
        """Get CPU usage information"""
        try:
            timestamp = datetime.now()

            # Get overall CPU usage
            if per_cpu:
                cpu_percentages = await asyncio.to_thread(
                    psutil.cpu_percent, interval=interval, percpu=True
                )
                overall_usage = sum(cpu_percentages) / len(cpu_percentages)
            else:
                overall_usage = await asyncio.to_thread(
                    psutil.cpu_percent, interval=interval
                )
                cpu_percentages = []

            # Get CPU times
            cpu_times = psutil.cpu_times()
            cpu_stats = psutil.cpu_stats()

            usage_data = {
                'timestamp': timestamp.isoformat(),
                'overall_usage': round(overall_usage, 2),
                'per_cpu_usage': [round(cpu, 2) for cpu in cpu_percentages] if per_cpu else [],
                'cpu_times': {
                    'user': cpu_times.user,
                    'system': cpu_times.system,
                    'idle': cpu_times.idle,
                    'nice': getattr(cpu_times, 'nice', 0),
                    'iowait': getattr(cpu_times, 'iowait', 0),
                    'irq': getattr(cpu_times, 'irq', 0),
                    'softirq': getattr(cpu_times, 'softirq', 0),
                    'steal': getattr(cpu_times, 'steal', 0),
                },
                'cpu_stats': {
                    'ctx_switches': cpu_stats.ctx_switches,
                    'interrupts': cpu_stats.interrupts,
                    'soft_interrupts': cpu_stats.soft_interrupts,
                    'syscalls': getattr(cpu_stats, 'syscalls', 0),
                }
            }

            # Add usage status
            usage_data['status'] = self._get_cpu_usage_status(overall_usage)

            # Store in history
            self._add_to_history(usage_data)

            return usage_data

        except Exception as e:
            self.logger.error(f"Error getting CPU usage: {e}")
            return {}

    @safe_execute
    async def get_load_average(self) -> Dict[str, Any]:
        """Get system load average information"""
        try:
            load_avg = os.getloadavg()
            cpu_count = self._cpu_count or psutil.cpu_count()

            load_data = {
                'timestamp': datetime.now().isoformat(),
                'load_1min': round(load_avg[0], 2),
                'load_5min': round(load_avg[1], 2),
                'load_15min': round(load_avg[2], 2),
                'cpu_count': cpu_count,
                'load_1min_per_cpu': round(load_avg[0] / cpu_count, 2),
                'load_5min_per_cpu': round(load_avg[1] / cpu_count, 2),
                'load_15min_per_cpu': round(load_avg[2] / cpu_count, 2),
                'load_1min_percentage': round((load_avg[0] / cpu_count) * 100, 2),
                'load_5min_percentage': round((load_avg[1] / cpu_count) * 100, 2),
                'load_15min_percentage': round((load_avg[2] / cpu_count) * 100, 2),
            }

            # Add load status
            load_data['status'] = self._get_load_status(load_data['load_1min_percentage'])

            return load_data

        except Exception as e:
            self.logger.error(f"Error getting load average: {e}")
            return {}

    @safe_execute
    async def get_cpu_frequency(self) -> Dict[str, Any]:
        """Get CPU frequency information"""
        try:
            # Get current frequency
            cpu_freq = psutil.cpu_freq()
            per_cpu_freq = psutil.cpu_freq(percpu=True) if hasattr(psutil, 'cpu_freq') else []

            freq_data = {
                'timestamp': datetime.now().isoformat(),
                'current': cpu_freq.current if cpu_freq else None,
                'min': cpu_freq.min if cpu_freq else None,
                'max': cpu_freq.max if cpu_freq else None,
            }

            if per_cpu_freq:
                freq_data['per_cpu'] = [
                    {
                        'current': freq.current,
                        'min': freq.min,
                        'max': freq.max
                    } for freq in per_cpu_freq
                ]

            # Try to get governor information
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
                )
                if returncode == 0:
                    freq_data['governor'] = stdout.strip()
            except:
                freq_data['governor'] = 'unknown'

            # Try to get available frequencies
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies"
                )
                if returncode == 0:
                    available_freqs = [int(f) for f in stdout.strip().split()]
                    freq_data['available_frequencies'] = available_freqs
            except:
                freq_data['available_frequencies'] = []

            return freq_data

        except Exception as e:
            self.logger.error(f"Error getting CPU frequency: {e}")
            return {}

    @safe_execute
    async def get_cpu_temperature(self) -> Dict[str, Any]:
        """Get CPU temperature information"""
        try:
            temp_data = {
                'timestamp': datetime.now().isoformat(),
                'temperature': None,
                'status': 'unknown'
            }

            # Method 1: Try psutil sensors
            if hasattr(psutil, "sensors_temperatures"):
                try:
                    temps = psutil.sensors_temperatures()
                    for name, entries in temps.items():
                        if entries and ('cpu' in name.lower() or 'coretemp' in name.lower()):
                            temp_data['temperature'] = entries[0].current
                            break
                except Exception as e:
                    self.logger.debug(f"psutil sensors failed: {e}")

            # Method 2: Try Raspberry Pi specific method
            if temp_data['temperature'] is None:
                try:
                    with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                        temp_celsius = float(f.read().strip()) / 1000
                        temp_data['temperature'] = temp_celsius
                except Exception as e:
                    self.logger.debug(f"thermal_zone0 failed: {e}")

            # Method 3: Try vcgencmd for Raspberry Pi
            if temp_data['temperature'] is None:
                try:
                    stdout, stderr, returncode = await asyncio.to_thread(
                        run_command, "vcgencmd measure_temp"
                    )
                    if returncode == 0 and 'temp=' in stdout:
                        temp_str = stdout.split('temp=')[1].split("'C")[0]
                        temp_data['temperature'] = float(temp_str)
                except Exception as e:
                    self.logger.debug(f"vcgencmd failed: {e}")

            # Add temperature status
            if temp_data['temperature'] is not None:
                temp_data['status'] = self._get_temperature_status(temp_data['temperature'])

            return temp_data

        except Exception as e:
            self.logger.error(f"Error getting CPU temperature: {e}")
            return {'timestamp': datetime.now().isoformat(), 'temperature': None, 'status': 'error'}

    @safe_execute
    async def get_top_processes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top CPU consuming processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    if pinfo['cpu_percent'] is not None and pinfo['cpu_percent'] > 0:
                        processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'username': pinfo['username'],
                            'cpu_percent': round(pinfo['cpu_percent'], 2),
                            'memory_percent': round(pinfo['memory_percent'], 2)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Sort by CPU usage and return top processes
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            return processes[:limit]

        except Exception as e:
            self.logger.error(f"Error getting top processes: {e}")
            return []

    def _get_cpu_usage_status(self, usage: float) -> Dict[str, Any]:
        """Get CPU usage status based on thresholds"""
        try:
            thresholds = getattr(THRESHOLDS, 'cpu_usage', {
                'normal': 70, 'warning': 85, 'critical': 95
            })

            if usage < thresholds.get('normal', 70):
                return {
                    'level': 'normal',
                    'emoji': '🟢',
                    'text': 'Normal',
                    'color': 'green'
                }
            elif usage < thresholds.get('warning', 85):
                return {
                    'level': 'warning',
                    'emoji': '🟡',
                    'text': 'High',
                    'color': 'yellow'
                }
            elif usage < thresholds.get('critical', 95):
                return {
                    'level': 'critical',
                    'emoji': '🟠',
                    'text': 'Critical',
                    'color': 'orange'
                }
            else:
                return {
                    'level': 'danger',
                    'emoji': '🔴',
                    'text': 'Danger',
                    'color': 'red'
                }

        except Exception as e:
            self.logger.error(f"Error getting CPU usage status: {e}")
            return {'level': 'unknown', 'emoji': '⚪', 'text': 'Unknown', 'color': 'gray'}

    def _get_load_status(self, load_percentage: float) -> Dict[str, Any]:
        """Get load average status based on thresholds"""
        try:
            if load_percentage < 70:
                return {
                    'level': 'normal',
                    'emoji': '🟢',
                    'text': 'Normal',
                    'color': 'green'
                }
            elif load_percentage < 100:
                return {
                    'level': 'warning',
                    'emoji': '🟡',
                    'text': 'High',
                    'color': 'yellow'
                }
            elif load_percentage < 150:
                return {
                    'level': 'critical',
                    'emoji': '🟠',
                    'text': 'Overloaded',
                    'color': 'orange'
                }
            else:
                return {
                    'level': 'danger',
                    'emoji': '🔴',
                    'text': 'Severely Overloaded',
                    'color': 'red'
                }

        except Exception as e:
            self.logger.error(f"Error getting load status: {e}")
            return {'level': 'unknown', 'emoji': '⚪', 'text': 'Unknown', 'color': 'gray'}

    def _get_temperature_status(self, temperature: float) -> Dict[str, Any]:
        """Get temperature status based on thresholds"""
        try:
            thresholds = getattr(THRESHOLDS, 'cpu_temp', {
                'info': 40.0, 'warning': 60.0, 'critical': 75.0, 'danger': 85.0
            })

            if temperature < thresholds.get('info', 40):
                return {
                    'level': 'normal',
                    'emoji': '🟢',
                    'text': 'Cool',
                    'color': 'green'
                }
            elif temperature < thresholds.get('warning', 60):
                return {
                    'level': 'info',
                    'emoji': '🔵',
                    'text': 'Warm',
                    'color': 'blue'
                }
            elif temperature < thresholds.get('critical', 75):
                return {
                    'level': 'warning',
                    'emoji': '🟡',
                    'text': 'Hot',
                    'color': 'yellow'
                }
            elif temperature < thresholds.get('danger', 85):
                return {
                    'level': 'critical',
                    'emoji': '🟠',
                    'text': 'Very Hot',
                    'color': 'orange'
                }
            else:
                return {
                    'level': 'danger',
                    'emoji': '🔴',
                    'text': 'Critical',
                    'color': 'red'
                }

        except Exception as e:
            self.logger.error(f"Error getting temperature status: {e}")
            return {'level': 'unknown', 'emoji': '⚪', 'text': 'Unknown', 'color': 'gray'}

    def _add_to_history(self, data: Dict[str, Any]):
        """Add data point to history"""
        try:
            self._cpu_history.append({
                'timestamp': data['timestamp'],
                'usage': data['overall_usage']
            })

            # Keep only the last N data points
            if len(self._cpu_history) > self._max_history:
                self._cpu_history = self._cpu_history[-self._max_history:]

        except Exception as e:
            self.logger.error(f"Error adding to history: {e}")

    @safe_execute
    async def get_cpu_history(self, minutes: int = 30) -> List[Dict[str, Any]]:
        """Get CPU usage history"""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            filtered_history = []

            for entry in self._cpu_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time:
                        filtered_history.append(entry)
                except:
                    continue

            return filtered_history

        except Exception as e:
            self.logger.error(f"Error getting CPU history: {e}")
            return []

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive CPU report"""
        try:
            cpu_info = await self.get_cpu_info()
            cpu_usage = await self.get_cpu_usage(interval=1.0, per_cpu=True)
            load_avg = await self.get_load_average()
            cpu_freq = await self.get_cpu_frequency()
            cpu_temp = await self.get_cpu_temperature()
            top_processes = await self.get_top_processes(5)

            report_lines = [
                "🖥️  CPU MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "🔧 CPU INFORMATION",
                "-" * 30,
                f"💾 Physical Cores: {cpu_info.get('physical_cores', 'Unknown')}",
                f"🧠 Logical Cores: {cpu_info.get('logical_cores', 'Unknown')}",
                f"📊 Model: {cpu_info.get('cpu_info', {}).get('model_name', 'Unknown')}",
            ]

            # Add frequency information
            if cpu_freq.get('current'):
                report_lines.extend([
                    "",
                    "⚡ FREQUENCY INFORMATION",
                    "-" * 30,
                    f"🔄 Current: {cpu_freq['current']:.1f} MHz",
                    f"⬆️  Max: {cpu_freq.get('max', 'Unknown')} MHz",
                    f"⬇️  Min: {cpu_freq.get('min', 'Unknown')} MHz",
                    f"🎛️  Governor: {cpu_freq.get('governor', 'Unknown')}",
                ])

            # Add usage information
            usage_status = cpu_usage.get('status', {})
            report_lines.extend([
                "",
                "📊 CPU USAGE",
                "-" * 30,
                f"{usage_status.get('emoji', '⚪')} Overall Usage: {cpu_usage.get('overall_usage', 0):.1f}%",
                f"📈 Status: {usage_status.get('text', 'Unknown')}",
            ])

            # Add per-CPU usage if available
            per_cpu = cpu_usage.get('per_cpu_usage', [])
            if per_cpu:
                report_lines.append("🔢 Per-CPU Usage:")
                for i, usage in enumerate(per_cpu):
                    report_lines.append(f"   CPU{i}: {usage:.1f}%")

            # Add load average
            load_status = load_avg.get('status', {})
            report_lines.extend([
                "",
                "⚖️  LOAD AVERAGE",
                "-" * 30,
                f"1min:  {load_avg.get('load_1min', 0):.2f} ({load_avg.get('load_1min_percentage', 0):.1f}%)",
                f"5min:  {load_avg.get('load_5min', 0):.2f} ({load_avg.get('load_5min_percentage', 0):.1f}%)",
                f"15min: {load_avg.get('load_15min', 0):.2f} ({load_avg.get('load_15min_percentage', 0):.1f}%)",
                f"{load_status.get('emoji', '⚪')} Status: {load_status.get('text', 'Unknown')}",
            ])

            # Add temperature
            if cpu_temp.get('temperature') is not None:
                temp_status = cpu_temp.get('status', {})
                report_lines.extend([
                    "",
                    "🌡️  TEMPERATURE",
                    "-" * 30,
                    f"{temp_status.get('emoji', '⚪')} CPU Temperature: {cpu_temp['temperature']:.1f}°C",
                    f"📊 Status: {temp_status.get('text', 'Unknown')}",
                ])

            # Add top processes
            if top_processes:
                report_lines.extend([
                    "",
                    "🏆 TOP CPU PROCESSES",
                    "-" * 30,
                ])
                for proc in top_processes:
                    report_lines.append(
                        f"🔹 {proc['name']} (PID: {proc['pid']}) - "
                        f"CPU: {proc['cpu_percent']:.1f}% | "
                        f"User: {proc['username']}"
                    )

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating CPU report: {e}")
            return f"❌ Error generating CPU report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up CPU Monitor...")
            self._cached_data.clear()
            self._cpu_history.clear()
            self.logger.info("✅ CPU Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during CPU Monitor cleanup: {e}")