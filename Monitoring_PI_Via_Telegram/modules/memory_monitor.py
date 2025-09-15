"""
Memory Monitor Module - Memory and swap monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive memory and swap monitoring capabilities including RAM usage analysis, swap monitoring, and memory performance metrics.
License: For educational and personal use
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import psutil

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, format_bytes, calculate_percentage
)

logger = logging.getLogger('monitoring.memory')


class MemoryMonitor:
    """Memory and swap monitoring class"""

    def __init__(self):
        """Initialize the memory monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 5  # seconds
        self._cached_data = {}
        self._memory_history = []
        self._max_history = 120  # Keep 2 hours of data points

    async def initialize(self) -> bool:
        """Initialize the memory monitor"""
        try:
            self.logger.info("🚀 Initializing Memory Monitor...")

            # Get initial memory information
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()

            self.logger.info(
                f"✅ Memory Monitor initialized - "
                f"RAM: {format_bytes(virtual_memory.total)}, "
                f"Swap: {format_bytes(swap_memory.total)}"
            )
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Memory Monitor: {e}")
            return False

    @safe_execute
    async def get_memory_info(self) -> Dict[str, Any]:
        """Get detailed memory information"""
        try:
            # Check cache
            if self._is_cached_data_valid('memory_info'):
                return self._cached_data['memory_info']

            virtual_mem = psutil.virtual_memory()
            swap_mem = psutil.swap_memory()

            memory_info = {
                'timestamp': datetime.now().isoformat(),
                'virtual_memory': {
                    'total': virtual_mem.total,
                    'available': virtual_mem.available,
                    'used': virtual_mem.used,
                    'free': virtual_mem.free,
                    'percent': virtual_mem.percent,
                    'total_formatted': format_bytes(virtual_mem.total),
                    'available_formatted': format_bytes(virtual_mem.available),
                    'used_formatted': format_bytes(virtual_mem.used),
                    'free_formatted': format_bytes(virtual_mem.free),
                },
                'swap_memory': {
                    'total': swap_mem.total,
                    'used': swap_mem.used,
                    'free': swap_mem.free,
                    'percent': swap_mem.percent,
                    'sin': getattr(swap_mem, 'sin', 0),  # bytes swapped in
                    'sout': getattr(swap_mem, 'sout', 0),  # bytes swapped out
                    'total_formatted': format_bytes(swap_mem.total),
                    'used_formatted': format_bytes(swap_mem.used),
                    'free_formatted': format_bytes(swap_mem.free),
                }
            }

            # Add platform-specific memory details
            if hasattr(virtual_mem, 'buffers'):
                memory_info['virtual_memory']['buffers'] = virtual_mem.buffers
                memory_info['virtual_memory']['buffers_formatted'] = format_bytes(virtual_mem.buffers)

            if hasattr(virtual_mem, 'cached'):
                memory_info['virtual_memory']['cached'] = virtual_mem.cached
                memory_info['virtual_memory']['cached_formatted'] = format_bytes(virtual_mem.cached)

            if hasattr(virtual_mem, 'shared'):
                memory_info['virtual_memory']['shared'] = virtual_mem.shared
                memory_info['virtual_memory']['shared_formatted'] = format_bytes(virtual_mem.shared)

            # Add status indicators
            memory_info['virtual_memory']['status'] = self._get_memory_status(virtual_mem.percent)
            memory_info['swap_memory']['status'] = self._get_swap_status(swap_mem.percent)

            # Get additional memory statistics
            try:
                memory_info['memory_maps'] = await self._get_memory_maps()
            except Exception as e:
                self.logger.debug(f"Could not get memory maps: {e}")
                memory_info['memory_maps'] = {}

            # Cache the data
            self._cached_data['memory_info'] = memory_info
            self._last_update = time.time()

            # Add to history
            self._add_to_history(memory_info)

            return memory_info

        except Exception as e:
            self.logger.error(f"Error getting memory info: {e}")
            return {}

    @safe_execute
    async def _get_memory_maps(self) -> Dict[str, Any]:
        """Get memory mapping information from /proc/meminfo"""
        try:
            memory_maps = {}

            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()

                        # Parse value and unit
                        if 'kB' in value:
                            size_kb = int(value.replace('kB', '').strip())
                            size_bytes = size_kb * 1024
                            memory_maps[key] = {
                                'bytes': size_bytes,
                                'formatted': format_bytes(size_bytes)
                            }
                        else:
                            memory_maps[key] = {'raw': value}

            return memory_maps

        except Exception as e:
            self.logger.error(f"Error getting memory maps: {e}")
            return {}

    @safe_execute
    async def get_memory_usage_by_process(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get processes sorted by memory usage"""
        try:
            processes = []

            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'memory_info']):
                try:
                    pinfo = proc.info
                    if pinfo['memory_percent'] is not None and pinfo['memory_percent'] > 0:
                        memory_info = pinfo.get('memory_info', {})
                        processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'username': pinfo['username'],
                            'memory_percent': round(pinfo['memory_percent'], 2),
                            'rss': getattr(memory_info, 'rss', 0) if memory_info else 0,
                            'vms': getattr(memory_info, 'vms', 0) if memory_info else 0,
                            'rss_formatted': format_bytes(getattr(memory_info, 'rss', 0)) if memory_info else '0 B',
                            'vms_formatted': format_bytes(getattr(memory_info, 'vms', 0)) if memory_info else '0 B',
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Sort by memory usage and return top processes
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            return processes[:limit]

        except Exception as e:
            self.logger.error(f"Error getting memory usage by process: {e}")
            return []

    @safe_execute
    async def get_swap_usage(self) -> Dict[str, Any]:
        """Get detailed swap usage information"""
        try:
            swap = psutil.swap_memory()

            swap_info = {
                'timestamp': datetime.now().isoformat(),
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent,
                'total_formatted': format_bytes(swap.total),
                'used_formatted': format_bytes(swap.used),
                'free_formatted': format_bytes(swap.free),
            }

            # Add swap I/O if available
            if hasattr(swap, 'sin'):
                swap_info['sin'] = swap.sin
                swap_info['sout'] = swap.sout
                swap_info['sin_formatted'] = format_bytes(swap.sin)
                swap_info['sout_formatted'] = format_bytes(swap.sout)

            # Get swap devices/files
            try:
                swap_info['devices'] = await self._get_swap_devices()
            except Exception as e:
                self.logger.debug(f"Could not get swap devices: {e}")
                swap_info['devices'] = []

            # Add status
            swap_info['status'] = self._get_swap_status(swap.percent)

            return swap_info

        except Exception as e:
            self.logger.error(f"Error getting swap usage: {e}")
            return {}

    @safe_execute
    async def _get_swap_devices(self) -> List[Dict[str, Any]]:
        """Get swap devices from /proc/swaps"""
        try:
            devices = []

            try:
                with open('/proc/swaps', 'r') as f:
                    lines = f.readlines()

                # Skip header line
                for line in lines[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        devices.append({
                            'filename': parts[0],
                            'type': parts[1],
                            'size': int(parts[2]) * 1024,  # Convert from KB to bytes
                            'used': int(parts[3]) * 1024,  # Convert from KB to bytes
                            'priority': int(parts[4]),
                            'size_formatted': format_bytes(int(parts[2]) * 1024),
                            'used_formatted': format_bytes(int(parts[3]) * 1024),
                        })

            except FileNotFoundError:
                # No swap configured
                pass

            return devices

        except Exception as e:
            self.logger.error(f"Error getting swap devices: {e}")
            return []

    @safe_execute
    async def get_memory_pressure(self) -> Dict[str, Any]:
        """Get memory pressure information"""
        try:
            virtual_mem = psutil.virtual_memory()
            swap_mem = psutil.swap_memory()

            # Calculate various pressure metrics
            pressure_info = {
                'timestamp': datetime.now().isoformat(),
                'memory_pressure': virtual_mem.percent,
                'swap_pressure': swap_mem.percent,
                'available_ratio': (virtual_mem.available / virtual_mem.total) * 100,
            }

            # Calculate combined pressure
            if swap_mem.total > 0:
                # Include swap in calculation
                total_memory = virtual_mem.total + swap_mem.total
                used_memory = virtual_mem.used + swap_mem.used
                pressure_info['combined_pressure'] = (used_memory / total_memory) * 100
            else:
                pressure_info['combined_pressure'] = virtual_mem.percent

            # Determine pressure level
            pressure_level = self._get_pressure_level(pressure_info['combined_pressure'])
            pressure_info['pressure_level'] = pressure_level

            # Add recommendations
            pressure_info['recommendations'] = self._get_memory_recommendations(pressure_info)

            return pressure_info

        except Exception as e:
            self.logger.error(f"Error getting memory pressure: {e}")
            return {}

    def _get_memory_status(self, usage_percent: float) -> Dict[str, Any]:
        """Get memory status based on usage percentage"""
        try:
            thresholds = getattr(THRESHOLDS, 'memory_usage', {
                'normal': 70, 'warning': 85, 'critical': 95
            })

            if usage_percent < thresholds.get('normal', 70):
                return {
                    'level': 'normal',
                    'emoji': '🟢',
                    'text': 'Normal',
                    'color': 'green'
                }
            elif usage_percent < thresholds.get('warning', 85):
                return {
                    'level': 'warning',
                    'emoji': '🟡',
                    'text': 'High',
                    'color': 'yellow'
                }
            elif usage_percent < thresholds.get('critical', 95):
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
            self.logger.error(f"Error getting memory status: {e}")
            return {'level': 'unknown', 'emoji': '⚪', 'text': 'Unknown', 'color': 'gray'}

    def _get_swap_status(self, usage_percent: float) -> Dict[str, Any]:
        """Get swap status based on usage percentage"""
        try:
            if usage_percent < 25:
                return {
                    'level': 'normal',
                    'emoji': '🟢',
                    'text': 'Normal',
                    'color': 'green'
                }
            elif usage_percent < 50:
                return {
                    'level': 'warning',
                    'emoji': '🟡',
                    'text': 'Moderate',
                    'color': 'yellow'
                }
            elif usage_percent < 75:
                return {
                    'level': 'critical',
                    'emoji': '🟠',
                    'text': 'High',
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
            self.logger.error(f"Error getting swap status: {e}")
            return {'level': 'unknown', 'emoji': '⚪', 'text': 'Unknown', 'color': 'gray'}

    def _get_pressure_level(self, pressure: float) -> Dict[str, Any]:
        """Get memory pressure level"""
        try:
            if pressure < 60:
                return {
                    'level': 'low',
                    'emoji': '🟢',
                    'text': 'Low Pressure',
                    'color': 'green'
                }
            elif pressure < 80:
                return {
                    'level': 'medium',
                    'emoji': '🟡',
                    'text': 'Medium Pressure',
                    'color': 'yellow'
                }
            elif pressure < 90:
                return {
                    'level': 'high',
                    'emoji': '🟠',
                    'text': 'High Pressure',
                    'color': 'orange'
                }
            else:
                return {
                    'level': 'critical',
                    'emoji': '🔴',
                    'text': 'Critical Pressure',
                    'color': 'red'
                }

        except Exception as e:
            self.logger.error(f"Error getting pressure level: {e}")
            return {'level': 'unknown', 'emoji': '⚪', 'text': 'Unknown', 'color': 'gray'}

    def _get_memory_recommendations(self, pressure_info: Dict[str, Any]) -> List[str]:
        """Get memory optimization recommendations"""
        try:
            recommendations = []

            pressure = pressure_info.get('combined_pressure', 0)
            swap_pressure = pressure_info.get('swap_pressure', 0)

            if pressure > 90:
                recommendations.append("🚨 Critical memory usage - consider stopping non-essential services")
                recommendations.append("🔄 Restart memory-intensive applications")
                recommendations.append("📊 Check for memory leaks in running processes")
            elif pressure > 80:
                recommendations.append("⚠️ High memory usage - monitor closely")
                recommendations.append("🧹 Clear system caches if possible")
            elif pressure > 70:
                recommendations.append("📊 Memory usage is elevated - consider optimization")

            if swap_pressure > 50:
                recommendations.append("💿 High swap usage detected - consider adding more RAM")
                recommendations.append("⚡ Optimize applications to reduce memory footprint")

            if pressure < 50 and swap_pressure < 10:
                recommendations.append("✅ Memory usage is healthy")

            return recommendations

        except Exception as e:
            self.logger.error(f"Error getting memory recommendations: {e}")
            return []

    def _add_to_history(self, memory_info: Dict[str, Any]):
        """Add data point to history"""
        try:
            virtual_mem = memory_info.get('virtual_memory', {})
            swap_mem = memory_info.get('swap_memory', {})

            self._memory_history.append({
                'timestamp': memory_info['timestamp'],
                'memory_usage': virtual_mem.get('percent', 0),
                'swap_usage': swap_mem.get('percent', 0),
                'available': virtual_mem.get('available', 0)
            })

            # Keep only the last N data points
            if len(self._memory_history) > self._max_history:
                self._memory_history = self._memory_history[-self._max_history:]

        except Exception as e:
            self.logger.error(f"Error adding to history: {e}")

    @safe_execute
    async def get_memory_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get memory usage history"""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            filtered_history = []

            for entry in self._memory_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time:
                        filtered_history.append(entry)
                except:
                    continue

            return filtered_history

        except Exception as e:
            self.logger.error(f"Error getting memory history: {e}")
            return []

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive memory report"""
        try:
            memory_info = await self.get_memory_info()
            swap_info = await self.get_swap_usage()
            pressure_info = await self.get_memory_pressure()
            top_processes = await self.get_memory_usage_by_process(5)

            virtual_mem = memory_info.get('virtual_memory', {})
            swap_mem = memory_info.get('swap_memory', {})

            report_lines = [
                "💾 MEMORY MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "🖥️  VIRTUAL MEMORY",
                "-" * 30,
                f"📊 Total: {virtual_mem.get('total_formatted', 'Unknown')}",
                f"✅ Available: {virtual_mem.get('available_formatted', 'Unknown')}",
                f"🔴 Used: {virtual_mem.get('used_formatted', 'Unknown')}",
                f"📈 Usage: {virtual_mem.get('percent', 0):.1f}%",
            ]

            # Add virtual memory status
            vm_status = virtual_mem.get('status', {})
            report_lines.append(f"{vm_status.get('emoji', '⚪')} Status: {vm_status.get('text', 'Unknown')}")

            # Add swap information if available
            if swap_mem.get('total', 0) > 0:
                swap_status = swap_mem.get('status', {})
                report_lines.extend([
                    "",
                    "💿 SWAP MEMORY",
                    "-" * 30,
                    f"📊 Total: {swap_mem.get('total_formatted', 'Unknown')}",
                    f"🔴 Used: {swap_mem.get('used_formatted', 'Unknown')}",
                    f"📈 Usage: {swap_mem.get('percent', 0):.1f}%",
                    f"{swap_status.get('emoji', '⚪')} Status: {swap_status.get('text', 'Unknown')}",
                ])

                # Add swap devices if available
                swap_devices = swap_info.get('devices', [])
                if swap_devices:
                    report_lines.append("💿 Swap Devices:")
                    for device in swap_devices:
                        report_lines.append(f"   📁 {device['filename']} - {device['size_formatted']}")

            else:
                report_lines.extend([
                    "",
                    "💿 SWAP MEMORY",
                    "-" * 30,
                    "⚪ No swap configured",
                ])

            # Add memory pressure information
            pressure_level = pressure_info.get('pressure_level', {})
            report_lines.extend([
                "",
                "🏥 MEMORY PRESSURE",
                "-" * 30,
                f"{pressure_level.get('emoji', '⚪')} Pressure Level: {pressure_level.get('text', 'Unknown')}",
                f"📊 Combined Usage: {pressure_info.get('combined_pressure', 0):.1f}%",
                f"💚 Available Ratio: {pressure_info.get('available_ratio', 0):.1f}%",
            ])

            # Add recommendations
            recommendations = pressure_info.get('recommendations', [])
            if recommendations:
                report_lines.extend([
                    "",
                    "💡 RECOMMENDATIONS",
                    "-" * 30,
                ] + recommendations)

            # Add top memory consuming processes
            if top_processes:
                report_lines.extend([
                    "",
                    "🏆 TOP MEMORY PROCESSES",
                    "-" * 30,
                ])
                for proc in top_processes:
                    report_lines.append(
                        f"🔹 {proc['name']} (PID: {proc['pid']}) - "
                        f"Memory: {proc['memory_percent']:.1f}% ({proc['rss_formatted']}) | "
                        f"User: {proc['username']}"
                    )

            # Add additional memory details
            memory_maps = memory_info.get('memory_maps', {})
            if memory_maps:
                interesting_keys = ['MemFree', 'Buffers', 'Cached', 'Slab', 'SReclaimable', 'SUnreclaim']
                available_keys = [k for k in interesting_keys if k in memory_maps]

                if available_keys:
                    report_lines.extend([
                        "",
                        "🔍 MEMORY DETAILS",
                        "-" * 30,
                    ])
                    for key in available_keys:
                        if 'formatted' in memory_maps[key]:
                            report_lines.append(f"📊 {key}: {memory_maps[key]['formatted']}")

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating memory report: {e}")
            return f"❌ Error generating memory report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Memory Monitor...")
            self._cached_data.clear()
            self._memory_history.clear()
            self.logger.info("✅ Memory Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Memory Monitor cleanup: {e}")