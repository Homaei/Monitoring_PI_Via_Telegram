"""
Disk Monitor Module - Disk usage and I/O monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive disk monitoring and analysis capabilities including disk space usage, I/O statistics, and storage performance metrics.
License: For educational and personal use
"""

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import psutil
from pathlib import Path

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, format_bytes, calculate_percentage
)

logger = logging.getLogger('monitoring.disk')


class DiskMonitor:
    """Disk usage and I/O monitoring class"""

    def __init__(self):
        """Initialize the disk monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 10  # seconds
        self._cached_data = {}
        self._io_history = []
        self._max_history = 60  # Keep 60 data points
        self._previous_io_stats = None

    async def initialize(self) -> bool:
        """Initialize the disk monitor"""
        try:
            self.logger.info("🚀 Initializing Disk Monitor...")

            # Get initial disk information
            disk_partitions = psutil.disk_partitions()
            self.logger.info(f"✅ Disk Monitor initialized - {len(disk_partitions)} partitions detected")

            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Disk Monitor: {e}")
            return False

    @safe_execute
    async def get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage information for all mounted filesystems"""
        try:
            # Check cache
            if self._is_cached_data_valid('disk_usage'):
                return self._cached_data['disk_usage']

            disk_usage = {
                'timestamp': datetime.now().isoformat(),
                'partitions': [],
                'total_usage': 0,
                'critical_partitions': [],
                'warnings': []
            }

            total_size = 0
            total_used = 0

            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    usage_percent = (partition_usage.used / partition_usage.total) * 100

                    partition_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'opts': partition.opts,
                        'total': partition_usage.total,
                        'used': partition_usage.used,
                        'free': partition_usage.free,
                        'percent': round(usage_percent, 2),
                        'total_formatted': format_bytes(partition_usage.total),
                        'used_formatted': format_bytes(partition_usage.used),
                        'free_formatted': format_bytes(partition_usage.free),
                        'status': self._get_disk_status(usage_percent)
                    }

                    # Add filesystem information
                    partition_info['filesystem_info'] = await self._get_filesystem_info(partition.mountpoint)

                    disk_usage['partitions'].append(partition_info)

                    # Track totals (only for real filesystems)
                    if not self._is_virtual_filesystem(partition.fstype):
                        total_size += partition_usage.total
                        total_used += partition_usage.used

                        # Check for critical usage
                        if usage_percent > 95:
                            disk_usage['critical_partitions'].append(partition.mountpoint)
                        elif usage_percent > 85:
                            disk_usage['warnings'].append(
                                f"High disk usage on {partition.mountpoint}: {usage_percent:.1f}%"
                            )

                except (PermissionError, FileNotFoundError, OSError) as e:
                    self.logger.debug(f"Could not access partition {partition.mountpoint}: {e}")
                    continue

            # Calculate overall usage
            if total_size > 0:
                disk_usage['total_usage'] = round((total_used / total_size) * 100, 2)

            # Cache the data
            self._cached_data['disk_usage'] = disk_usage
            self._last_update = time.time()

            return disk_usage

        except Exception as e:
            self.logger.error(f"Error getting disk usage: {e}")
            return {}

    @safe_execute
    async def _get_filesystem_info(self, mountpoint: str) -> Dict[str, Any]:
        """Get additional filesystem information"""
        try:
            filesystem_info = {}

            # Get filesystem statistics using statvfs
            try:
                statvfs = os.statvfs(mountpoint)
                filesystem_info['block_size'] = statvfs.f_bsize
                filesystem_info['fragment_size'] = statvfs.f_frsize
                filesystem_info['total_blocks'] = statvfs.f_blocks
                filesystem_info['free_blocks'] = statvfs.f_bfree
                filesystem_info['available_blocks'] = statvfs.f_bavail
                filesystem_info['total_inodes'] = statvfs.f_files
                filesystem_info['free_inodes'] = statvfs.f_ffree
                filesystem_info['available_inodes'] = statvfs.f_favail

                # Calculate inode usage
                if statvfs.f_files > 0:
                    used_inodes = statvfs.f_files - statvfs.f_ffree
                    filesystem_info['inode_usage_percent'] = round(
                        (used_inodes / statvfs.f_files) * 100, 2
                    )
                else:
                    filesystem_info['inode_usage_percent'] = 0

            except OSError as e:
                self.logger.debug(f"Could not get statvfs info for {mountpoint}: {e}")

            return filesystem_info

        except Exception as e:
            self.logger.error(f"Error getting filesystem info for {mountpoint}: {e}")
            return {}

    def _is_virtual_filesystem(self, fstype: str) -> bool:
        """Check if filesystem type is virtual"""
        virtual_fs_types = {
            'proc', 'sysfs', 'devpts', 'tmpfs', 'devtmpfs', 'cgroup', 'cgroup2',
            'pstore', 'bpf', 'debugfs', 'tracefs', 'securityfs', 'hugetlbfs',
            'mqueue', 'fuse.gvfsd-fuse', 'fusectl', 'configfs'
        }
        return fstype in virtual_fs_types

    @safe_execute
    async def get_disk_io(self) -> Dict[str, Any]:
        """Get disk I/O statistics"""
        try:
            disk_io = {
                'timestamp': datetime.now().isoformat(),
                'per_disk': {},
                'totals': {},
                'rates': {}
            }

            # Get current I/O statistics
            current_io = psutil.disk_io_counters(perdisk=True)
            total_io = psutil.disk_io_counters()

            if current_io:
                for device, iostat in current_io.items():
                    # Filter out loop devices and other virtual devices
                    if not self._is_real_disk_device(device):
                        continue

                    disk_io['per_disk'][device] = {
                        'read_count': iostat.read_count,
                        'write_count': iostat.write_count,
                        'read_bytes': iostat.read_bytes,
                        'write_bytes': iostat.write_bytes,
                        'read_time': iostat.read_time,
                        'write_time': iostat.write_time,
                        'read_bytes_formatted': format_bytes(iostat.read_bytes),
                        'write_bytes_formatted': format_bytes(iostat.write_bytes),
                    }

                    # Add busy time if available
                    if hasattr(iostat, 'busy_time'):
                        disk_io['per_disk'][device]['busy_time'] = iostat.busy_time

            if total_io:
                disk_io['totals'] = {
                    'read_count': total_io.read_count,
                    'write_count': total_io.write_count,
                    'read_bytes': total_io.read_bytes,
                    'write_bytes': total_io.write_bytes,
                    'read_time': total_io.read_time,
                    'write_time': total_io.write_time,
                    'read_bytes_formatted': format_bytes(total_io.read_bytes),
                    'write_bytes_formatted': format_bytes(total_io.write_bytes),
                }

            # Calculate I/O rates if we have previous data
            if self._previous_io_stats:
                disk_io['rates'] = await self._calculate_io_rates(
                    self._previous_io_stats, current_io, total_io
                )

            # Store current stats for next calculation
            self._previous_io_stats = {
                'timestamp': time.time(),
                'per_disk': current_io,
                'total': total_io
            }

            # Add to history
            self._add_io_to_history(disk_io)

            return disk_io

        except Exception as e:
            self.logger.error(f"Error getting disk I/O: {e}")
            return {}

    def _is_real_disk_device(self, device: str) -> bool:
        """Check if device is a real disk (not loop, ram, etc.)"""
        virtual_prefixes = ['loop', 'ram', 'dm-', 'sr']
        return not any(device.startswith(prefix) for prefix in virtual_prefixes)

    @safe_execute
    async def _calculate_io_rates(self, previous_stats: Dict[str, Any],
                                current_per_disk: Dict, current_total) -> Dict[str, Any]:
        """Calculate I/O rates based on previous and current statistics"""
        try:
            rates = {
                'per_disk': {},
                'totals': {}
            }

            time_diff = time.time() - previous_stats['timestamp']
            if time_diff <= 0:
                return rates

            # Calculate per-disk rates
            prev_per_disk = previous_stats.get('per_disk', {})
            for device, current_stats in current_per_disk.items():
                if device in prev_per_disk:
                    prev_stats = prev_per_disk[device]
                    rates['per_disk'][device] = {
                        'read_rate': (current_stats.read_bytes - prev_stats.read_bytes) / time_diff,
                        'write_rate': (current_stats.write_bytes - prev_stats.write_bytes) / time_diff,
                        'read_ops_rate': (current_stats.read_count - prev_stats.read_count) / time_diff,
                        'write_ops_rate': (current_stats.write_count - prev_stats.write_count) / time_diff,
                    }

                    # Format rates
                    rates['per_disk'][device]['read_rate_formatted'] = format_bytes(
                        rates['per_disk'][device]['read_rate']
                    ) + '/s'
                    rates['per_disk'][device]['write_rate_formatted'] = format_bytes(
                        rates['per_disk'][device]['write_rate']
                    ) + '/s'

            # Calculate total rates
            prev_total = previous_stats.get('total')
            if prev_total and current_total:
                rates['totals'] = {
                    'read_rate': (current_total.read_bytes - prev_total.read_bytes) / time_diff,
                    'write_rate': (current_total.write_bytes - prev_total.write_bytes) / time_diff,
                    'read_ops_rate': (current_total.read_count - prev_total.read_count) / time_diff,
                    'write_ops_rate': (current_total.write_count - prev_total.write_count) / time_diff,
                }

                # Format total rates
                rates['totals']['read_rate_formatted'] = format_bytes(
                    rates['totals']['read_rate']
                ) + '/s'
                rates['totals']['write_rate_formatted'] = format_bytes(
                    rates['totals']['write_rate']
                ) + '/s'

            return rates

        except Exception as e:
            self.logger.error(f"Error calculating I/O rates: {e}")
            return {}

    @safe_execute
    async def get_mount_points(self) -> List[Dict[str, Any]]:
        """Get information about all mount points"""
        try:
            mount_points = []

            partitions = psutil.disk_partitions(all=True)
            for partition in partitions:
                mount_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'is_virtual': self._is_virtual_filesystem(partition.fstype)
                }

                # Get usage if accessible
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    mount_info['usage'] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': round((usage.used / usage.total) * 100, 2),
                        'total_formatted': format_bytes(usage.total),
                        'used_formatted': format_bytes(usage.used),
                        'free_formatted': format_bytes(usage.free),
                    }
                except (PermissionError, FileNotFoundError, OSError):
                    mount_info['usage'] = None

                mount_points.append(mount_info)

            return mount_points

        except Exception as e:
            self.logger.error(f"Error getting mount points: {e}")
            return []

    @safe_execute
    async def get_disk_health(self) -> Dict[str, Any]:
        """Get disk health information using SMART data if available"""
        try:
            health_info = {
                'timestamp': datetime.now().isoformat(),
                'disks': {},
                'overall_status': 'unknown'
            }

            # Try to get SMART data for each disk
            try:
                # Get list of disk devices
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "lsblk -d -n -o NAME,TYPE"
                )

                if returncode == 0:
                    disk_devices = []
                    for line in stdout.split('\n'):
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[1] == 'disk':
                            disk_devices.append(f"/dev/{parts[0]}")

                    # Get SMART data for each device
                    for device in disk_devices:
                        smart_data = await self._get_smart_data(device)
                        if smart_data:
                            health_info['disks'][device] = smart_data

            except Exception as e:
                self.logger.debug(f"Could not get disk health data: {e}")

            # Determine overall status
            if health_info['disks']:
                all_healthy = all(
                    disk_data.get('overall_health') == 'PASSED'
                    for disk_data in health_info['disks'].values()
                )
                health_info['overall_status'] = 'healthy' if all_healthy else 'warning'
            else:
                health_info['overall_status'] = 'unavailable'

            return health_info

        except Exception as e:
            self.logger.error(f"Error getting disk health: {e}")
            return {}

    @safe_execute
    async def _get_smart_data(self, device: str) -> Optional[Dict[str, Any]]:
        """Get SMART data for a specific device"""
        try:
            # Check if smartctl is available
            stdout, stderr, returncode = await asyncio.to_thread(
                run_command, f"smartctl -H {device}"
            )

            if returncode != 0:
                return None

            smart_data = {'device': device}

            # Parse health status
            if 'SMART overall-health self-assessment test result:' in stdout:
                for line in stdout.split('\n'):
                    if 'test result:' in line:
                        health_status = line.split(':')[1].strip()
                        smart_data['overall_health'] = health_status
                        break

            # Get additional SMART attributes
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, f"smartctl -A {device}"
                )

                if returncode == 0:
                    smart_data['attributes'] = await self._parse_smart_attributes(stdout)

            except Exception as e:
                self.logger.debug(f"Could not get SMART attributes for {device}: {e}")

            return smart_data

        except Exception as e:
            self.logger.debug(f"Could not get SMART data for {device}: {e}")
            return None

    @safe_execute
    async def _parse_smart_attributes(self, smart_output: str) -> Dict[str, Any]:
        """Parse SMART attributes from smartctl output"""
        try:
            attributes = {}
            in_attributes_section = False

            for line in smart_output.split('\n'):
                line = line.strip()

                if 'ID# ATTRIBUTE_NAME' in line:
                    in_attributes_section = True
                    continue

                if in_attributes_section and line:
                    parts = line.split()
                    if len(parts) >= 10 and parts[0].isdigit():
                        attr_id = parts[0]
                        attr_name = parts[1]
                        attr_value = parts[3]
                        attr_raw = ' '.join(parts[9:])

                        attributes[attr_name] = {
                            'id': attr_id,
                            'value': attr_value,
                            'raw_value': attr_raw
                        }

            return attributes

        except Exception as e:
            self.logger.error(f"Error parsing SMART attributes: {e}")
            return {}

    def _get_disk_status(self, usage_percent: float) -> Dict[str, Any]:
        """Get disk status based on usage percentage"""
        try:
            thresholds = getattr(THRESHOLDS, 'disk_usage', {
                'normal': 80, 'warning': 90, 'critical': 95
            })

            if usage_percent < thresholds.get('normal', 80):
                return {
                    'level': 'normal',
                    'emoji': '🟢',
                    'text': 'Normal',
                    'color': 'green'
                }
            elif usage_percent < thresholds.get('warning', 90):
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
            self.logger.error(f"Error getting disk status: {e}")
            return {'level': 'unknown', 'emoji': '⚪', 'text': 'Unknown', 'color': 'gray'}

    def _add_io_to_history(self, io_data: Dict[str, Any]):
        """Add I/O data point to history"""
        try:
            totals = io_data.get('totals', {})
            rates = io_data.get('rates', {}).get('totals', {})

            history_entry = {
                'timestamp': io_data['timestamp'],
                'read_bytes': totals.get('read_bytes', 0),
                'write_bytes': totals.get('write_bytes', 0),
                'read_rate': rates.get('read_rate', 0),
                'write_rate': rates.get('write_rate', 0),
            }

            self._io_history.append(history_entry)

            # Keep only the last N data points
            if len(self._io_history) > self._max_history:
                self._io_history = self._io_history[-self._max_history:]

        except Exception as e:
            self.logger.error(f"Error adding I/O to history: {e}")

    @safe_execute
    async def get_io_history(self, minutes: int = 30) -> List[Dict[str, Any]]:
        """Get disk I/O history"""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            filtered_history = []

            for entry in self._io_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time:
                        filtered_history.append(entry)
                except:
                    continue

            return filtered_history

        except Exception as e:
            self.logger.error(f"Error getting I/O history: {e}")
            return []

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive disk report"""
        try:
            disk_usage = await self.get_disk_usage()
            disk_io = await self.get_disk_io()
            disk_health = await self.get_disk_health()

            report_lines = [
                "💿 DISK MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add overall disk usage
            total_usage = disk_usage.get('total_usage', 0)
            if total_usage > 0:
                report_lines.extend([
                    "",
                    "📊 OVERALL DISK USAGE",
                    "-" * 30,
                    f"📈 Total Usage: {total_usage:.1f}%",
                ])

            # Add partition information
            partitions = disk_usage.get('partitions', [])
            if partitions:
                report_lines.extend([
                    "",
                    "💾 DISK PARTITIONS",
                    "-" * 30,
                ])

                for partition in partitions:
                    if not self._is_virtual_filesystem(partition.get('fstype', '')):
                        status = partition.get('status', {})
                        report_lines.append(
                            f"{status.get('emoji', '⚪')} {partition['mountpoint']} - "
                            f"{partition['percent']:.1f}% used "
                            f"({partition['used_formatted']}/{partition['total_formatted']})"
                        )

            # Add warnings and critical partitions
            warnings = disk_usage.get('warnings', [])
            critical_partitions = disk_usage.get('critical_partitions', [])

            if critical_partitions:
                report_lines.extend([
                    "",
                    "🚨 CRITICAL DISK USAGE",
                    "-" * 30,
                ] + [f"🔴 {partition}" for partition in critical_partitions])

            if warnings:
                report_lines.extend([
                    "",
                    "⚠️  DISK WARNINGS",
                    "-" * 30,
                ] + [f"🟡 {warning}" for warning in warnings])

            # Add I/O information
            rates = disk_io.get('rates', {}).get('totals', {})
            if rates:
                report_lines.extend([
                    "",
                    "📈 DISK I/O ACTIVITY",
                    "-" * 30,
                    f"📖 Read Rate: {rates.get('read_rate_formatted', 'N/A')}",
                    f"✏️  Write Rate: {rates.get('write_rate_formatted', 'N/A')}",
                    f"📊 Read Ops/s: {rates.get('read_ops_rate', 0):.1f}",
                    f"📊 Write Ops/s: {rates.get('write_ops_rate', 0):.1f}",
                ])

            # Add per-disk I/O if available
            per_disk_rates = disk_io.get('rates', {}).get('per_disk', {})
            if per_disk_rates:
                report_lines.extend([
                    "",
                    "💿 PER-DISK I/O RATES",
                    "-" * 30,
                ])
                for device, device_rates in per_disk_rates.items():
                    report_lines.append(
                        f"🔹 {device}: R: {device_rates.get('read_rate_formatted', 'N/A')} | "
                        f"W: {device_rates.get('write_rate_formatted', 'N/A')}"
                    )

            # Add disk health information
            health_disks = disk_health.get('disks', {})
            if health_disks:
                report_lines.extend([
                    "",
                    "🏥 DISK HEALTH STATUS",
                    "-" * 30,
                ])
                for device, health_data in health_disks.items():
                    overall_health = health_data.get('overall_health', 'UNKNOWN')
                    health_emoji = '🟢' if overall_health == 'PASSED' else '🔴'
                    report_lines.append(f"{health_emoji} {device}: {overall_health}")

            elif disk_health.get('overall_status') == 'unavailable':
                report_lines.extend([
                    "",
                    "🏥 DISK HEALTH STATUS",
                    "-" * 30,
                    "⚪ SMART data unavailable (smartctl not installed or no SMART support)",
                ])

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating disk report: {e}")
            return f"❌ Error generating disk report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Disk Monitor...")
            self._cached_data.clear()
            self._io_history.clear()
            self._previous_io_stats = None
            self.logger.info("✅ Disk Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Disk Monitor cleanup: {e}")