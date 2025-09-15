"""
Temperature Monitor Module - Temperature sensor monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive temperature monitoring for Raspberry Pi systems including CPU temperature, thermal sensors, and temperature-based alerts.
License: For educational and personal use
"""

import asyncio
import logging
import time
import glob
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import psutil

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, calculate_percentage
)

logger = logging.getLogger('monitoring.temperature')


class TemperatureMonitor:
    """Temperature sensor monitoring class"""

    def __init__(self):
        """Initialize the temperature monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 5  # seconds
        self._cached_data = {}
        self._temperature_history = []
        self._max_history = 1440  # Keep 24 hours of data (1 per minute)
        self._sensor_paths = []

    async def initialize(self) -> bool:
        """Initialize the temperature monitor"""
        try:
            self.logger.info("🚀 Initializing Temperature Monitor...")

            # Discover temperature sensors
            self._sensor_paths = await self._discover_sensors()

            sensor_count = len(self._sensor_paths)
            self.logger.info(f"✅ Temperature Monitor initialized - {sensor_count} sensors found")

            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Temperature Monitor: {e}")
            return False

    @safe_execute
    async def _discover_sensors(self) -> List[Dict[str, Any]]:
        """Discover available temperature sensors"""
        try:
            sensors = []

            # Raspberry Pi CPU temperature (primary method)
            thermal_zone_path = "/sys/class/thermal/thermal_zone0/temp"
            try:
                with open(thermal_zone_path, 'r') as f:
                    temp_raw = f.read().strip()
                    temp_celsius = float(temp_raw) / 1000
                    sensors.append({
                        'name': 'CPU',
                        'path': thermal_zone_path,
                        'type': 'cpu',
                        'method': 'thermal_zone',
                        'test_reading': temp_celsius
                    })
            except Exception as e:
                self.logger.debug(f"thermal_zone0 not available: {e}")

            # Try vcgencmd for Raspberry Pi
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "vcgencmd measure_temp"
                )
                if returncode == 0 and 'temp=' in stdout:
                    temp_str = stdout.split('temp=')[1].split("'C")[0]
                    temp_celsius = float(temp_str)
                    # Only add if we don't already have thermal_zone
                    if not any(s['method'] == 'thermal_zone' for s in sensors):
                        sensors.append({
                            'name': 'CPU (vcgencmd)',
                            'path': 'vcgencmd',
                            'type': 'cpu',
                            'method': 'vcgencmd',
                            'test_reading': temp_celsius
                        })
            except Exception as e:
                self.logger.debug(f"vcgencmd not available: {e}")

            # Try psutil sensors (for other systems)
            try:
                if hasattr(psutil, "sensors_temperatures"):
                    psutil_temps = psutil.sensors_temperatures()
                    for sensor_name, temp_list in psutil_temps.items():
                        for i, temp_entry in enumerate(temp_list):
                            sensor_id = f"{sensor_name}_{i}" if len(temp_list) > 1 else sensor_name
                            sensors.append({
                                'name': f"{sensor_name} #{i+1}" if len(temp_list) > 1 else sensor_name,
                                'path': f'psutil:{sensor_name}:{i}',
                                'type': 'hardware' if 'cpu' not in sensor_name.lower() else 'cpu',
                                'method': 'psutil',
                                'test_reading': temp_entry.current,
                                'label': getattr(temp_entry, 'label', ''),
                                'high': getattr(temp_entry, 'high', None),
                                'critical': getattr(temp_entry, 'critical', None)
                            })
            except Exception as e:
                self.logger.debug(f"psutil sensors not available: {e}")

            # Look for 1-wire temperature sensors
            try:
                w1_devices = glob.glob('/sys/bus/w1/devices/28-*/w1_slave')
                for device_path in w1_devices:
                    device_id = device_path.split('/')[-2]
                    try:
                        with open(device_path, 'r') as f:
                            lines = f.readlines()
                            if len(lines) >= 2 and 'YES' in lines[0]:
                                temp_line = lines[1]
                                temp_pos = temp_line.find('t=')
                                if temp_pos != -1:
                                    temp_string = temp_line[temp_pos+2:]
                                    temp_celsius = float(temp_string) / 1000
                                    sensors.append({
                                        'name': f'1-Wire {device_id}',
                                        'path': device_path,
                                        'type': 'external',
                                        'method': 'onewire',
                                        'device_id': device_id,
                                        'test_reading': temp_celsius
                                    })
                    except Exception as e:
                        self.logger.debug(f"Could not read 1-wire sensor {device_path}: {e}")
            except Exception as e:
                self.logger.debug(f"1-wire sensors not available: {e}")

            # Look for additional thermal zones
            try:
                thermal_zones = glob.glob('/sys/class/thermal/thermal_zone*/temp')
                for zone_path in thermal_zones:
                    zone_num = zone_path.split('/')[-2].replace('thermal_zone', '')
                    if zone_num != '0':  # Skip zone0 as we already checked it
                        try:
                            with open(zone_path, 'r') as f:
                                temp_raw = f.read().strip()
                                temp_celsius = float(temp_raw) / 1000
                                sensors.append({
                                    'name': f'Thermal Zone {zone_num}',
                                    'path': zone_path,
                                    'type': 'hardware',
                                    'method': 'thermal_zone',
                                    'zone': zone_num,
                                    'test_reading': temp_celsius
                                })
                        except Exception as e:
                            self.logger.debug(f"Could not read thermal zone {zone_path}: {e}")
            except Exception as e:
                self.logger.debug(f"Additional thermal zones not available: {e}")

            self.logger.info(f"Discovered {len(sensors)} temperature sensors")
            for sensor in sensors:
                self.logger.debug(f"Sensor: {sensor['name']} ({sensor['method']}) - {sensor['test_reading']:.1f}°C")

            return sensors

        except Exception as e:
            self.logger.error(f"Error discovering sensors: {e}")
            return []

    @safe_execute
    async def get_temperature_readings(self) -> Dict[str, Any]:
        """Get current temperature readings from all sensors"""
        try:
            # Check cache
            if self._is_cached_data_valid('readings'):
                return self._cached_data['readings']

            readings = {
                'timestamp': datetime.now().isoformat(),
                'sensors': {},
                'summary': {
                    'max_temp': 0,
                    'min_temp': 100,
                    'avg_temp': 0,
                    'cpu_temp': None,
                    'status': 'unknown'
                }
            }

            valid_temps = []

            for sensor in self._sensor_paths:
                try:
                    temp_value = await self._read_sensor(sensor)
                    if temp_value is not None:
                        sensor_reading = {
                            'name': sensor['name'],
                            'temperature': round(temp_value, 2),
                            'type': sensor['type'],
                            'method': sensor['method'],
                            'status': self._get_temperature_status(temp_value, sensor['type'])
                        }

                        # Add thresholds if available
                        if 'high' in sensor and sensor['high']:
                            sensor_reading['high_threshold'] = sensor['high']
                        if 'critical' in sensor and sensor['critical']:
                            sensor_reading['critical_threshold'] = sensor['critical']

                        readings['sensors'][sensor['name']] = sensor_reading
                        valid_temps.append(temp_value)

                        # Track CPU temperature specifically
                        if sensor['type'] == 'cpu' and readings['summary']['cpu_temp'] is None:
                            readings['summary']['cpu_temp'] = temp_value

                except Exception as e:
                    self.logger.error(f"Error reading sensor {sensor['name']}: {e}")
                    continue

            # Calculate summary statistics
            if valid_temps:
                readings['summary']['max_temp'] = round(max(valid_temps), 2)
                readings['summary']['min_temp'] = round(min(valid_temps), 2)
                readings['summary']['avg_temp'] = round(sum(valid_temps) / len(valid_temps), 2)

                # Overall temperature status based on maximum temperature
                readings['summary']['status'] = self._get_temperature_status(
                    readings['summary']['max_temp'], 'system'
                )

            # Cache the data
            self._cached_data['readings'] = readings
            self._last_update = time.time()

            # Add to history
            self._add_to_history(readings)

            return readings

        except Exception as e:
            self.logger.error(f"Error getting temperature readings: {e}")
            return {}

    @safe_execute
    async def _read_sensor(self, sensor: Dict[str, Any]) -> Optional[float]:
        """Read temperature from a specific sensor"""
        try:
            method = sensor['method']

            if method == 'thermal_zone':
                with open(sensor['path'], 'r') as f:
                    temp_raw = f.read().strip()
                    return float(temp_raw) / 1000

            elif method == 'vcgencmd':
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "vcgencmd measure_temp"
                )
                if returncode == 0 and 'temp=' in stdout:
                    temp_str = stdout.split('temp=')[1].split("'C")[0]
                    return float(temp_str)

            elif method == 'psutil':
                if hasattr(psutil, "sensors_temperatures"):
                    path_parts = sensor['path'].split(':')
                    sensor_name = path_parts[1]
                    sensor_index = int(path_parts[2])
                    temps = psutil.sensors_temperatures()
                    if sensor_name in temps and sensor_index < len(temps[sensor_name]):
                        return temps[sensor_name][sensor_index].current

            elif method == 'onewire':
                with open(sensor['path'], 'r') as f:
                    lines = f.readlines()
                    if len(lines) >= 2 and 'YES' in lines[0]:
                        temp_line = lines[1]
                        temp_pos = temp_line.find('t=')
                        if temp_pos != -1:
                            temp_string = temp_line[temp_pos+2:]
                            return float(temp_string) / 1000

            return None

        except Exception as e:
            self.logger.error(f"Error reading sensor {sensor['name']}: {e}")
            return None

    def _get_temperature_status(self, temperature: float, sensor_type: str) -> Dict[str, Any]:
        """Get temperature status based on thresholds"""
        try:
            # Use different thresholds based on sensor type
            if sensor_type == 'cpu':
                thresholds = getattr(THRESHOLDS, 'cpu_temp', {
                    'info': 40.0, 'warning': 60.0, 'critical': 75.0, 'danger': 85.0
                })
            else:
                # General hardware thresholds (more conservative)
                thresholds = {
                    'info': 35.0, 'warning': 50.0, 'critical': 65.0, 'danger': 80.0
                }

            if temperature < thresholds.get('info', 40):
                return {
                    'level': 'normal',
                    'emoji': '❄️',
                    'text': 'Cool',
                    'color': 'blue'
                }
            elif temperature < thresholds.get('warning', 60):
                return {
                    'level': 'info',
                    'emoji': '🟢',
                    'text': 'Normal',
                    'color': 'green'
                }
            elif temperature < thresholds.get('critical', 75):
                return {
                    'level': 'warning',
                    'emoji': '🟡',
                    'text': 'Warm',
                    'color': 'yellow'
                }
            elif temperature < thresholds.get('danger', 85):
                return {
                    'level': 'critical',
                    'emoji': '🟠',
                    'text': 'Hot',
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

    @safe_execute
    async def get_temperature_trends(self, minutes: int = 60) -> Dict[str, Any]:
        """Analyze temperature trends over time"""
        try:
            trends = {
                'timestamp': datetime.now().isoformat(),
                'timeframe_minutes': minutes,
                'sensors': {},
                'overall_trend': 'stable'
            }

            cutoff_time = datetime.now() - timedelta(minutes=minutes)

            # Filter history for timeframe
            filtered_history = []
            for entry in self._temperature_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time:
                        filtered_history.append(entry)
                except:
                    continue

            if len(filtered_history) < 2:
                return trends

            # Analyze trends for each sensor
            sensor_trends = {}
            for sensor_name in self._get_sensor_names():
                sensor_temps = []
                sensor_times = []

                for entry in filtered_history:
                    if sensor_name in entry.get('sensors', {}):
                        temp = entry['sensors'][sensor_name].get('temperature')
                        if temp is not None:
                            sensor_temps.append(temp)
                            sensor_times.append(entry['timestamp'])

                if len(sensor_temps) >= 2:
                    trend_analysis = self._analyze_trend(sensor_temps, sensor_times)
                    trends['sensors'][sensor_name] = trend_analysis
                    sensor_trends[sensor_name] = trend_analysis['direction']

            # Determine overall trend
            if sensor_trends:
                rising_count = sum(1 for trend in sensor_trends.values() if trend == 'rising')
                falling_count = sum(1 for trend in sensor_trends.values() if trend == 'falling')
                total_sensors = len(sensor_trends)

                if rising_count > total_sensors * 0.6:
                    trends['overall_trend'] = 'rising'
                elif falling_count > total_sensors * 0.6:
                    trends['overall_trend'] = 'falling'
                else:
                    trends['overall_trend'] = 'stable'

            return trends

        except Exception as e:
            self.logger.error(f"Error getting temperature trends: {e}")
            return {}

    def _get_sensor_names(self) -> List[str]:
        """Get list of sensor names"""
        return [sensor['name'] for sensor in self._sensor_paths]

    def _analyze_trend(self, temperatures: List[float], timestamps: List[str]) -> Dict[str, Any]:
        """Analyze temperature trend for a single sensor"""
        try:
            if len(temperatures) < 2:
                return {'direction': 'unknown', 'rate': 0, 'confidence': 0}

            # Simple linear trend analysis
            n = len(temperatures)
            sum_temp = sum(temperatures)
            sum_time = sum(range(n))  # Use index as time proxy
            sum_temp_time = sum(i * temp for i, temp in enumerate(temperatures))
            sum_time_sq = sum(i * i for i in range(n))

            # Calculate slope (temperature change rate)
            slope = (n * sum_temp_time - sum_time * sum_temp) / (n * sum_time_sq - sum_time * sum_time)

            # Determine direction and confidence
            temp_range = max(temperatures) - min(temperatures)
            confidence = min(100, abs(slope) * 50)  # Arbitrary confidence calculation

            if abs(slope) < 0.1:  # Small change threshold
                direction = 'stable'
            elif slope > 0:
                direction = 'rising'
            else:
                direction = 'falling'

            return {
                'direction': direction,
                'rate': round(slope, 3),
                'confidence': round(confidence, 1),
                'temp_range': round(temp_range, 2),
                'current_temp': temperatures[-1],
                'previous_temp': temperatures[0]
            }

        except Exception as e:
            self.logger.error(f"Error analyzing trend: {e}")
            return {'direction': 'unknown', 'rate': 0, 'confidence': 0}

    def _add_to_history(self, readings: Dict[str, Any]):
        """Add temperature readings to history"""
        try:
            # Store simplified history entry
            history_entry = {
                'timestamp': readings['timestamp'],
                'sensors': {}
            }

            for sensor_name, sensor_data in readings.get('sensors', {}).items():
                history_entry['sensors'][sensor_name] = {
                    'temperature': sensor_data['temperature'],
                    'status_level': sensor_data['status']['level']
                }

            self._temperature_history.append(history_entry)

            # Keep only the last N data points
            if len(self._temperature_history) > self._max_history:
                self._temperature_history = self._temperature_history[-self._max_history:]

        except Exception as e:
            self.logger.error(f"Error adding to history: {e}")

    @safe_execute
    async def get_temperature_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get temperature history"""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            filtered_history = []

            for entry in self._temperature_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time:
                        filtered_history.append(entry)
                except:
                    continue

            return filtered_history

        except Exception as e:
            self.logger.error(f"Error getting temperature history: {e}")
            return []

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive temperature report"""
        try:
            readings = await self.get_temperature_readings()
            trends = await self.get_temperature_trends(30)  # 30 minute trends

            report_lines = [
                "🌡️  TEMPERATURE MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add current readings
            sensors = readings.get('sensors', {})
            if sensors:
                report_lines.extend([
                    "",
                    "🌡️  CURRENT TEMPERATURES",
                    "-" * 30,
                ])

                for sensor_name, sensor_data in sensors.items():
                    status = sensor_data.get('status', {})
                    temp = sensor_data.get('temperature', 0)
                    sensor_type = sensor_data.get('type', 'unknown')

                    report_lines.append(
                        f"{status.get('emoji', '⚪')} {sensor_name}: {temp:.1f}°C "
                        f"({status.get('text', 'Unknown')}) [{sensor_type}]"
                    )

            # Add summary
            summary = readings.get('summary', {})
            if summary:
                overall_status = summary.get('status', {})
                report_lines.extend([
                    "",
                    "📊 TEMPERATURE SUMMARY",
                    "-" * 30,
                    f"🔥 Maximum: {summary.get('max_temp', 0):.1f}°C",
                    f"❄️  Minimum: {summary.get('min_temp', 0):.1f}°C",
                    f"📊 Average: {summary.get('avg_temp', 0):.1f}°C",
                    f"{overall_status.get('emoji', '⚪')} Overall Status: {overall_status.get('text', 'Unknown')}",
                ])

                # Add CPU temperature specifically
                cpu_temp = summary.get('cpu_temp')
                if cpu_temp is not None:
                    report_lines.append(f"🖥️  CPU Temperature: {cpu_temp:.1f}°C")

            # Add trends
            overall_trend = trends.get('overall_trend', 'unknown')
            trend_emoji = {'rising': '📈', 'falling': '📉', 'stable': '➡️'}.get(overall_trend, '❓')

            report_lines.extend([
                "",
                "📈 TEMPERATURE TRENDS (30 min)",
                "-" * 30,
                f"{trend_emoji} Overall Trend: {overall_trend.title()}",
            ])

            # Add individual sensor trends
            sensor_trends = trends.get('sensors', {})
            if sensor_trends:
                report_lines.append("🔍 Sensor Trends:")
                for sensor_name, trend_data in sensor_trends.items():
                    direction = trend_data.get('direction', 'unknown')
                    rate = trend_data.get('rate', 0)
                    confidence = trend_data.get('confidence', 0)

                    trend_emoji = {'rising': '📈', 'falling': '📉', 'stable': '➡️'}.get(direction, '❓')
                    report_lines.append(
                        f"   {trend_emoji} {sensor_name}: {direction} "
                        f"({rate:+.2f}°C/period, {confidence:.0f}% confidence)"
                    )

            # Add warnings for high temperatures
            high_temp_sensors = []
            for sensor_name, sensor_data in sensors.items():
                status_level = sensor_data.get('status', {}).get('level', 'normal')
                if status_level in ['critical', 'danger']:
                    high_temp_sensors.append((sensor_name, sensor_data))

            if high_temp_sensors:
                report_lines.extend([
                    "",
                    "⚠️  HIGH TEMPERATURE WARNINGS",
                    "-" * 30,
                ])
                for sensor_name, sensor_data in high_temp_sensors:
                    temp = sensor_data.get('temperature', 0)
                    status = sensor_data.get('status', {})
                    report_lines.append(
                        f"🚨 {sensor_name}: {temp:.1f}°C ({status.get('text', 'Unknown')})"
                    )

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating temperature report: {e}")
            return f"❌ Error generating temperature report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Temperature Monitor...")
            self._cached_data.clear()
            self._temperature_history.clear()
            self.logger.info("✅ Temperature Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Temperature Monitor cleanup: {e}")