"""
Network Monitor Module - Network interfaces and connectivity monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive network monitoring and analysis capabilities including interface statistics, connectivity tests, and network performance metrics.
License: For educational and personal use
"""

import asyncio
import logging
import socket
import time
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import psutil

from config.settings import THRESHOLDS, MONITORING_CONFIG
from utils.helpers import (
    safe_execute, run_command, format_bytes, calculate_percentage,
    check_internet_connectivity, get_local_ip, ping_host
)

logger = logging.getLogger('monitoring.network')


class NetworkMonitor:
    """Network interfaces and connectivity monitoring class"""

    def __init__(self):
        """Initialize the network monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 10  # seconds
        self._cached_data = {}
        self._network_history = []
        self._max_history = 120  # Keep 2 hours of data points
        self._previous_stats = None

    async def initialize(self) -> bool:
        """Initialize the network monitor"""
        try:
            self.logger.info("🚀 Initializing Network Monitor...")

            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            self.logger.info(f"✅ Network Monitor initialized - {len(interfaces)} interfaces detected")

            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Network Monitor: {e}")
            return False

    @safe_execute
    async def get_network_interfaces(self) -> Dict[str, Any]:
        """Get detailed network interface information"""
        try:
            # Check cache
            if self._is_cached_data_valid('interfaces'):
                return self._cached_data['interfaces']

            interfaces_info = {
                'timestamp': datetime.now().isoformat(),
                'interfaces': {},
                'active_interfaces': [],
                'total_interfaces': 0
            }

            # Get interface addresses
            if_addrs = psutil.net_if_addrs()
            # Get interface statistics
            if_stats = psutil.net_if_stats()

            for interface_name, addresses in if_addrs.items():
                interface_info = {
                    'name': interface_name,
                    'addresses': [],
                    'is_up': False,
                    'is_running': False,
                    'mtu': 0,
                    'speed': 0,
                    'duplex': 'unknown',
                    'type': await self._get_interface_type(interface_name)
                }

                # Get interface statistics
                if interface_name in if_stats:
                    stats = if_stats[interface_name]
                    interface_info.update({
                        'is_up': stats.isup,
                        'is_running': getattr(stats, 'isrunning', False),
                        'mtu': stats.mtu,
                        'speed': stats.speed,
                        'duplex': str(getattr(stats, 'duplex', 'unknown')),
                    })

                # Process addresses
                for addr in addresses:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': getattr(addr, 'netmask', None),
                        'broadcast': getattr(addr, 'broadcast', None),
                        'ptp': getattr(addr, 'ptp', None)
                    }

                    # Add address type classification
                    addr_info['type'] = await self._classify_address(addr.address, str(addr.family))
                    interface_info['addresses'].append(addr_info)

                # Get additional interface details
                interface_info['details'] = await self._get_interface_details(interface_name)

                interfaces_info['interfaces'][interface_name] = interface_info

                # Track active interfaces
                if interface_info['is_up'] and interface_name != 'lo':
                    interfaces_info['active_interfaces'].append(interface_name)

            interfaces_info['total_interfaces'] = len(interfaces_info['interfaces'])

            # Cache the data
            self._cached_data['interfaces'] = interfaces_info
            self._last_update = time.time()

            return interfaces_info

        except Exception as e:
            self.logger.error(f"Error getting network interfaces: {e}")
            return {}

    @safe_execute
    async def _get_interface_type(self, interface_name: str) -> str:
        """Determine interface type based on name"""
        try:
            if interface_name.startswith('eth'):
                return 'ethernet'
            elif interface_name.startswith('wlan') or interface_name.startswith('wlp'):
                return 'wireless'
            elif interface_name.startswith('lo'):
                return 'loopback'
            elif interface_name.startswith('docker') or interface_name.startswith('br-'):
                return 'bridge'
            elif interface_name.startswith('tun') or interface_name.startswith('tap'):
                return 'tunnel'
            elif interface_name.startswith('veth'):
                return 'virtual'
            else:
                return 'unknown'
        except Exception as e:
            self.logger.error(f"Error getting interface type for {interface_name}: {e}")
            return 'unknown'

    @safe_execute
    async def _classify_address(self, address: str, family: str) -> str:
        """Classify an IP address"""
        try:
            if 'AF_INET' in family:  # IPv4
                ip = ipaddress.IPv4Address(address)
                if ip.is_private:
                    return 'private'
                elif ip.is_loopback:
                    return 'loopback'
                elif ip.is_link_local:
                    return 'link_local'
                else:
                    return 'public'
            elif 'AF_INET6' in family:  # IPv6
                ip = ipaddress.IPv6Address(address)
                if ip.is_private:
                    return 'private'
                elif ip.is_loopback:
                    return 'loopback'
                elif ip.is_link_local:
                    return 'link_local'
                else:
                    return 'public'
            elif 'AF_PACKET' in family:  # MAC address
                return 'hardware'
            else:
                return 'unknown'
        except Exception as e:
            self.logger.debug(f"Could not classify address {address}: {e}")
            return 'unknown'

    @safe_execute
    async def _get_interface_details(self, interface_name: str) -> Dict[str, Any]:
        """Get additional interface details from system"""
        try:
            details = {}

            # Get interface details from ip command
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, f"ip addr show {interface_name}"
                )
                if returncode == 0:
                    details['ip_output'] = stdout.strip()
            except Exception as e:
                self.logger.debug(f"Could not get ip details for {interface_name}: {e}")

            # Get wireless information if applicable
            if interface_name.startswith('wlan') or interface_name.startswith('wlp'):
                wireless_details = await self._get_wireless_details(interface_name)
                if wireless_details:
                    details['wireless'] = wireless_details

            return details

        except Exception as e:
            self.logger.error(f"Error getting interface details for {interface_name}: {e}")
            return {}

    @safe_execute
    async def _get_wireless_details(self, interface_name: str) -> Optional[Dict[str, Any]]:
        """Get wireless interface details"""
        try:
            wireless_info = {}

            # Try to get wireless information using iwconfig
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, f"iwconfig {interface_name}"
                )
                if returncode == 0:
                    wireless_info['iwconfig'] = await self._parse_iwconfig(stdout)
            except Exception as e:
                self.logger.debug(f"iwconfig failed for {interface_name}: {e}")

            # Try to get wireless scan results
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, f"iwlist {interface_name} scan", timeout=10
                )
                if returncode == 0:
                    wireless_info['scan'] = await self._parse_iwlist_scan(stdout)
            except Exception as e:
                self.logger.debug(f"iwlist scan failed for {interface_name}: {e}")

            return wireless_info if wireless_info else None

        except Exception as e:
            self.logger.error(f"Error getting wireless details for {interface_name}: {e}")
            return None

    @safe_execute
    async def _parse_iwconfig(self, iwconfig_output: str) -> Dict[str, Any]:
        """Parse iwconfig output"""
        try:
            info = {}
            for line in iwconfig_output.split('\n'):
                line = line.strip()
                if 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    info['ssid'] = essid
                elif 'Bit Rate=' in line:
                    bit_rate = line.split('Bit Rate=')[1].split(' ')[0]
                    info['bit_rate'] = bit_rate
                elif 'Signal level=' in line:
                    signal = line.split('Signal level=')[1].split(' ')[0]
                    info['signal_level'] = signal
                elif 'Link Quality=' in line:
                    quality = line.split('Link Quality=')[1].split(' ')[0]
                    info['link_quality'] = quality
            return info
        except Exception as e:
            self.logger.error(f"Error parsing iwconfig output: {e}")
            return {}

    @safe_execute
    async def _parse_iwlist_scan(self, scan_output: str) -> List[Dict[str, Any]]:
        """Parse iwlist scan output"""
        try:
            networks = []
            current_network = {}

            for line in scan_output.split('\n'):
                line = line.strip()
                if 'Cell ' in line and 'Address:' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {'bssid': line.split('Address: ')[1]}
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    current_network['ssid'] = essid
                elif 'Signal level=' in line:
                    signal = line.split('Signal level=')[1].split(' ')[0]
                    current_network['signal_level'] = signal
                elif 'Quality=' in line:
                    quality = line.split('Quality=')[1].split(' ')[0]
                    current_network['quality'] = quality

            if current_network:
                networks.append(current_network)

            return networks
        except Exception as e:
            self.logger.error(f"Error parsing iwlist scan output: {e}")
            return []

    @safe_execute
    async def get_network_statistics(self) -> Dict[str, Any]:
        """Get network I/O statistics"""
        try:
            network_stats = {
                'timestamp': datetime.now().isoformat(),
                'per_interface': {},
                'totals': {},
                'rates': {}
            }

            # Get current network I/O statistics
            current_stats = psutil.net_io_counters(pernic=True)
            total_stats = psutil.net_io_counters()

            # Process per-interface statistics
            for interface_name, iostat in current_stats.items():
                network_stats['per_interface'][interface_name] = {
                    'bytes_sent': iostat.bytes_sent,
                    'bytes_recv': iostat.bytes_recv,
                    'packets_sent': iostat.packets_sent,
                    'packets_recv': iostat.packets_recv,
                    'errin': iostat.errin,
                    'errout': iostat.errout,
                    'dropin': iostat.dropin,
                    'dropout': iostat.dropout,
                    'bytes_sent_formatted': format_bytes(iostat.bytes_sent),
                    'bytes_recv_formatted': format_bytes(iostat.bytes_recv),
                }

            # Total statistics
            if total_stats:
                network_stats['totals'] = {
                    'bytes_sent': total_stats.bytes_sent,
                    'bytes_recv': total_stats.bytes_recv,
                    'packets_sent': total_stats.packets_sent,
                    'packets_recv': total_stats.packets_recv,
                    'errin': total_stats.errin,
                    'errout': total_stats.errout,
                    'dropin': total_stats.dropin,
                    'dropout': total_stats.dropout,
                    'bytes_sent_formatted': format_bytes(total_stats.bytes_sent),
                    'bytes_recv_formatted': format_bytes(total_stats.bytes_recv),
                }

            # Calculate rates if we have previous data
            if self._previous_stats:
                network_stats['rates'] = await self._calculate_network_rates(
                    self._previous_stats, current_stats, total_stats
                )

            # Store current stats for next calculation
            self._previous_stats = {
                'timestamp': time.time(),
                'per_interface': current_stats,
                'total': total_stats
            }

            # Add to history
            self._add_to_history(network_stats)

            return network_stats

        except Exception as e:
            self.logger.error(f"Error getting network statistics: {e}")
            return {}

    @safe_execute
    async def _calculate_network_rates(self, previous_stats: Dict[str, Any],
                                     current_per_interface: Dict, current_total) -> Dict[str, Any]:
        """Calculate network transfer rates"""
        try:
            rates = {
                'per_interface': {},
                'totals': {}
            }

            time_diff = time.time() - previous_stats['timestamp']
            if time_diff <= 0:
                return rates

            # Calculate per-interface rates
            prev_per_interface = previous_stats.get('per_interface', {})
            for interface_name, current_stats in current_per_interface.items():
                if interface_name in prev_per_interface:
                    prev_stats = prev_per_interface[interface_name]
                    rates['per_interface'][interface_name] = {
                        'bytes_sent_rate': (current_stats.bytes_sent - prev_stats.bytes_sent) / time_diff,
                        'bytes_recv_rate': (current_stats.bytes_recv - prev_stats.bytes_recv) / time_diff,
                        'packets_sent_rate': (current_stats.packets_sent - prev_stats.packets_sent) / time_diff,
                        'packets_recv_rate': (current_stats.packets_recv - prev_stats.packets_recv) / time_diff,
                    }

                    # Format rates
                    interface_rates = rates['per_interface'][interface_name]
                    interface_rates['bytes_sent_rate_formatted'] = format_bytes(
                        interface_rates['bytes_sent_rate']
                    ) + '/s'
                    interface_rates['bytes_recv_rate_formatted'] = format_bytes(
                        interface_rates['bytes_recv_rate']
                    ) + '/s'

            # Calculate total rates
            prev_total = previous_stats.get('total')
            if prev_total and current_total:
                rates['totals'] = {
                    'bytes_sent_rate': (current_total.bytes_sent - prev_total.bytes_sent) / time_diff,
                    'bytes_recv_rate': (current_total.bytes_recv - prev_total.bytes_recv) / time_diff,
                    'packets_sent_rate': (current_total.packets_sent - prev_total.packets_sent) / time_diff,
                    'packets_recv_rate': (current_total.packets_recv - prev_total.packets_recv) / time_diff,
                }

                # Format total rates
                rates['totals']['bytes_sent_rate_formatted'] = format_bytes(
                    rates['totals']['bytes_sent_rate']
                ) + '/s'
                rates['totals']['bytes_recv_rate_formatted'] = format_bytes(
                    rates['totals']['bytes_recv_rate']
                ) + '/s'

            return rates

        except Exception as e:
            self.logger.error(f"Error calculating network rates: {e}")
            return {}

    @safe_execute
    async def get_connectivity_status(self) -> Dict[str, Any]:
        """Get network connectivity status"""
        try:
            connectivity = {
                'timestamp': datetime.now().isoformat(),
                'internet_connected': False,
                'dns_working': False,
                'default_gateway': None,
                'public_ip': None,
                'connectivity_tests': {}
            }

            # Test internet connectivity
            connectivity['internet_connected'] = await asyncio.to_thread(
                check_internet_connectivity
            )

            # Get default gateway
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "ip route show default"
                )
                if returncode == 0 and stdout:
                    # Parse default gateway
                    for line in stdout.split('\n'):
                        if 'default via' in line:
                            gateway = line.split('default via')[1].split()[0]
                            connectivity['default_gateway'] = gateway
                            break
            except Exception as e:
                self.logger.debug(f"Could not get default gateway: {e}")

            # Test DNS resolution
            try:
                socket.gethostbyname('google.com')
                connectivity['dns_working'] = True
            except Exception as e:
                self.logger.debug(f"DNS test failed: {e}")
                connectivity['dns_working'] = False

            # Get public IP
            try:
                connectivity['public_ip'] = await self._get_public_ip()
            except Exception as e:
                self.logger.debug(f"Could not get public IP: {e}")

            # Perform connectivity tests
            test_hosts = ['8.8.8.8', 'google.com', 'cloudflare.com']
            for host in test_hosts:
                try:
                    result = await asyncio.to_thread(ping_host, host, timeout=5)
                    connectivity['connectivity_tests'][host] = {
                        'reachable': result is not None,
                        'response_time': result
                    }
                except Exception as e:
                    connectivity['connectivity_tests'][host] = {
                        'reachable': False,
                        'error': str(e)
                    }

            return connectivity

        except Exception as e:
            self.logger.error(f"Error getting connectivity status: {e}")
            return {}

    @safe_execute
    async def _get_public_ip(self) -> Optional[str]:
        """Get public IP address"""
        try:
            import urllib.request
            import urllib.error

            # Try multiple services
            services = [
                'https://api.ipify.org',
                'https://ipinfo.io/ip',
                'https://icanhazip.com'
            ]

            for service in services:
                try:
                    response = await asyncio.to_thread(
                        urllib.request.urlopen, service, timeout=10
                    )
                    public_ip = response.read().decode().strip()
                    if public_ip:
                        return public_ip
                except Exception as e:
                    self.logger.debug(f"Service {service} failed: {e}")
                    continue

            return None

        except Exception as e:
            self.logger.error(f"Error getting public IP: {e}")
            return None

    @safe_execute
    async def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections"""
        try:
            connections = []

            for conn in psutil.net_connections(kind='inet'):
                try:
                    connection_info = {
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }

                    # Get process name if PID is available
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            connection_info['process_name'] = proc.name()
                            connection_info['username'] = proc.username()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            connection_info['process_name'] = 'Unknown'
                            connection_info['username'] = 'Unknown'

                    connections.append(connection_info)

                except Exception as e:
                    self.logger.debug(f"Could not process connection: {e}")
                    continue

            return connections

        except Exception as e:
            self.logger.error(f"Error getting network connections: {e}")
            return []

    @safe_execute
    async def get_listening_ports(self) -> List[Dict[str, Any]]:
        """Get listening ports and services"""
        try:
            listening_ports = []

            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    try:
                        port_info = {
                            'address': conn.laddr.ip if conn.laddr else 'Unknown',
                            'port': conn.laddr.port if conn.laddr else None,
                            'family': str(conn.family),
                            'type': str(conn.type),
                            'pid': conn.pid
                        }

                        # Get process information
                        if conn.pid:
                            try:
                                proc = psutil.Process(conn.pid)
                                port_info['process_name'] = proc.name()
                                port_info['username'] = proc.username()
                                port_info['cmdline'] = ' '.join(proc.cmdline())
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                port_info['process_name'] = 'Unknown'
                                port_info['username'] = 'Unknown'
                                port_info['cmdline'] = 'Unknown'

                        # Try to identify service
                        port_info['service'] = await self._identify_service(port_info.get('port'))

                        listening_ports.append(port_info)

                    except Exception as e:
                        self.logger.debug(f"Could not process listening port: {e}")
                        continue

            return listening_ports

        except Exception as e:
            self.logger.error(f"Error getting listening ports: {e}")
            return []

    @safe_execute
    async def _identify_service(self, port: int) -> str:
        """Identify common services by port number"""
        try:
            common_ports = {
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                3389: 'RDP',
                5432: 'PostgreSQL',
                3306: 'MySQL',
                6379: 'Redis',
                27017: 'MongoDB'
            }

            return common_ports.get(port, 'Unknown')

        except Exception as e:
            self.logger.error(f"Error identifying service for port {port}: {e}")
            return 'Unknown'

    def _add_to_history(self, network_stats: Dict[str, Any]):
        """Add network stats to history"""
        try:
            totals = network_stats.get('totals', {})
            rates = network_stats.get('rates', {}).get('totals', {})

            history_entry = {
                'timestamp': network_stats['timestamp'],
                'bytes_sent': totals.get('bytes_sent', 0),
                'bytes_recv': totals.get('bytes_recv', 0),
                'bytes_sent_rate': rates.get('bytes_sent_rate', 0),
                'bytes_recv_rate': rates.get('bytes_recv_rate', 0),
            }

            self._network_history.append(history_entry)

            # Keep only the last N data points
            if len(self._network_history) > self._max_history:
                self._network_history = self._network_history[-self._max_history:]

        except Exception as e:
            self.logger.error(f"Error adding to history: {e}")

    @safe_execute
    async def get_network_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get network usage history"""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            filtered_history = []

            for entry in self._network_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time:
                        filtered_history.append(entry)
                except:
                    continue

            return filtered_history

        except Exception as e:
            self.logger.error(f"Error getting network history: {e}")
            return []

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive network report"""
        try:
            interfaces = await self.get_network_interfaces()
            network_stats = await self.get_network_statistics()
            connectivity = await self.get_connectivity_status()
            listening_ports = await self.get_listening_ports()

            report_lines = [
                "🌐 NETWORK MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add connectivity status
            internet_status = "🟢 Connected" if connectivity.get('internet_connected') else "🔴 Disconnected"
            dns_status = "🟢 Working" if connectivity.get('dns_working') else "🔴 Failed"

            report_lines.extend([
                "",
                "🔗 CONNECTIVITY STATUS",
                "-" * 30,
                f"🌐 Internet: {internet_status}",
                f"🔍 DNS: {dns_status}",
                f"🚪 Gateway: {connectivity.get('default_gateway', 'Unknown')}",
                f"🌍 Public IP: {connectivity.get('public_ip', 'Unknown')}",
            ])

            # Add interface information
            active_interfaces = interfaces.get('active_interfaces', [])
            total_interfaces = interfaces.get('total_interfaces', 0)

            report_lines.extend([
                "",
                "🔌 NETWORK INTERFACES",
                "-" * 30,
                f"📊 Total Interfaces: {total_interfaces}",
                f"✅ Active Interfaces: {len(active_interfaces)}",
            ])

            # Add details for active interfaces
            for interface_name in active_interfaces:
                interface_data = interfaces.get('interfaces', {}).get(interface_name, {})
                interface_type = interface_data.get('type', 'unknown')

                report_lines.append(f"🔹 {interface_name} ({interface_type})")

                # Add IP addresses
                addresses = interface_data.get('addresses', [])
                for addr in addresses:
                    if addr.get('type') in ['private', 'public']:
                        report_lines.append(f"    📍 {addr['address']}")

            # Add network statistics
            rates = network_stats.get('rates', {}).get('totals', {})
            if rates:
                report_lines.extend([
                    "",
                    "📈 NETWORK TRAFFIC",
                    "-" * 30,
                    f"📤 Upload Rate: {rates.get('bytes_sent_rate_formatted', 'N/A')}",
                    f"📥 Download Rate: {rates.get('bytes_recv_rate_formatted', 'N/A')}",
                    f"📊 Packet TX Rate: {rates.get('packets_sent_rate', 0):.1f} pps",
                    f"📊 Packet RX Rate: {rates.get('packets_recv_rate', 0):.1f} pps",
                ])

            # Add connectivity test results
            connectivity_tests = connectivity.get('connectivity_tests', {})
            if connectivity_tests:
                report_lines.extend([
                    "",
                    "🏓 CONNECTIVITY TESTS",
                    "-" * 30,
                ])
                for host, result in connectivity_tests.items():
                    if result.get('reachable'):
                        response_time = result.get('response_time', 0)
                        report_lines.append(f"🟢 {host}: {response_time:.1f}ms")
                    else:
                        report_lines.append(f"🔴 {host}: Unreachable")

            # Add listening services
            if listening_ports:
                report_lines.extend([
                    "",
                    "👂 LISTENING SERVICES",
                    "-" * 30,
                ])
                for port_info in listening_ports[:10]:  # Limit to top 10
                    address = port_info.get('address', 'Unknown')
                    port = port_info.get('port', 'Unknown')
                    service = port_info.get('service', 'Unknown')
                    process = port_info.get('process_name', 'Unknown')

                    if address == '0.0.0.0':
                        address = 'All interfaces'
                    elif address == '127.0.0.1':
                        address = 'Localhost'

                    report_lines.append(f"🔹 {address}:{port} - {service} ({process})")

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating network report: {e}")
            return f"❌ Error generating network report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Network Monitor...")
            self._cached_data.clear()
            self._network_history.clear()
            self._previous_stats = None
            self.logger.info("✅ Network Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Network Monitor cleanup: {e}")