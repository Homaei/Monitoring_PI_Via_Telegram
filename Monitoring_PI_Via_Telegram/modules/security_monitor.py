"""
Security Monitor Module - Security checks and monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive security monitoring and assessment capabilities including system security analysis, vulnerability detection, and security compliance checks.
License: For educational and personal use
"""

import asyncio
import logging
import time
import hashlib
import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from config.settings import THRESHOLDS, MONITORING_CONFIG, AUTHORIZED_USERS
from utils.helpers import (
    safe_execute, run_command, check_file_permissions, get_file_hash
)

logger = logging.getLogger('monitoring.security')


class SecurityMonitor:
    """Security monitoring and assessment class"""

    def __init__(self):
        """Initialize the security monitor"""
        self.logger = logger
        self._last_update = None
        self._cache_duration = 300  # 5 minutes cache
        self._cached_data = {}
        self._security_events = []
        self._max_events = 1000
        self._critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/etc/hosts', '/etc/crontab'
        ]

    async def initialize(self) -> bool:
        """Initialize the security monitor"""
        try:
            self.logger.info("🚀 Initializing Security Monitor...")

            # Create baseline file hashes
            await self._create_file_baselines()

            self.logger.info("✅ Security Monitor initialized")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Security Monitor: {e}")
            return False

    @safe_execute
    async def _create_file_baselines(self):
        """Create baseline hashes for critical files"""
        try:
            baselines = {}
            for file_path in self._critical_files:
                try:
                    if os.path.exists(file_path):
                        file_hash = await asyncio.to_thread(get_file_hash, file_path)
                        baselines[file_path] = {
                            'hash': file_hash,
                            'size': os.path.getsize(file_path),
                            'mtime': os.path.getmtime(file_path),
                            'timestamp': datetime.now().isoformat()
                        }
                except Exception as e:
                    self.logger.debug(f"Could not create baseline for {file_path}: {e}")

            self._cached_data['file_baselines'] = baselines
            self.logger.info(f"Created baselines for {len(baselines)} critical files")

        except Exception as e:
            self.logger.error(f"Error creating file baselines: {e}")

    @safe_execute
    async def get_security_overview(self) -> Dict[str, Any]:
        """Get comprehensive security overview"""
        try:
            # Check cache
            if self._is_cached_data_valid('overview'):
                return self._cached_data['overview']

            overview = {
                'timestamp': datetime.now().isoformat(),
                'overall_score': 0,
                'risk_level': 'unknown',
                'categories': {
                    'authentication': await self._check_authentication_security(),
                    'network': await self._check_network_security(),
                    'file_system': await self._check_filesystem_security(),
                    'processes': await self._check_process_security(),
                    'system_integrity': await self._check_system_integrity(),
                    'updates': await self._check_system_updates()
                },
                'alerts': [],
                'recommendations': []
            }

            # Calculate overall security score
            category_scores = []
            for category, data in overview['categories'].items():
                score = data.get('score', 50)
                category_scores.append(score)

                # Collect alerts and recommendations
                if 'alerts' in data:
                    overview['alerts'].extend(data['alerts'])
                if 'recommendations' in data:
                    overview['recommendations'].extend(data['recommendations'])

            if category_scores:
                overview['overall_score'] = round(sum(category_scores) / len(category_scores), 1)

            # Determine risk level
            if overview['overall_score'] >= 85:
                overview['risk_level'] = 'low'
                overview['risk_emoji'] = '🟢'
            elif overview['overall_score'] >= 70:
                overview['risk_level'] = 'medium'
                overview['risk_emoji'] = '🟡'
            elif overview['overall_score'] >= 50:
                overview['risk_level'] = 'high'
                overview['risk_emoji'] = '🟠'
            else:
                overview['risk_level'] = 'critical'
                overview['risk_emoji'] = '🔴'

            # Cache the data
            self._cached_data['overview'] = overview
            self._last_update = time.time()

            return overview

        except Exception as e:
            self.logger.error(f"Error getting security overview: {e}")
            return {}

    @safe_execute
    async def _check_authentication_security(self) -> Dict[str, Any]:
        """Check authentication-related security"""
        try:
            auth_security = {
                'score': 100,
                'status': 'good',
                'checks': {},
                'alerts': [],
                'recommendations': []
            }

            # Check SSH configuration
            ssh_check = await self._check_ssh_security()
            auth_security['checks']['ssh'] = ssh_check
            auth_security['score'] -= ssh_check.get('penalty', 0)

            # Check password policies
            passwd_check = await self._check_password_policies()
            auth_security['checks']['passwords'] = passwd_check
            auth_security['score'] -= passwd_check.get('penalty', 0)

            # Check user accounts
            user_check = await self._check_user_accounts()
            auth_security['checks']['users'] = user_check
            auth_security['score'] -= user_check.get('penalty', 0)

            # Check sudo configuration
            sudo_check = await self._check_sudo_configuration()
            auth_security['checks']['sudo'] = sudo_check
            auth_security['score'] -= sudo_check.get('penalty', 0)

            # Collect alerts and recommendations
            for check in auth_security['checks'].values():
                auth_security['alerts'].extend(check.get('alerts', []))
                auth_security['recommendations'].extend(check.get('recommendations', []))

            auth_security['score'] = max(0, auth_security['score'])

            # Determine status
            if auth_security['score'] >= 80:
                auth_security['status'] = 'good'
            elif auth_security['score'] >= 60:
                auth_security['status'] = 'warning'
            else:
                auth_security['status'] = 'critical'

            return auth_security

        except Exception as e:
            self.logger.error(f"Error checking authentication security: {e}")
            return {'score': 0, 'status': 'error', 'error': str(e)}

    @safe_execute
    async def _check_ssh_security(self) -> Dict[str, Any]:
        """Check SSH security configuration"""
        try:
            ssh_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {}
            }

            ssh_config_path = '/etc/ssh/sshd_config'
            if not os.path.exists(ssh_config_path):
                ssh_check['alerts'].append("SSH configuration file not found")
                ssh_check['penalty'] += 20
                return ssh_check

            try:
                with open(ssh_config_path, 'r') as f:
                    ssh_config = f.read()

                # Check for root login
                if 'PermitRootLogin yes' in ssh_config:
                    ssh_check['alerts'].append("Root SSH login is enabled")
                    ssh_check['recommendations'].append("Disable root SSH login")
                    ssh_check['penalty'] += 15

                # Check for password authentication
                if 'PasswordAuthentication yes' in ssh_config:
                    ssh_check['details']['password_auth'] = True
                    ssh_check['recommendations'].append("Consider using key-based authentication only")
                    ssh_check['penalty'] += 5

                # Check for empty passwords
                if 'PermitEmptyPasswords yes' in ssh_config:
                    ssh_check['alerts'].append("Empty passwords are permitted for SSH")
                    ssh_check['penalty'] += 20

                # Check SSH version
                if 'Protocol 1' in ssh_config:
                    ssh_check['alerts'].append("SSH Protocol 1 is enabled (insecure)")
                    ssh_check['penalty'] += 25

                # Check for specific port
                port_match = re.search(r'Port\s+(\d+)', ssh_config)
                if port_match:
                    port = int(port_match.group(1))
                    ssh_check['details']['port'] = port
                    if port == 22:
                        ssh_check['recommendations'].append("Consider changing SSH port from default (22)")

            except Exception as e:
                ssh_check['alerts'].append(f"Could not read SSH configuration: {e}")
                ssh_check['penalty'] += 10

            return ssh_check

        except Exception as e:
            self.logger.error(f"Error checking SSH security: {e}")
            return {'penalty': 20, 'alerts': [f"SSH check failed: {e}"]}

    @safe_execute
    async def _check_password_policies(self) -> Dict[str, Any]:
        """Check password policy configuration"""
        try:
            passwd_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {}
            }

            # Check /etc/passwd for unusual entries
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "awk -F: '$3 == 0 {print $1}' /etc/passwd"
                )

                if returncode == 0:
                    root_users = [user.strip() for user in stdout.split('\n') if user.strip()]
                    passwd_check['details']['root_users'] = root_users

                    if len(root_users) > 1:
                        passwd_check['alerts'].append(f"Multiple root users found: {', '.join(root_users)}")
                        passwd_check['penalty'] += 15

            except Exception as e:
                passwd_check['alerts'].append(f"Could not check root users: {e}")

            # Check for users without passwords
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "awk -F: '$2 == \"\" {print $1}' /etc/shadow"
                )

                if returncode == 0:
                    users_no_pass = [user.strip() for user in stdout.split('\n') if user.strip()]
                    if users_no_pass:
                        passwd_check['alerts'].append(f"Users without passwords: {', '.join(users_no_pass)}")
                        passwd_check['penalty'] += 20

            except Exception as e:
                self.logger.debug(f"Could not check password status: {e}")

            return passwd_check

        except Exception as e:
            self.logger.error(f"Error checking password policies: {e}")
            return {'penalty': 10, 'alerts': [f"Password policy check failed: {e}"]}

    @safe_execute
    async def _check_user_accounts(self) -> Dict[str, Any]:
        """Check user account security"""
        try:
            user_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {'users': []}
            }

            # Get all users
            try:
                with open('/etc/passwd', 'r') as f:
                    passwd_lines = f.readlines()

                for line in passwd_lines:
                    if line.strip():
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            username = parts[0]
                            uid = int(parts[2])
                            home_dir = parts[5]
                            shell = parts[6]

                            user_info = {
                                'username': username,
                                'uid': uid,
                                'home_dir': home_dir,
                                'shell': shell,
                                'is_system': uid < 1000,
                                'has_shell': shell not in ['/bin/false', '/usr/sbin/nologin', '/bin/nologin']
                            }

                            user_check['details']['users'].append(user_info)

                            # Check for suspicious user accounts
                            if uid >= 1000 and user_info['has_shell']:
                                # Check last login
                                try:
                                    stdout, stderr, returncode = await asyncio.to_thread(
                                        run_command, f"lastlog -u {username}"
                                    )
                                    if "Never logged in" in stdout:
                                        user_check['recommendations'].append(
                                            f"User {username} has never logged in - consider reviewing"
                                        )
                                except:
                                    pass

            except Exception as e:
                user_check['alerts'].append(f"Could not read user accounts: {e}")
                user_check['penalty'] += 10

            return user_check

        except Exception as e:
            self.logger.error(f"Error checking user accounts: {e}")
            return {'penalty': 10, 'alerts': [f"User account check failed: {e}"]}

    @safe_execute
    async def _check_sudo_configuration(self) -> Dict[str, Any]:
        """Check sudo configuration security"""
        try:
            sudo_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {}
            }

            # Check /etc/sudoers
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "sudo -l"
                )

                if returncode == 0:
                    sudo_check['details']['sudo_access'] = stdout

                    # Check for NOPASSWD entries
                    if 'NOPASSWD' in stdout:
                        sudo_check['recommendations'].append(
                            "Some sudo commands don't require password - review NOPASSWD entries"
                        )

            except Exception as e:
                sudo_check['details']['sudo_check_error'] = str(e)

            return sudo_check

        except Exception as e:
            self.logger.error(f"Error checking sudo configuration: {e}")
            return {'penalty': 5, 'alerts': [f"Sudo check failed: {e}"]}

    @safe_execute
    async def _check_network_security(self) -> Dict[str, Any]:
        """Check network security configuration"""
        try:
            network_security = {
                'score': 100,
                'status': 'good',
                'checks': {},
                'alerts': [],
                'recommendations': []
            }

            # Check open ports
            ports_check = await self._check_open_ports()
            network_security['checks']['open_ports'] = ports_check
            network_security['score'] -= ports_check.get('penalty', 0)

            # Check firewall status
            firewall_check = await self._check_firewall_status()
            network_security['checks']['firewall'] = firewall_check
            network_security['score'] -= firewall_check.get('penalty', 0)

            # Check network connections
            connections_check = await self._check_suspicious_connections()
            network_security['checks']['connections'] = connections_check
            network_security['score'] -= connections_check.get('penalty', 0)

            # Collect alerts and recommendations
            for check in network_security['checks'].values():
                network_security['alerts'].extend(check.get('alerts', []))
                network_security['recommendations'].extend(check.get('recommendations', []))

            network_security['score'] = max(0, network_security['score'])

            if network_security['score'] >= 80:
                network_security['status'] = 'good'
            elif network_security['score'] >= 60:
                network_security['status'] = 'warning'
            else:
                network_security['status'] = 'critical'

            return network_security

        except Exception as e:
            self.logger.error(f"Error checking network security: {e}")
            return {'score': 0, 'status': 'error', 'error': str(e)}

    @safe_execute
    async def _check_open_ports(self) -> Dict[str, Any]:
        """Check for open ports and services"""
        try:
            ports_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {'listening_ports': []}
            }

            # Get listening ports
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "ss -tuln"
                )

                if returncode == 0:
                    lines = stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 5:
                                local_address = parts[4]
                                if ':' in local_address:
                                    port = local_address.split(':')[-1]
                                    if port.isdigit():
                                        port_num = int(port)
                                        ports_check['details']['listening_ports'].append(port_num)

                                        # Check for potentially risky ports
                                        if port_num in [23, 21, 135, 139, 445, 1433, 3389]:
                                            ports_check['alerts'].append(
                                                f"Potentially risky port {port_num} is open"
                                            )
                                            ports_check['penalty'] += 10

            except Exception as e:
                ports_check['alerts'].append(f"Could not check open ports: {e}")
                ports_check['penalty'] += 5

            return ports_check

        except Exception as e:
            self.logger.error(f"Error checking open ports: {e}")
            return {'penalty': 5, 'alerts': [f"Port check failed: {e}"]}

    @safe_execute
    async def _check_firewall_status(self) -> Dict[str, Any]:
        """Check firewall configuration"""
        try:
            firewall_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {}
            }

            # Check ufw status
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "ufw status"
                )

                if returncode == 0:
                    firewall_check['details']['ufw_status'] = stdout
                    if 'Status: inactive' in stdout:
                        firewall_check['alerts'].append("UFW firewall is inactive")
                        firewall_check['recommendations'].append("Enable UFW firewall for better security")
                        firewall_check['penalty'] += 15
                    elif 'Status: active' in stdout:
                        firewall_check['details']['ufw_active'] = True

            except Exception as e:
                firewall_check['details']['ufw_error'] = str(e)

            # Check iptables rules
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "iptables -L -n"
                )

                if returncode == 0:
                    firewall_check['details']['iptables_rules'] = len(stdout.split('\n'))
                    if 'ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0' in stdout:
                        firewall_check['recommendations'].append(
                            "Review iptables rules for overly permissive entries"
                        )

            except Exception as e:
                firewall_check['details']['iptables_error'] = str(e)

            return firewall_check

        except Exception as e:
            self.logger.error(f"Error checking firewall status: {e}")
            return {'penalty': 10, 'alerts': [f"Firewall check failed: {e}"]}

    @safe_execute
    async def _check_suspicious_connections(self) -> Dict[str, Any]:
        """Check for suspicious network connections"""
        try:
            connections_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {'connections': []}
            }

            # Get network connections
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "ss -tuplan"
                )

                if returncode == 0:
                    lines = stdout.split('\n')[1:]  # Skip header
                    established_connections = 0
                    for line in lines:
                        if 'ESTAB' in line:
                            established_connections += 1
                            parts = line.split()
                            if len(parts) >= 5:
                                local_addr = parts[4]
                                remote_addr = parts[5] if len(parts) > 5 else 'Unknown'
                                connections_check['details']['connections'].append({
                                    'local': local_addr,
                                    'remote': remote_addr
                                })

                    # Check for excessive connections
                    if established_connections > 100:
                        connections_check['alerts'].append(
                            f"High number of established connections: {established_connections}"
                        )
                        connections_check['penalty'] += 5

            except Exception as e:
                connections_check['alerts'].append(f"Could not check connections: {e}")

            return connections_check

        except Exception as e:
            self.logger.error(f"Error checking connections: {e}")
            return {'penalty': 5, 'alerts': [f"Connection check failed: {e}"]}

    @safe_execute
    async def _check_filesystem_security(self) -> Dict[str, Any]:
        """Check filesystem security"""
        try:
            fs_security = {
                'score': 100,
                'status': 'good',
                'checks': {},
                'alerts': [],
                'recommendations': []
            }

            # Check file permissions on critical files
            permissions_check = await self._check_file_permissions()
            fs_security['checks']['permissions'] = permissions_check
            fs_security['score'] -= permissions_check.get('penalty', 0)

            # Check for SUID/SGID files
            suid_check = await self._check_suid_files()
            fs_security['checks']['suid_files'] = suid_check
            fs_security['score'] -= suid_check.get('penalty', 0)

            # Check file integrity
            integrity_check = await self._check_file_integrity()
            fs_security['checks']['file_integrity'] = integrity_check
            fs_security['score'] -= integrity_check.get('penalty', 0)

            # Collect alerts and recommendations
            for check in fs_security['checks'].values():
                fs_security['alerts'].extend(check.get('alerts', []))
                fs_security['recommendations'].extend(check.get('recommendations', []))

            fs_security['score'] = max(0, fs_security['score'])

            if fs_security['score'] >= 80:
                fs_security['status'] = 'good'
            elif fs_security['score'] >= 60:
                fs_security['status'] = 'warning'
            else:
                fs_security['status'] = 'critical'

            return fs_security

        except Exception as e:
            self.logger.error(f"Error checking filesystem security: {e}")
            return {'score': 0, 'status': 'error', 'error': str(e)}

    @safe_execute
    async def _check_file_permissions(self) -> Dict[str, Any]:
        """Check permissions on critical files"""
        try:
            permissions_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {}
            }

            critical_files_perms = {
                '/etc/passwd': '644',
                '/etc/shadow': '640',
                '/etc/group': '644',
                '/etc/sudoers': '440',
                '/etc/ssh/sshd_config': '600'
            }

            for file_path, expected_perms in critical_files_perms.items():
                if os.path.exists(file_path):
                    try:
                        file_stat = os.stat(file_path)
                        actual_perms = oct(file_stat.st_mode)[-3:]

                        permissions_check['details'][file_path] = {
                            'expected': expected_perms,
                            'actual': actual_perms
                        }

                        if actual_perms != expected_perms:
                            permissions_check['alerts'].append(
                                f"{file_path} has incorrect permissions: {actual_perms} (expected: {expected_perms})"
                            )
                            permissions_check['penalty'] += 10

                    except Exception as e:
                        permissions_check['alerts'].append(f"Could not check permissions for {file_path}: {e}")

            return permissions_check

        except Exception as e:
            self.logger.error(f"Error checking file permissions: {e}")
            return {'penalty': 10, 'alerts': [f"File permissions check failed: {e}"]}

    @safe_execute
    async def _check_suid_files(self) -> Dict[str, Any]:
        """Check for SUID and SGID files"""
        try:
            suid_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {'suid_files': [], 'sgid_files': []}
            }

            # Find SUID files
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "find / -perm -4000 -type f 2>/dev/null", timeout=30
                )

                if returncode == 0:
                    suid_files = [f.strip() for f in stdout.split('\n') if f.strip()]
                    suid_check['details']['suid_files'] = suid_files

                    # Check for unusual SUID files
                    common_suid = ['/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd', '/bin/ping']
                    unusual_suid = [f for f in suid_files if f not in common_suid]

                    if unusual_suid:
                        suid_check['recommendations'].append(
                            f"Review unusual SUID files: {', '.join(unusual_suid[:5])}"
                        )

            except Exception as e:
                suid_check['alerts'].append(f"Could not check SUID files: {e}")

            return suid_check

        except Exception as e:
            self.logger.error(f"Error checking SUID files: {e}")
            return {'penalty': 5, 'alerts': [f"SUID check failed: {e}"]}

    @safe_execute
    async def _check_file_integrity(self) -> Dict[str, Any]:
        """Check integrity of critical files"""
        try:
            integrity_check = {
                'penalty': 0,
                'alerts': [],
                'recommendations': [],
                'details': {'changed_files': []}
            }

            baselines = self._cached_data.get('file_baselines', {})

            for file_path in self._critical_files:
                if os.path.exists(file_path) and file_path in baselines:
                    try:
                        baseline = baselines[file_path]
                        current_hash = await asyncio.to_thread(get_file_hash, file_path)
                        current_size = os.path.getsize(file_path)
                        current_mtime = os.path.getmtime(file_path)

                        if current_hash != baseline['hash']:
                            integrity_check['alerts'].append(f"File {file_path} has been modified")
                            integrity_check['details']['changed_files'].append({
                                'path': file_path,
                                'baseline_hash': baseline['hash'],
                                'current_hash': current_hash,
                                'size_change': current_size - baseline['size']
                            })
                            integrity_check['penalty'] += 15

                    except Exception as e:
                        integrity_check['alerts'].append(f"Could not check integrity of {file_path}: {e}")

            return integrity_check

        except Exception as e:
            self.logger.error(f"Error checking file integrity: {e}")
            return {'penalty': 10, 'alerts': [f"File integrity check failed: {e}"]}

    @safe_execute
    async def _check_process_security(self) -> Dict[str, Any]:
        """Check for suspicious processes"""
        try:
            process_security = {
                'score': 100,
                'status': 'good',
                'alerts': [],
                'recommendations': []
            }

            # This is a basic implementation - in production, you'd want more sophisticated checks
            suspicious_processes = ['nc', 'netcat', 'nmap', 'masscan']

            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "ps aux"
                )

                if returncode == 0:
                    for suspicious in suspicious_processes:
                        if suspicious in stdout.lower():
                            process_security['alerts'].append(f"Potentially suspicious process detected: {suspicious}")
                            process_security['score'] -= 10

            except Exception as e:
                process_security['alerts'].append(f"Could not check processes: {e}")
                process_security['score'] -= 5

            return process_security

        except Exception as e:
            self.logger.error(f"Error checking process security: {e}")
            return {'score': 0, 'status': 'error', 'error': str(e)}

    @safe_execute
    async def _check_system_integrity(self) -> Dict[str, Any]:
        """Check system integrity"""
        try:
            integrity = {
                'score': 100,
                'status': 'good',
                'alerts': [],
                'recommendations': []
            }

            # Check for rootkits (basic check)
            try:
                # Check for common rootkit indicators
                rootkit_paths = ['/tmp/.ICE-unix', '/tmp/.X11-unix', '/tmp/.font-unix']
                for path in rootkit_paths:
                    if os.path.exists(path):
                        stat_info = os.stat(path)
                        if not (stat_info.st_mode & 0o1000):  # Check sticky bit
                            integrity['alerts'].append(f"Suspicious directory permissions: {path}")
                            integrity['score'] -= 15

            except Exception as e:
                integrity['alerts'].append(f"Could not check for rootkits: {e}")

            return integrity

        except Exception as e:
            self.logger.error(f"Error checking system integrity: {e}")
            return {'score': 0, 'status': 'error', 'error': str(e)}

    @safe_execute
    async def _check_system_updates(self) -> Dict[str, Any]:
        """Check system update status"""
        try:
            updates = {
                'score': 100,
                'status': 'good',
                'alerts': [],
                'recommendations': [],
                'details': {}
            }

            # Check for available updates
            try:
                stdout, stderr, returncode = await asyncio.to_thread(
                    run_command, "apt list --upgradable 2>/dev/null | wc -l"
                )

                if returncode == 0:
                    update_count = int(stdout.strip()) - 1  # Subtract header line
                    updates['details']['available_updates'] = update_count

                    if update_count > 0:
                        updates['recommendations'].append(f"{update_count} updates available")
                        if update_count > 50:
                            updates['alerts'].append(f"Many updates available: {update_count}")
                            updates['score'] -= 20
                        elif update_count > 20:
                            updates['score'] -= 10
                        else:
                            updates['score'] -= 5

            except Exception as e:
                updates['alerts'].append(f"Could not check for updates: {e}")

            return updates

        except Exception as e:
            self.logger.error(f"Error checking system updates: {e}")
            return {'score': 90, 'alerts': [f"Update check failed: {e}"]}

    def _is_cached_data_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if not self._last_update or key not in self._cached_data:
            return False
        return (time.time() - self._last_update) < self._cache_duration

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a comprehensive security report"""
        try:
            overview = await self.get_security_overview()

            report_lines = [
                "🔒 SECURITY MONITORING REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add overall security score
            risk_emoji = overview.get('risk_emoji', '❓')
            risk_level = overview.get('risk_level', 'unknown').upper()
            score = overview.get('overall_score', 0)

            report_lines.extend([
                "",
                "📊 SECURITY OVERVIEW",
                "-" * 30,
                f"{risk_emoji} Security Score: {score:.1f}/100",
                f"🎯 Risk Level: {risk_level}",
            ])

            # Add category scores
            categories = overview.get('categories', {})
            if categories:
                report_lines.extend([
                    "",
                    "🔍 CATEGORY SCORES",
                    "-" * 30,
                ])
                for category, data in categories.items():
                    category_score = data.get('score', 0)
                    status = data.get('status', 'unknown')
                    status_emoji = {'good': '🟢', 'warning': '🟡', 'critical': '🔴', 'error': '❌'}.get(status, '⚪')

                    report_lines.append(f"{status_emoji} {category.replace('_', ' ').title()}: {category_score:.1f}/100")

            # Add security alerts
            alerts = overview.get('alerts', [])
            if alerts:
                report_lines.extend([
                    "",
                    "🚨 SECURITY ALERTS",
                    "-" * 30,
                ])
                for alert in alerts[:10]:  # Limit to top 10 alerts
                    report_lines.append(f"🔴 {alert}")

            # Add recommendations
            recommendations = overview.get('recommendations', [])
            if recommendations:
                report_lines.extend([
                    "",
                    "💡 SECURITY RECOMMENDATIONS",
                    "-" * 30,
                ])
                for rec in recommendations[:10]:  # Limit to top 10 recommendations
                    report_lines.append(f"🔹 {rec}")

            # Add specific security details
            auth_checks = categories.get('authentication', {}).get('checks', {})
            if 'ssh' in auth_checks:
                ssh_details = auth_checks['ssh'].get('details', {})
                if 'port' in ssh_details:
                    report_lines.extend([
                        "",
                        "🔐 SSH CONFIGURATION",
                        "-" * 30,
                        f"📡 SSH Port: {ssh_details['port']}",
                    ])

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating security report: {e}")
            return f"❌ Error generating security report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up Security Monitor...")
            self._cached_data.clear()
            self._security_events.clear()
            self.logger.info("✅ Security Monitor cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during Security Monitor cleanup: {e}")