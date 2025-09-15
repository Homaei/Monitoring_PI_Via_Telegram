"""
User Manager Module - User management and permissions

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides comprehensive user management capabilities for the monitoring system including user authentication, permissions management, and session handling.
License: For educational and personal use
"""

import asyncio
import json
import logging
import hashlib
import time
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from config.settings import USERS_FILE, AUTHORIZED_USERS, ADMIN_USER_ID
from utils.helpers import safe_execute, run_command

logger = logging.getLogger('monitoring.user_manager')


class UserManager:
    """User management and permissions class"""

    def __init__(self):
        """Initialize the user manager"""
        self.logger = logger
        self._users_file = Path(USERS_FILE)
        self._users_data = {}
        self._sessions = {}
        self._failed_attempts = {}
        self._max_failed_attempts = 5
        self._lockout_duration = 300  # 5 minutes

    async def initialize(self) -> bool:
        """Initialize the user manager"""
        try:
            self.logger.info("🚀 Initializing User Manager...")

            # Ensure users file exists
            self._users_file.parent.mkdir(parents=True, exist_ok=True)

            # Load existing users or create initial admin user
            await self._load_users()

            # Initialize admin user if not exists
            if not self._users_data:
                await self._create_initial_admin()

            # Clean up old sessions
            await self._cleanup_sessions()

            self.logger.info(f"✅ User Manager initialized - {len(self._users_data)} users loaded")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize User Manager: {e}")
            return False

    @safe_execute
    async def _load_users(self):
        """Load users from storage file"""
        try:
            if self._users_file.exists():
                with open(self._users_file, 'r') as f:
                    data = json.load(f)
                    self._users_data = data.get('users', {})
                    self.logger.info(f"Loaded {len(self._users_data)} users from storage")
            else:
                self._users_data = {}
                self.logger.info("No existing users file found")

        except Exception as e:
            self.logger.error(f"Error loading users: {e}")
            self._users_data = {}

    @safe_execute
    async def _save_users(self):
        """Save users to storage file"""
        try:
            data = {
                'users': self._users_data,
                'last_updated': datetime.now().isoformat(),
                'version': '1.0'
            }

            with open(self._users_file, 'w') as f:
                json.dump(data, f, indent=2)

            self.logger.debug("Users data saved to storage")

        except Exception as e:
            self.logger.error(f"Error saving users: {e}")

    @safe_execute
    async def _create_initial_admin(self):
        """Create initial admin user from settings"""
        try:
            admin_user = {
                'user_id': str(ADMIN_USER_ID),
                'username': 'admin',
                'role': 'administrator',
                'permissions': ['all'],
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'is_active': True,
                'login_count': 0,
                'telegram_id': ADMIN_USER_ID
            }

            self._users_data[str(ADMIN_USER_ID)] = admin_user
            await self._save_users()

            self.logger.info(f"Created initial admin user with ID: {ADMIN_USER_ID}")

        except Exception as e:
            self.logger.error(f"Error creating initial admin user: {e}")

    @safe_execute
    async def add_user(self, telegram_id: int, username: str, role: str = 'user',
                      permissions: List[str] = None) -> Dict[str, Any]:
        """Add a new user to the system"""
        try:
            if permissions is None:
                permissions = ['read'] if role == 'user' else ['read', 'write']

            user_id = str(telegram_id)

            if user_id in self._users_data:
                return {
                    'success': False,
                    'message': f"User with ID {telegram_id} already exists",
                    'user_id': user_id
                }

            # Validate role
            valid_roles = ['user', 'moderator', 'administrator']
            if role not in valid_roles:
                return {
                    'success': False,
                    'message': f"Invalid role. Must be one of: {', '.join(valid_roles)}",
                    'user_id': user_id
                }

            # Create new user
            new_user = {
                'user_id': user_id,
                'username': username,
                'role': role,
                'permissions': permissions,
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'is_active': True,
                'login_count': 0,
                'telegram_id': telegram_id,
                'added_by': 'system'  # You might want to track who added the user
            }

            self._users_data[user_id] = new_user
            await self._save_users()

            self.logger.info(f"Added new user: {username} (ID: {telegram_id}) with role: {role}")

            return {
                'success': True,
                'message': f"User {username} added successfully",
                'user_id': user_id,
                'user': new_user
            }

        except Exception as e:
            self.logger.error(f"Error adding user: {e}")
            return {
                'success': False,
                'message': f"Error adding user: {str(e)}",
                'user_id': str(telegram_id)
            }

    @safe_execute
    async def remove_user(self, user_id: str, removed_by: str = None) -> Dict[str, Any]:
        """Remove a user from the system"""
        try:
            if user_id not in self._users_data:
                return {
                    'success': False,
                    'message': f"User with ID {user_id} not found"
                }

            # Don't allow removal of the admin user
            if user_id == str(ADMIN_USER_ID):
                return {
                    'success': False,
                    'message': "Cannot remove the admin user"
                }

            removed_user = self._users_data.pop(user_id)
            await self._save_users()

            # Clean up any sessions for this user
            if user_id in self._sessions:
                del self._sessions[user_id]

            self.logger.info(f"Removed user: {removed_user.get('username', 'Unknown')} (ID: {user_id})")

            return {
                'success': True,
                'message': f"User {removed_user.get('username', user_id)} removed successfully",
                'removed_user': removed_user
            }

        except Exception as e:
            self.logger.error(f"Error removing user: {e}")
            return {
                'success': False,
                'message': f"Error removing user: {str(e)}"
            }

    @safe_execute
    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update user information"""
        try:
            if user_id not in self._users_data:
                return {
                    'success': False,
                    'message': f"User with ID {user_id} not found"
                }

            user = self._users_data[user_id]

            # Fields that can be updated
            updatable_fields = ['username', 'role', 'permissions', 'is_active']

            updated_fields = []
            for field, value in updates.items():
                if field in updatable_fields:
                    old_value = user.get(field)
                    user[field] = value
                    updated_fields.append(f"{field}: {old_value} -> {value}")

            # Update timestamp
            user['updated_at'] = datetime.now().isoformat()

            await self._save_users()

            self.logger.info(f"Updated user {user.get('username', user_id)}: {', '.join(updated_fields)}")

            return {
                'success': True,
                'message': f"User updated successfully",
                'updated_fields': updated_fields,
                'user': user
            }

        except Exception as e:
            self.logger.error(f"Error updating user: {e}")
            return {
                'success': False,
                'message': f"Error updating user: {str(e)}"
            }

    @safe_execute
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information by ID"""
        try:
            return self._users_data.get(user_id)

        except Exception as e:
            self.logger.error(f"Error getting user {user_id}: {e}")
            return None

    @safe_execute
    async def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users"""
        try:
            return list(self._users_data.values())

        except Exception as e:
            self.logger.error(f"Error getting all users: {e}")
            return []

    @safe_execute
    async def authenticate_user(self, telegram_id: int) -> Dict[str, Any]:
        """Authenticate a user and create session"""
        try:
            user_id = str(telegram_id)

            # Check if user is locked out
            if await self._is_user_locked_out(user_id):
                return {
                    'success': False,
                    'message': 'Account temporarily locked due to failed attempts',
                    'locked_until': self._failed_attempts[user_id]['locked_until']
                }

            # Check if user exists and is active
            user = self._users_data.get(user_id)
            if not user:
                await self._record_failed_attempt(user_id)
                return {
                    'success': False,
                    'message': 'User not found or not authorized'
                }

            if not user.get('is_active', True):
                return {
                    'success': False,
                    'message': 'User account is deactivated'
                }

            # Create session
            session_token = await self._create_session(user_id)

            # Update user login info
            user['last_login'] = datetime.now().isoformat()
            user['login_count'] = user.get('login_count', 0) + 1
            await self._save_users()

            # Clear failed attempts
            if user_id in self._failed_attempts:
                del self._failed_attempts[user_id]

            self.logger.info(f"User authenticated: {user.get('username', user_id)} (ID: {telegram_id})")

            return {
                'success': True,
                'message': 'Authentication successful',
                'user': user,
                'session_token': session_token
            }

        except Exception as e:
            self.logger.error(f"Error authenticating user {telegram_id}: {e}")
            return {
                'success': False,
                'message': 'Authentication failed'
            }

    @safe_execute
    async def _create_session(self, user_id: str) -> str:
        """Create a user session"""
        try:
            session_token = secrets.token_urlsafe(32)
            session_data = {
                'user_id': user_id,
                'token': session_token,
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(hours=24)).isoformat(),
                'last_activity': datetime.now().isoformat()
            }

            self._sessions[user_id] = session_data
            return session_token

        except Exception as e:
            self.logger.error(f"Error creating session for user {user_id}: {e}")
            return None

    @safe_execute
    async def validate_session(self, user_id: str, session_token: str) -> bool:
        """Validate a user session"""
        try:
            if user_id not in self._sessions:
                return False

            session = self._sessions[user_id]

            # Check if token matches
            if session.get('token') != session_token:
                return False

            # Check if session has expired
            expires_at = datetime.fromisoformat(session['expires_at'])
            if datetime.now() > expires_at:
                del self._sessions[user_id]
                return False

            # Update last activity
            session['last_activity'] = datetime.now().isoformat()
            return True

        except Exception as e:
            self.logger.error(f"Error validating session for user {user_id}: {e}")
            return False

    @safe_execute
    async def logout_user(self, user_id: str) -> Dict[str, Any]:
        """Logout a user and invalidate session"""
        try:
            if user_id in self._sessions:
                del self._sessions[user_id]
                self.logger.info(f"User logged out: {user_id}")
                return {
                    'success': True,
                    'message': 'Logged out successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'No active session found'
                }

        except Exception as e:
            self.logger.error(f"Error logging out user {user_id}: {e}")
            return {
                'success': False,
                'message': 'Error during logout'
            }

    @safe_execute
    async def check_permission(self, user_id: str, required_permission: str) -> bool:
        """Check if user has required permission"""
        try:
            user = self._users_data.get(user_id)
            if not user or not user.get('is_active', True):
                return False

            user_permissions = user.get('permissions', [])

            # Administrators have all permissions
            if user.get('role') == 'administrator' or 'all' in user_permissions:
                return True

            # Check specific permission
            return required_permission in user_permissions

        except Exception as e:
            self.logger.error(f"Error checking permission for user {user_id}: {e}")
            return False

    @safe_execute
    async def _record_failed_attempt(self, user_id: str):
        """Record a failed authentication attempt"""
        try:
            now = datetime.now()

            if user_id not in self._failed_attempts:
                self._failed_attempts[user_id] = {
                    'count': 0,
                    'first_attempt': now.isoformat(),
                    'last_attempt': now.isoformat(),
                    'locked_until': None
                }

            attempt_data = self._failed_attempts[user_id]
            attempt_data['count'] += 1
            attempt_data['last_attempt'] = now.isoformat()

            # Lock account if too many failed attempts
            if attempt_data['count'] >= self._max_failed_attempts:
                attempt_data['locked_until'] = (now + timedelta(seconds=self._lockout_duration)).isoformat()
                self.logger.warning(f"User {user_id} locked out after {attempt_data['count']} failed attempts")

        except Exception as e:
            self.logger.error(f"Error recording failed attempt for user {user_id}: {e}")

    @safe_execute
    async def _is_user_locked_out(self, user_id: str) -> bool:
        """Check if user is currently locked out"""
        try:
            if user_id not in self._failed_attempts:
                return False

            attempt_data = self._failed_attempts[user_id]
            locked_until = attempt_data.get('locked_until')

            if not locked_until:
                return False

            locked_until_dt = datetime.fromisoformat(locked_until)
            if datetime.now() > locked_until_dt:
                # Lockout period expired, clear the record
                del self._failed_attempts[user_id]
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error checking lockout status for user {user_id}: {e}")
            return False

    @safe_execute
    async def _cleanup_sessions(self):
        """Clean up expired sessions"""
        try:
            now = datetime.now()
            expired_sessions = []

            for user_id, session in self._sessions.items():
                try:
                    expires_at = datetime.fromisoformat(session['expires_at'])
                    if now > expires_at:
                        expired_sessions.append(user_id)
                except:
                    expired_sessions.append(user_id)

            for user_id in expired_sessions:
                del self._sessions[user_id]

            if expired_sessions:
                self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

        except Exception as e:
            self.logger.error(f"Error cleaning up sessions: {e}")

    @safe_execute
    async def get_user_statistics(self) -> Dict[str, Any]:
        """Get user statistics"""
        try:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'total_users': len(self._users_data),
                'active_users': 0,
                'inactive_users': 0,
                'roles': {},
                'active_sessions': len(self._sessions),
                'locked_users': len(self._failed_attempts),
                'recent_logins': []
            }

            # Count by status and role
            for user in self._users_data.values():
                if user.get('is_active', True):
                    stats['active_users'] += 1
                else:
                    stats['inactive_users'] += 1

                role = user.get('role', 'unknown')
                stats['roles'][role] = stats['roles'].get(role, 0) + 1

                # Get recent logins (last 24 hours)
                last_login = user.get('last_login')
                if last_login:
                    try:
                        login_time = datetime.fromisoformat(last_login)
                        if (datetime.now() - login_time).total_seconds() < 86400:  # 24 hours
                            stats['recent_logins'].append({
                                'username': user.get('username', 'Unknown'),
                                'user_id': user.get('user_id'),
                                'login_time': last_login
                            })
                    except:
                        pass

            # Sort recent logins by time
            stats['recent_logins'].sort(key=lambda x: x['login_time'], reverse=True)

            return stats

        except Exception as e:
            self.logger.error(f"Error getting user statistics: {e}")
            return {}

    @safe_execute
    async def generate_report(self) -> str:
        """Generate a user management report"""
        try:
            stats = await self.get_user_statistics()
            all_users = await self.get_all_users()

            report_lines = [
                "👥 USER MANAGEMENT REPORT",
                "=" * 50,
                f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            # Add user statistics
            report_lines.extend([
                "",
                "📊 USER STATISTICS",
                "-" * 30,
                f"📈 Total Users: {stats.get('total_users', 0)}",
                f"✅ Active Users: {stats.get('active_users', 0)}",
                f"❌ Inactive Users: {stats.get('inactive_users', 0)}",
                f"🔓 Active Sessions: {stats.get('active_sessions', 0)}",
                f"🔒 Locked Users: {stats.get('locked_users', 0)}",
            ])

            # Add role distribution
            roles = stats.get('roles', {})
            if roles:
                report_lines.extend([
                    "",
                    "👤 USER ROLES",
                    "-" * 30,
                ])
                for role, count in roles.items():
                    role_emoji = {'administrator': '👑', 'moderator': '🛡️', 'user': '👤'}.get(role, '❓')
                    report_lines.append(f"{role_emoji} {role.title()}: {count}")

            # Add recent logins
            recent_logins = stats.get('recent_logins', [])
            if recent_logins:
                report_lines.extend([
                    "",
                    "🕐 RECENT LOGINS (24h)",
                    "-" * 30,
                ])
                for login in recent_logins[:10]:  # Show last 10
                    try:
                        login_time = datetime.fromisoformat(login['login_time'])
                        formatted_time = login_time.strftime('%H:%M:%S')
                        report_lines.append(f"🔹 {login['username']} at {formatted_time}")
                    except:
                        report_lines.append(f"🔹 {login['username']} (time unknown)")

            # Add user list
            if all_users:
                report_lines.extend([
                    "",
                    "📋 USER LIST",
                    "-" * 30,
                ])
                for user in all_users:
                    username = user.get('username', 'Unknown')
                    role = user.get('role', 'user')
                    is_active = user.get('is_active', True)
                    login_count = user.get('login_count', 0)

                    status_emoji = "✅" if is_active else "❌"
                    role_emoji = {'administrator': '👑', 'moderator': '🛡️', 'user': '👤'}.get(role, '❓')

                    report_lines.append(
                        f"{status_emoji} {role_emoji} {username} "
                        f"({login_count} logins)"
                    )

            # Add security information
            if self._failed_attempts:
                report_lines.extend([
                    "",
                    "🚨 SECURITY ALERTS",
                    "-" * 30,
                ])
                for user_id, attempt_data in self._failed_attempts.items():
                    count = attempt_data.get('count', 0)
                    is_locked = attempt_data.get('locked_until') is not None
                    status = "🔒 LOCKED" if is_locked else "⚠️ ATTEMPTS"

                    user = self._users_data.get(user_id, {})
                    username = user.get('username', f'ID:{user_id}')

                    report_lines.append(f"{status} {username}: {count} failed attempts")

            report_lines.extend([
                "",
                "=" * 50,
                "📊 Advanced Raspberry Pi Monitoring System"
            ])

            return "\n".join(report_lines)

        except Exception as e:
            self.logger.error(f"Error generating user report: {e}")
            return f"❌ Error generating user report: {e}"

    async def cleanup(self):
        """Cleanup resources"""
        try:
            self.logger.info("🧹 Cleaning up User Manager...")

            # Save any pending changes
            await self._save_users()

            # Clean up sessions
            await self._cleanup_sessions()

            self.logger.info("✅ User Manager cleanup completed")
        except Exception as e:
            self.logger.error(f"❌ Error during User Manager cleanup: {e}")