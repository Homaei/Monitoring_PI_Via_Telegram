"""
Advanced Raspberry Pi Monitoring System - Configuration Settings

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module contains all configuration settings for the monitoring system including thresholds, paths, logging configuration, and system parameters.
License: For educational and personal use
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import logging

# Base paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
METRICS_DIR = DATA_DIR / "metrics"
BACKUP_DIR = DATA_DIR / "backups"

# Ensure all directories exist
for directory in [DATA_DIR, LOGS_DIR, REPORTS_DIR, METRICS_DIR, BACKUP_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Telegram Bot Configuration
BOT_TOKEN = "7205224892:AAGBoEw1RaYd-oEA26GUDcBD95hbA9Ayo30"
ADMIN_USER_ID = 798926067
AUTHORIZED_USERS = [798926067]  # Initial admin users

# Files
CONFIG_FILE = CONFIG_DIR / "config.json"
USERS_FILE = DATA_DIR / "users.json"
ACTIVITY_LOG = LOGS_DIR / "activity.log"
SYSTEM_LOG = LOGS_DIR / "system.log"
ERROR_LOG = LOGS_DIR / "errors.log"
METRICS_DB = METRICS_DIR / "metrics.db"

# System Monitoring Thresholds
@dataclass
class Thresholds:
    """System monitoring thresholds configuration"""

    cpu_temp: Dict[str, float] = field(default_factory=lambda: {
        "info": 40.0,
        "warning": 60.0,
        "critical": 75.0,
        "danger": 85.0
    })

    cpu_usage: Dict[str, float] = field(default_factory=lambda: {
        "info": 30.0,
        "warning": 70.0,
        "critical": 85.0,
        "danger": 95.0
    })

    memory_usage: Dict[str, float] = field(default_factory=lambda: {
        "info": 50.0,
        "warning": 75.0,
        "critical": 85.0,
        "danger": 95.0
    })

    disk_usage: Dict[str, float] = field(default_factory=lambda: {
        "info": 60.0,
        "warning": 75.0,
        "critical": 85.0,
        "danger": 95.0
    })

    swap_usage: Dict[str, float] = field(default_factory=lambda: {
        "info": 30.0,
        "warning": 50.0,
        "critical": 70.0,
        "danger": 90.0
    })

    network_latency: Dict[str, float] = field(default_factory=lambda: {
        "excellent": 20.0,
        "good": 50.0,
        "fair": 100.0,
        "poor": 200.0
    })

# Create global thresholds instance
THRESHOLDS = Thresholds()

# Monitoring Configuration
@dataclass
class MonitoringConfig:
    """Monitoring system configuration"""

    # Intervals (in seconds)
    quick_check_interval: int = 5
    normal_check_interval: int = 60
    detailed_check_interval: int = 300
    cleanup_interval: int = 86400  # 24 hours

    # Data retention (in days)
    metrics_retention: int = 30
    logs_retention: int = 90
    reports_retention: int = 365

    # Alert settings
    alert_cooldown: int = 300  # 5 minutes between same alerts
    max_alerts_per_hour: int = 20

    # Performance settings
    max_history_records: int = 1000
    batch_size: int = 100
    timeout: int = 30

    # Feature flags
    enable_auto_cleanup: bool = True
    enable_alerts: bool = True
    enable_metrics: bool = True
    enable_reports: bool = True
    enable_webhooks: bool = False

    # Security settings
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes
    session_timeout: int = 3600  # 1 hour

    # Network settings
    public_ip_check_interval: int = 3600  # 1 hour
    network_scan_enabled: bool = False
    ping_timeout: int = 2

    # System settings
    allow_reboot: bool = False
    allow_service_control: bool = True
    allow_process_kill: bool = False
    safe_mode: bool = True

# Create global config instance
MONITORING_CONFIG = MonitoringConfig()

# Permission Levels
class PermissionLevel:
    """User permission levels"""
    ADMIN = 4        # Full system control
    POWER_USER = 3   # Most operations except critical
    USER = 2         # Read and basic operations
    READ_ONLY = 1    # View only
    GUEST = 0        # Limited view

# Command Permissions
COMMAND_PERMISSIONS = {
    # View commands (Level 0+)
    "status": PermissionLevel.GUEST,
    "help": PermissionLevel.GUEST,
    "quick_status": PermissionLevel.GUEST,

    # Basic monitoring (Level 1+)
    "cpu": PermissionLevel.READ_ONLY,
    "memory": PermissionLevel.READ_ONLY,
    "disk": PermissionLevel.READ_ONLY,
    "temperature": PermissionLevel.READ_ONLY,
    "uptime": PermissionLevel.READ_ONLY,
    "ip": PermissionLevel.READ_ONLY,

    # Advanced monitoring (Level 2+)
    "network": PermissionLevel.USER,
    "processes": PermissionLevel.USER,
    "services": PermissionLevel.USER,
    "reports": PermissionLevel.USER,

    # System operations (Level 3+)
    "restart_service": PermissionLevel.POWER_USER,
    "kill_process": PermissionLevel.POWER_USER,
    "security": PermissionLevel.POWER_USER,

    # Admin only (Level 4)
    "users": PermissionLevel.ADMIN,
    "reboot": PermissionLevel.ADMIN,
    "shutdown": PermissionLevel.ADMIN,
    "config": PermissionLevel.ADMIN,
}

# Emoji Configuration
EMOJIS = {
    # Status indicators
    "green": "🟢",
    "yellow": "🟡",
    "orange": "🟠",
    "red": "🔴",
    "blue": "🔵",
    "purple": "🟣",
    "white": "⚪",
    "black": "⚫",

    # Status icons
    "success": "✅",
    "warning": "⚠️",
    "error": "❌",
    "critical": "🚨",
    "info": "ℹ️",
    "question": "❓",
    "exclamation": "❗",

    # System icons
    "system": "🖥️",
    "cpu": "⚙️",
    "memory": "📊",
    "disk": "💾",
    "network": "🌐",
    "wifi": "📶",
    "ethernet": "🔌",
    "temperature": "🌡️",
    "fire": "🔥",
    "cold": "❄️",
    "fan": "🌀",

    # Process/Service icons
    "process": "🔄",
    "services": "⚙️",
    "running": "▶️",
    "stopped": "⏹️",
    "paused": "⏸️",
    "restart": "🔄",

    # Security icons
    "security": "🛡️",
    "lock": "🔒",
    "unlock": "🔓",
    "key": "🔑",
    "alert": "🚨",

    # User/Admin icons
    "user": "👤",
    "users": "👥",
    "admin": "👑",
    "moderator": "🎖️",
    "guest": "👻",

    # Action icons
    "up": "⬆️",
    "down": "⬇️",
    "left": "⬅️",
    "right": "➡️",
    "refresh": "🔄",
    "save": "💾",
    "delete": "🗑️",
    "edit": "✏️",
    "settings": "⚙️",

    # Time icons
    "time": "⏰",
    "clock": "🕐",
    "calendar": "📅",
    "history": "📜",
    "uptime": "⏱️",

    # Report icons
    "report": "📋",
    "chart": "📈",
    "graph": "📊",
    "stats": "📊",

    # Communication
    "bell": "🔔",
    "mute": "🔇",
    "speaker": "🔊",
    "email": "📧",
    "message": "💬",

    # Power
    "power": "🔋",
    "plug": "🔌",
    "lightning": "⚡",
    "reboot": "🔄",
    "shutdown": "⏻",
}

# Logging Configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'json': {
            'format': '{"time": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout'
        },
        'system_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'detailed',
            'filename': str(SYSTEM_LOG),
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        },
        'error_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'ERROR',
            'formatter': 'detailed',
            'filename': str(ERROR_LOG),
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        }
    },
    'loggers': {
        '': {  # Root logger
            'handlers': ['console', 'system_file', 'error_file'],
            'level': 'INFO'
        },
        'telegram': {
            'handlers': ['console', 'system_file'],
            'level': 'WARNING',
            'propagate': False
        },
        'monitoring': {
            'handlers': ['console', 'system_file', 'error_file'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}

# Services to monitor
MONITORED_SERVICES = [
    "ssh",
    "nginx",
    "apache2",
    "mysql",
    "postgresql",
    "docker",
    "cron",
    "systemd-resolved",
    "NetworkManager",
]

# Critical system files to monitor
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/boot/config.txt",
    "/boot/cmdline.txt",
]

# Network test endpoints
NETWORK_TEST_ENDPOINTS = {
    "dns": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
    "http": ["http://www.google.com", "http://www.cloudflare.com"],
    "ping": ["google.com", "cloudflare.com", "1.1.1.1"],
}

# External service URLs
EXTERNAL_SERVICES = {
    "public_ip": [
        "https://api.ipify.org?format=json",
        "https://ipapi.co/json/",
        "https://api.myip.com",
    ],
    "speedtest": "https://www.speedtest.net/api/api.php",
}

def load_config():
    """Load configuration from JSON file"""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        else:
            # Save default config
            save_config(get_default_config())
            return get_default_config()
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        return get_default_config()

def save_config(config_data):
    """Save configuration to JSON file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Error saving config: {e}")
        return False

def get_default_config():
    """Get default configuration"""
    return {
        "bot_token": BOT_TOKEN,
        "admin_users": AUTHORIZED_USERS,
        "monitoring": {
            "enabled": True,
            "interval": MONITORING_CONFIG.normal_check_interval,
            "retention_days": MONITORING_CONFIG.metrics_retention,
        },
        "alerts": {
            "enabled": MONITORING_CONFIG.enable_alerts,
            "cooldown": MONITORING_CONFIG.alert_cooldown,
        },
        "features": {
            "auto_cleanup": MONITORING_CONFIG.enable_auto_cleanup,
            "metrics": MONITORING_CONFIG.enable_metrics,
            "reports": MONITORING_CONFIG.enable_reports,
        },
        "security": {
            "max_login_attempts": MONITORING_CONFIG.max_login_attempts,
            "lockout_duration": MONITORING_CONFIG.lockout_duration,
            "safe_mode": MONITORING_CONFIG.safe_mode,
        }
    }

# Initialize configuration
if __name__ == "__main__":
    # Test configuration loading
    config = load_config()
    print(f"Configuration loaded successfully: {json.dumps(config, indent=2)}")