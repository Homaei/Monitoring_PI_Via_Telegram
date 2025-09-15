"""
Helper Functions - Utility functions for the monitoring system

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: This module provides utility functions and helpers used across the monitoring system including safe execution wrappers, system commands, file operations, and formatting utilities.
License: For educational and personal use
"""

import os
import re
import json
import subprocess
import logging
import hashlib
import socket
import time
import shlex
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any, Union
from functools import wraps
import requests

logger = logging.getLogger('monitoring.utils')

# Constants
BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
TIME_UNITS = [
    ('year', 365 * 24 * 3600),
    ('month', 30 * 24 * 3600),
    ('week', 7 * 24 * 3600),
    ('day', 24 * 3600),
    ('hour', 3600),
    ('minute', 60),
    ('second', 1)
]

def safe_execute(func):
    """Decorator for safe function execution with error handling"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}")
            return None
    return wrapper

def run_command(command: Union[str, List[str]],
                shell: bool = False,
                timeout: int = 30,
                check: bool = False) -> Tuple[str, str, int]:
    """
    Execute system command safely with timeout

    Args:
        command: Command to execute (string or list)
        shell: Whether to use shell execution
        timeout: Command timeout in seconds
        check: Whether to raise exception on non-zero return code

    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    try:
        # Security: Avoid shell=True when possible
        if isinstance(command, str) and not shell:
            command = shlex.split(command)

        # Validate command to prevent injection
        if shell:
            logger.warning(f"Shell execution requested for: {command}")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=shell,
            timeout=timeout,
            check=check
        )

        return result.stdout.strip(), result.stderr.strip(), result.returncode

    except subprocess.TimeoutExpired:
        logger.error(f"Command timeout after {timeout}s: {command}")
        return "", f"Command timeout after {timeout} seconds", 124

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with code {e.returncode}: {command}")
        return e.stdout or "", e.stderr or str(e), e.returncode

    except Exception as e:
        logger.error(f"Command execution error: {str(e)}")
        return "", str(e), 1

def format_bytes(bytes_value: Union[int, float], precision: int = 2) -> str:
    """
    Convert bytes to human-readable format

    Args:
        bytes_value: Size in bytes
        precision: Decimal precision

    Returns:
        Formatted string (e.g., "1.23 GB")
    """
    if bytes_value < 0:
        return "Invalid"

    if bytes_value == 0:
        return "0 B"

    for unit in BYTE_UNITS[:-1]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.{precision}f} {unit}"
        bytes_value /= 1024.0

    return f"{bytes_value:.{precision}f} {BYTE_UNITS[-1]}"

def format_time(seconds: Union[int, float], detailed: bool = False) -> str:
    """
    Convert seconds to human-readable time format

    Args:
        seconds: Time in seconds
        detailed: Whether to include all units

    Returns:
        Formatted time string
    """
    if seconds < 0:
        return "Invalid"

    if seconds == 0:
        return "0 seconds"

    parts = []
    remaining = int(seconds)

    for unit_name, unit_seconds in TIME_UNITS:
        if remaining >= unit_seconds:
            value = remaining // unit_seconds
            remaining %= unit_seconds

            if value == 1:
                parts.append(f"{value} {unit_name}")
            else:
                parts.append(f"{value} {unit_name}s")

            if not detailed and len(parts) >= 2:
                break

    return " ".join(parts) if parts else "Less than a second"

def format_percentage(value: float, precision: int = 1) -> str:
    """Format percentage value with emoji indicator"""
    return f"{value:.{precision}f}%"

def get_emoji_by_value(value: float,
                       thresholds: Dict[str, float],
                       reverse: bool = False) -> str:
    """
    Get emoji indicator based on value and thresholds

    Args:
        value: Current value
        thresholds: Dictionary with threshold levels
        reverse: Whether lower values are better

    Returns:
        Emoji string
    """
    from config.settings import EMOJIS

    if reverse:
        if value <= thresholds.get('info', 0):
            return EMOJIS['green']
        elif value <= thresholds.get('warning', 50):
            return EMOJIS['yellow']
        elif value <= thresholds.get('critical', 75):
            return EMOJIS['orange']
        else:
            return EMOJIS['red']
    else:
        if value >= thresholds.get('danger', 95):
            return EMOJIS['red']
        elif value >= thresholds.get('critical', 85):
            return EMOJIS['orange']
        elif value >= thresholds.get('warning', 70):
            return EMOJIS['yellow']
        else:
            return EMOJIS['green']

def create_progress_bar(percentage: float,
                       length: int = 10,
                       filled_char: str = "█",
                       empty_char: str = "░") -> str:
    """
    Create text-based progress bar

    Args:
        percentage: Progress percentage (0-100)
        length: Bar length in characters
        filled_char: Character for filled portion
        empty_char: Character for empty portion

    Returns:
        Progress bar string
    """
    percentage = max(0, min(100, percentage))
    filled = int(length * percentage / 100)
    empty = length - filled

    bar = filled_char * filled + empty_char * empty
    return f"[{bar}] {percentage:.1f}%"

def validate_input(value: str,
                  input_type: str = "string",
                  max_length: int = 100) -> bool:
    """
    Validate user input for security

    Args:
        value: Input value to validate
        input_type: Type of input (string, number, alphanum, service_name)
        max_length: Maximum allowed length

    Returns:
        True if valid, False otherwise
    """
    if not value or len(value) > max_length:
        return False

    patterns = {
        "string": r"^[\w\s\-\.]+$",
        "number": r"^\d+$",
        "alphanum": r"^[a-zA-Z0-9]+$",
        "service_name": r"^[a-zA-Z0-9\-\_\.]+$",
        "filename": r"^[a-zA-Z0-9\-\_\.\/]+$",
        "ip_address": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        "username": r"^[a-zA-Z0-9\_\-]+$"
    }

    pattern = patterns.get(input_type, patterns["string"])
    return bool(re.match(pattern, value))

def sanitize_input(value: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    # Remove potential dangerous characters
    dangerous_chars = ['`', '$', '&', '|', ';', '>', '<', '\\', '"', "'", '\n', '\r']

    sanitized = value
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')

    return sanitized.strip()

def calculate_hash(data: Union[str, bytes], algorithm: str = "sha256") -> str:
    """
    Calculate hash of data

    Args:
        data: Data to hash
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        Hex digest string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    hash_funcs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256
    }

    hash_func = hash_funcs.get(algorithm, hashlib.sha256)
    return hash_func(data).hexdigest()

def check_network_connectivity(timeout: int = 2) -> bool:
    """Check if network is available"""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=timeout)
        return True
    except (socket.error, socket.timeout):
        return False

def get_local_ip() -> str:
    """Get local IP address"""
    try:
        # Create a socket and connect to an external server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_hostname() -> str:
    """Get system hostname"""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"

def parse_size(size_str: str) -> int:
    """
    Parse human-readable size to bytes

    Args:
        size_str: Size string (e.g., "10GB", "512MB")

    Returns:
        Size in bytes
    """
    size_str = size_str.strip().upper()

    units = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024**2,
        'MB': 1024**2,
        'G': 1024**3,
        'GB': 1024**3,
        'T': 1024**4,
        'TB': 1024**4
    }

    # Extract number and unit
    match = re.match(r'^([\d.]+)\s*([A-Z]+)?$', size_str)
    if not match:
        raise ValueError(f"Invalid size format: {size_str}")

    number = float(match.group(1))
    unit = match.group(2) or 'B'

    if unit not in units:
        raise ValueError(f"Unknown unit: {unit}")

    return int(number * units[unit])

def rate_limit(calls: int = 1, period: int = 1):
    """
    Rate limiting decorator

    Args:
        calls: Number of allowed calls
        period: Time period in seconds
    """
    min_interval = period / calls
    last_called = [0.0]

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            wait_time = min_interval - elapsed

            if wait_time > 0:
                time.sleep(wait_time)

            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result

        return wrapper
    return decorator

def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """
    Retry decorator with exponential backoff

    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries
        backoff: Backoff multiplier
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay

            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        logger.error(f"Failed after {max_attempts} attempts: {str(e)}")
                        raise

                    logger.warning(f"Attempt {attempt} failed, retrying in {current_delay}s: {str(e)}")
                    time.sleep(current_delay)
                    current_delay *= backoff

            return None

        return wrapper
    return decorator

def load_json_file(filepath: Path, default: Any = None) -> Any:
    """Load JSON file with error handling"""
    try:
        if filepath.exists():
            with open(filepath, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON from {filepath}: {str(e)}")

    return default if default is not None else {}

def save_json_file(filepath: Path, data: Any) -> bool:
    """Save data to JSON file with error handling"""
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return True
    except Exception as e:
        logger.error(f"Error saving JSON to {filepath}: {str(e)}")
        return False

def get_system_uptime() -> float:
    """Get system uptime in seconds"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            return uptime_seconds
    except Exception as e:
        logger.error(f"Error getting uptime: {str(e)}")
        return 0.0

def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate string to maximum length"""
    if len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix

def parse_datetime(date_str: str) -> Optional[datetime]:
    """Parse datetime string with multiple format support"""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None

def get_file_age(filepath: Path) -> Optional[timedelta]:
    """Get age of file"""
    try:
        if filepath.exists():
            mtime = filepath.stat().st_mtime
            age = datetime.now() - datetime.fromtimestamp(mtime)
            return age
    except Exception as e:
        logger.error(f"Error getting file age: {str(e)}")

    return None

def cleanup_old_files(directory: Path, max_age_days: int = 30, pattern: str = "*") -> int:
    """
    Clean up old files from directory

    Args:
        directory: Directory to clean
        max_age_days: Maximum file age in days
        pattern: File pattern to match

    Returns:
        Number of files deleted
    """
    deleted_count = 0
    max_age = timedelta(days=max_age_days)

    try:
        for filepath in directory.glob(pattern):
            if filepath.is_file():
                age = get_file_age(filepath)
                if age and age > max_age:
                    filepath.unlink()
                    deleted_count += 1
                    logger.info(f"Deleted old file: {filepath}")

    except Exception as e:
        logger.error(f"Error cleaning up files: {str(e)}")

    return deleted_count

@safe_execute
def fetch_url(url: str, timeout: int = 10) -> Optional[Dict]:
    """Fetch URL and return JSON response"""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching URL {url}: {str(e)}")
        return None

def is_raspberry_pi() -> bool:
    """Check if running on Raspberry Pi"""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read()
            return 'Raspberry Pi' in cpuinfo or 'BCM' in cpuinfo
    except Exception:
        return False

def get_cpu_temperature() -> Optional[float]:
    """Get CPU temperature (Raspberry Pi specific)"""
    temp_paths = [
        '/sys/class/thermal/thermal_zone0/temp',
        '/sys/class/hwmon/hwmon0/temp1_input'
    ]

    for path in temp_paths:
        try:
            with open(path, 'r') as f:
                temp = float(f.read().strip()) / 1000.0
                return temp
        except Exception:
            continue

    # Try vcgencmd for Raspberry Pi
    if is_raspberry_pi():
        stdout, _, _ = run_command("vcgencmd measure_temp")
        if stdout:
            match = re.search(r'temp=([\d.]+)', stdout)
            if match:
                return float(match.group(1))

    return None