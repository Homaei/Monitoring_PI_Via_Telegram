#!/usr/bin/env python3
"""
Advanced Raspberry Pi Monitoring System - Main Bot
Enhanced version with improved error handling, modular design, and comprehensive monitoring

Author: Mohammadhossein Homaei
GitHub: github.com/homaei
Email: homaei@ieee.org
Description: Production-ready Raspberry Pi monitoring system with Telegram bot interface
License: For educational and personal use
"""

import asyncio
import logging
import logging.config
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)
from telegram.constants import ParseMode

# Import configuration and utilities
from config.settings import (
    BOT_TOKEN,
    ADMIN_USER_ID,
    LOGGING_CONFIG,
    EMOJIS,
    COMMAND_PERMISSIONS,
    PermissionLevel,
    MONITORING_CONFIG,
    DATA_DIR
)
from utils.helpers import (
    safe_execute,
    format_time,
    validate_input,
    sanitize_input,
    get_hostname
)

# Import monitoring modules
from modules.system_monitor import SystemMonitor
from modules.cpu_monitor import CPUMonitor
from modules.memory_monitor import MemoryMonitor
from modules.disk_monitor import DiskMonitor
from modules.network_monitor import NetworkMonitor
from modules.process_monitor import ProcessMonitor
from modules.service_monitor import ServiceMonitor
from modules.temperature_monitor import TemperatureMonitor
from modules.security_monitor import SecurityMonitor
from modules.user_manager import UserManager
from modules.alert_manager import AlertManager
from modules.report_manager import ReportManager

# Configure logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger('monitoring.main')

class RaspberryPiMonitorBot:
    """Advanced Raspberry Pi Monitoring Bot with comprehensive error handling"""

    def __init__(self):
        """Initialize the monitoring bot"""
        logger.info("Initializing Raspberry Pi Monitor Bot...")

        # Initialize monitoring modules
        self.system_monitor = SystemMonitor()
        self.cpu_monitor = CPUMonitor()
        self.memory_monitor = MemoryMonitor()
        self.disk_monitor = DiskMonitor()
        self.network_monitor = NetworkMonitor()
        self.process_monitor = ProcessMonitor()
        self.service_monitor = ServiceMonitor()
        self.temperature_monitor = TemperatureMonitor()
        self.security_monitor = SecurityMonitor()
        self.user_manager = UserManager()
        self.alert_manager = AlertManager()
        self.report_manager = ReportManager()

        # Initialize bot application
        self.application = None
        self.monitoring_task = None
        self.cleanup_task = None
        self.is_running = False

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.is_running = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()

    async def initialize(self):
        """Initialize bot and all components"""
        try:
            # Create bot application
            self.application = Application.builder().token(BOT_TOKEN).build()

            # Register handlers
            self._register_handlers()

            # Initialize modules
            await self._initialize_modules()

            # Start background tasks
            self.is_running = True
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

            logger.info("Bot initialization completed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize bot: {str(e)}")
            return False

    async def _initialize_modules(self):
        """Initialize all monitoring modules"""
        modules = [
            self.system_monitor,
            self.cpu_monitor,
            self.memory_monitor,
            self.disk_monitor,
            self.network_monitor,
            self.process_monitor,
            self.service_monitor,
            self.temperature_monitor,
            self.security_monitor,
            self.user_manager,
            self.alert_manager,
            self.report_manager
        ]

        for module in modules:
            try:
                if hasattr(module, 'initialize'):
                    await module.initialize()
                logger.debug(f"Initialized {module.__class__.__name__}")
            except Exception as e:
                logger.error(f"Failed to initialize {module.__class__.__name__}: {str(e)}")

    def _register_handlers(self):
        """Register all command and message handlers"""

        # Command handlers
        commands = [
            ("start", self.cmd_start),
            ("help", self.cmd_help),
            ("status", self.cmd_status),
            ("cpu", self.cmd_cpu),
            ("memory", self.cmd_memory),
            ("disk", self.cmd_disk),
            ("network", self.cmd_network),
            ("processes", self.cmd_processes),
            ("services", self.cmd_services),
            ("temperature", self.cmd_temperature),
            ("security", self.cmd_security),
            ("users", self.cmd_users),
            ("alerts", self.cmd_alerts),
            ("reports", self.cmd_reports),
            ("uptime", self.cmd_uptime),
            ("ip", self.cmd_ip),
            ("menu", self.cmd_menu),
            ("settings", self.cmd_settings),
            ("restart", self.cmd_restart_service),
            ("kill", self.cmd_kill_process),
            ("reboot", self.cmd_reboot),
            ("shutdown", self.cmd_shutdown),
        ]

        for command, handler in commands:
            self.application.add_handler(CommandHandler(command, handler))

        # Keyboard button handlers
        keyboard_handlers = [
            (r"^📊 Status$", self.cmd_status),
            (r"^⚙️ CPU$", self.cmd_cpu),
            (r"^📈 Memory$", self.cmd_memory),
            (r"^💾 Disk$", self.cmd_disk),
            (r"^🌐 Network$", self.cmd_network),
            (r"^🔄 Processes$", self.cmd_processes),
            (r"^⚙️ Services$", self.cmd_services),
            (r"^🌡️ Temperature$", self.cmd_temperature),
            (r"^🛡️ Security$", self.cmd_security),
            (r"^👥 Users$", self.cmd_users),
            (r"^🔔 Alerts$", self.cmd_alerts),
            (r"^📋 Reports$", self.cmd_reports),
            (r"^❓ Help$", self.cmd_help),
            (r"^⚙️ Settings$", self.cmd_settings),
            (r"^❌ Hide Menu$", self.cmd_hide_menu),
        ]

        for pattern, handler in keyboard_handlers:
            self.application.add_handler(
                MessageHandler(filters.Regex(pattern), handler)
            )

        # Callback query handler for inline keyboards
        self.application.add_handler(CallbackQueryHandler(self.handle_callback))

        # Error handler
        self.application.add_error_handler(self.error_handler)

    def create_main_keyboard(self):
        """Create main menu keyboard"""
        keyboard = [
            [KeyboardButton("📊 Status"), KeyboardButton("⚙️ CPU")],
            [KeyboardButton("📈 Memory"), KeyboardButton("💾 Disk")],
            [KeyboardButton("🌐 Network"), KeyboardButton("🔄 Processes")],
            [KeyboardButton("⚙️ Services"), KeyboardButton("🌡️ Temperature")],
            [KeyboardButton("🛡️ Security"), KeyboardButton("👥 Users")],
            [KeyboardButton("🔔 Alerts"), KeyboardButton("📋 Reports")],
            [KeyboardButton("⚙️ Settings"), KeyboardButton("❓ Help")],
            [KeyboardButton("❌ Hide Menu")]
        ]

        return ReplyKeyboardMarkup(
            keyboard,
            resize_keyboard=True,
            persistent=True
        )

    async def check_permission(self, user_id: int, command: str) -> bool:
        """Check if user has permission for command"""
        try:
            # Get user permission level
            user_level = await self.user_manager.get_user_permission(user_id)

            # Get required permission for command
            required_level = COMMAND_PERMISSIONS.get(command, PermissionLevel.USER)

            # Admin bypass
            if user_id == ADMIN_USER_ID:
                return True

            # Check permission
            return user_level >= required_level

        except Exception as e:
            logger.error(f"Error checking permission: {str(e)}")
            return False

    async def log_user_action(self, user_id: int, action: str, details: str = ""):
        """Log user action for auditing"""
        try:
            await self.user_manager.log_activity(user_id, action, details)
        except Exception as e:
            logger.error(f"Error logging user action: {str(e)}")

    # Command Handlers

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user = update.effective_user
        user_id = user.id

        # Log action
        await self.log_user_action(user_id, "start", "Bot started")

        # Register user if new
        await self.user_manager.register_user(user_id, user.username or user.first_name)

        hostname = get_hostname()
        welcome_message = f"""
{EMOJIS['system']} **Raspberry Pi Monitor Bot**
{EMOJIS['info']} Host: `{hostname}`

Welcome {user.first_name}! 👋

This bot provides comprehensive monitoring of your Raspberry Pi system. Use the menu below to navigate or type /help for more information.

Your User ID: `{user_id}`
Access Level: {await self.user_manager.get_user_level_name(user_id)}
        """

        await update.message.reply_text(
            welcome_message,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=self.create_main_keyboard()
        )

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        user_id = update.effective_user.id
        user_level = await self.user_manager.get_user_permission(user_id)

        help_text = f"""
{EMOJIS['help']} **Help - Available Commands**

**📊 Monitoring Commands:**
/status - System overview
/cpu - CPU usage and stats
/memory - Memory usage
/disk - Disk usage
/network - Network stats
/processes - Running processes
/services - System services
/temperature - Temperature sensors
/uptime - System uptime
/ip - IP addresses

**🛡️ Security & Management:**
/security - Security status
/users - User management
/alerts - Alert settings
/reports - System reports
        """

        if user_level >= PermissionLevel.POWER_USER:
            help_text += """

**⚡ Power User Commands:**
/restart <service> - Restart service
/kill <pid> - Kill process
            """

        if user_level >= PermissionLevel.ADMIN:
            help_text += """

**👑 Admin Commands:**
/settings - Bot settings
/reboot - System reboot
/shutdown - System shutdown
            """

        help_text += """

**📱 Navigation:**
/menu - Show keyboard menu
/help - This help message

Use the keyboard buttons for quick access to common functions.
        """

        await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "status"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied. You need at least Guest access."
            )
            return

        await self.log_user_action(user_id, "status", "Requested system status")

        # Send loading message
        message = await update.message.reply_text(
            f"{EMOJIS['info']} Gathering system information..."
        )

        try:
            # Get comprehensive status
            status = await self.system_monitor.get_full_status()

            # Edit message with status
            await message.edit_text(status, parse_mode=ParseMode.MARKDOWN)

        except Exception as e:
            logger.error(f"Error getting status: {str(e)}")
            await message.edit_text(
                f"{EMOJIS['error']} Error getting system status: {str(e)}"
            )

    async def cmd_cpu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /cpu command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "cpu"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "cpu", "Requested CPU stats")

        try:
            cpu_report = await self.cpu_monitor.get_detailed_report()
            await self.send_long_message(update, cpu_report)
        except Exception as e:
            logger.error(f"Error getting CPU info: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting CPU information: {str(e)}"
            )

    async def cmd_memory(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /memory command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "memory"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "memory", "Requested memory stats")

        try:
            memory_report = await self.memory_monitor.get_detailed_report()
            await self.send_long_message(update, memory_report)
        except Exception as e:
            logger.error(f"Error getting memory info: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting memory information: {str(e)}"
            )

    async def cmd_disk(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /disk command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "disk"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "disk", "Requested disk stats")

        try:
            disk_report = await self.disk_monitor.get_detailed_report()
            await self.send_long_message(update, disk_report)
        except Exception as e:
            logger.error(f"Error getting disk info: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting disk information: {str(e)}"
            )

    async def cmd_network(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /network command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "network"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "network", "Requested network stats")

        try:
            network_report = await self.network_monitor.get_detailed_report()
            await self.send_long_message(update, network_report)
        except Exception as e:
            logger.error(f"Error getting network info: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting network information: {str(e)}"
            )

    async def cmd_processes(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /processes command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "processes"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "processes", "Requested process list")

        try:
            process_report = await self.process_monitor.get_top_processes()
            await self.send_long_message(update, process_report)
        except Exception as e:
            logger.error(f"Error getting processes: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting process information: {str(e)}"
            )

    async def cmd_services(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /services command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "services"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "services", "Requested service status")

        try:
            services_report = await self.service_monitor.get_services_status()
            await self.send_long_message(update, services_report)
        except Exception as e:
            logger.error(f"Error getting services: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting service information: {str(e)}"
            )

    async def cmd_temperature(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /temperature command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "temperature"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "temperature", "Requested temperature")

        try:
            temp_report = await self.temperature_monitor.get_temperature_report()
            await update.message.reply_text(temp_report, parse_mode=ParseMode.MARKDOWN)
        except Exception as e:
            logger.error(f"Error getting temperature: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting temperature: {str(e)}"
            )

    async def cmd_security(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /security command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "security"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        await self.log_user_action(user_id, "security", "Requested security status")

        try:
            security_report = await self.security_monitor.get_security_report()
            await self.send_long_message(update, security_report)
        except Exception as e:
            logger.error(f"Error getting security info: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting security information: {str(e)}"
            )

    async def cmd_users(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /users command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "users"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied. Admin access required."
            )
            return

        await self.log_user_action(user_id, "users", "Accessed user management")

        try:
            users_report = await self.user_manager.get_users_report()
            await self.send_long_message(update, users_report)
        except Exception as e:
            logger.error(f"Error getting users: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting user information: {str(e)}"
            )

    async def cmd_alerts(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /alerts command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "alerts"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        try:
            alerts_report = await self.alert_manager.get_alerts_summary()
            await self.send_long_message(update, alerts_report)
        except Exception as e:
            logger.error(f"Error getting alerts: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting alerts: {str(e)}"
            )

    async def cmd_reports(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /reports command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "reports"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied."
            )
            return

        try:
            reports_summary = await self.report_manager.get_reports_summary()
            await self.send_long_message(update, reports_summary)
        except Exception as e:
            logger.error(f"Error getting reports: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting reports: {str(e)}"
            )

    async def cmd_uptime(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /uptime command"""
        user_id = update.effective_user.id

        try:
            uptime = await self.system_monitor.get_uptime()
            await update.message.reply_text(uptime, parse_mode=ParseMode.MARKDOWN)
        except Exception as e:
            logger.error(f"Error getting uptime: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting uptime: {str(e)}"
            )

    async def cmd_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ip command"""
        user_id = update.effective_user.id

        try:
            ip_info = await self.network_monitor.get_ip_addresses()
            await update.message.reply_text(ip_info, parse_mode=ParseMode.MARKDOWN)
        except Exception as e:
            logger.error(f"Error getting IP: {str(e)}")
            await update.message.reply_text(
                f"{EMOJIS['error']} Error getting IP addresses: {str(e)}"
            )

    async def cmd_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /menu command"""
        await update.message.reply_text(
            "Select an option:",
            reply_markup=self.create_main_keyboard()
        )

    async def cmd_hide_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Hide keyboard menu"""
        await update.message.reply_text(
            "Menu hidden. Use /menu to show again.",
            reply_markup=ReplyKeyboardRemove()
        )

    async def cmd_settings(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /settings command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "config"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied. Admin access required."
            )
            return

        # TODO: Implement settings management
        await update.message.reply_text(
            f"{EMOJIS['settings']} Settings management coming soon!"
        )

    async def cmd_restart_service(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /restart command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "restart_service"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied. Power User access required."
            )
            return

        # Parse service name from command
        if context.args:
            service_name = sanitize_input(context.args[0])
            if validate_input(service_name, "service_name"):
                result = await self.service_monitor.restart_service(service_name)
                await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
            else:
                await update.message.reply_text(
                    f"{EMOJIS['error']} Invalid service name."
                )
        else:
            await update.message.reply_text(
                f"{EMOJIS['info']} Usage: /restart <service_name>"
            )

    async def cmd_kill_process(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /kill command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "kill_process"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied. Power User access required."
            )
            return

        # Parse PID from command
        if context.args:
            try:
                pid = int(context.args[0])
                result = await self.process_monitor.kill_process(pid)
                await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
            except ValueError:
                await update.message.reply_text(
                    f"{EMOJIS['error']} Invalid PID. Must be a number."
                )
        else:
            await update.message.reply_text(
                f"{EMOJIS['info']} Usage: /kill <pid>"
            )

    async def cmd_reboot(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /reboot command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "reboot"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied. Admin access required."
            )
            return

        if not MONITORING_CONFIG.allow_reboot:
            await update.message.reply_text(
                f"{EMOJIS['error']} Reboot is disabled in configuration."
            )
            return

        # TODO: Implement reboot with confirmation
        await update.message.reply_text(
            f"{EMOJIS['warning']} Reboot functionality disabled for safety."
        )

    async def cmd_shutdown(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /shutdown command"""
        user_id = update.effective_user.id

        if not await self.check_permission(user_id, "shutdown"):
            await update.message.reply_text(
                f"{EMOJIS['error']} Permission denied. Admin access required."
            )
            return

        # TODO: Implement shutdown with confirmation
        await update.message.reply_text(
            f"{EMOJIS['warning']} Shutdown functionality disabled for safety."
        )

    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle callback queries from inline keyboards"""
        query = update.callback_query
        await query.answer()

        # TODO: Implement callback handling for inline keyboards
        await query.edit_message_text("Processing...")

    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle errors in the bot"""
        logger.error(f"Update {update} caused error {context.error}")

        if update and update.effective_message:
            await update.effective_message.reply_text(
                f"{EMOJIS['error']} An error occurred. Please try again later."
            )

    async def send_long_message(self, update: Update, message: str, max_length: int = 4000):
        """Send long messages by splitting them"""
        if len(message) <= max_length:
            await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
            return

        # Split message into chunks
        parts = []
        current = ""

        for line in message.split('\n'):
            if len(current + line + '\n') > max_length:
                if current:
                    parts.append(current)
                    current = line + '\n'
                else:
                    # Line too long, truncate
                    parts.append(line[:max_length])
                    current = ""
            else:
                current += line + '\n'

        if current:
            parts.append(current)

        # Send parts
        for i, part in enumerate(parts):
            if i == 0:
                await update.message.reply_text(part, parse_mode=ParseMode.MARKDOWN)
            else:
                await update.message.reply_text(
                    f"*Continued...*\n\n{part}",
                    parse_mode=ParseMode.MARKDOWN
                )
                await asyncio.sleep(0.5)  # Rate limiting

    async def _monitoring_loop(self):
        """Background monitoring loop"""
        logger.info("Starting monitoring loop...")

        while self.is_running:
            try:
                # Check for alerts
                if MONITORING_CONFIG.enable_alerts:
                    await self.alert_manager.check_alerts()

                # Generate reports if scheduled
                if MONITORING_CONFIG.enable_reports:
                    await self.report_manager.check_scheduled_reports()

                # Sleep for monitoring interval
                await asyncio.sleep(MONITORING_CONFIG.normal_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                await asyncio.sleep(60)

        logger.info("Monitoring loop stopped")

    async def _cleanup_loop(self):
        """Background cleanup loop"""
        logger.info("Starting cleanup loop...")

        while self.is_running:
            try:
                if MONITORING_CONFIG.enable_auto_cleanup:
                    # Clean old logs
                    await self.report_manager.cleanup_old_files()

                    # Clean old metrics
                    # TODO: Implement metrics cleanup

                # Sleep for cleanup interval
                await asyncio.sleep(MONITORING_CONFIG.cleanup_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {str(e)}")
                await asyncio.sleep(3600)

        logger.info("Cleanup loop stopped")

    async def run(self):
        """Run the bot"""
        logger.info("Starting Raspberry Pi Monitor Bot...")

        # Initialize bot
        if not await self.initialize():
            logger.error("Failed to initialize bot")
            return

        # Start bot
        try:
            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling(
                allowed_updates=Update.ALL_TYPES,
                drop_pending_updates=True
            )

            logger.info(f"Bot started successfully! Admin ID: {ADMIN_USER_ID}")

            # Keep running until stopped
            while self.is_running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Error running bot: {str(e)}")

        finally:
            # Cleanup
            logger.info("Shutting down bot...")
            self.is_running = False

            if self.monitoring_task:
                self.monitoring_task.cancel()
            if self.cleanup_task:
                self.cleanup_task.cancel()

            if self.application:
                await self.application.updater.stop()
                await self.application.stop()
                await self.application.shutdown()

            logger.info("Bot stopped")

def main():
    """Main entry point"""
    # Create and run bot
    bot = RaspberryPiMonitorBot()

    # Run asyncio event loop
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()