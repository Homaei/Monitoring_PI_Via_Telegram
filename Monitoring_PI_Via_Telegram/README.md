# 🖥️ Advanced Raspberry Pi Monitoring System

A comprehensive, production-ready monitoring system for Raspberry Pi with Telegram bot interface. This enhanced version provides real-time system monitoring, alerts, reporting, and user management with enterprise-grade features.

## ✨ Key Features

### 🔍 **Comprehensive Monitoring**
- **System Status**: Overall health, uptime, load average
- **CPU Monitoring**: Usage, frequency, per-core stats, top processes
- **Memory Tracking**: RAM, swap, memory pressure analysis
- **Disk Monitoring**: Usage, I/O stats, SMART health data
- **Network Analysis**: Interface stats, connectivity tests, traffic monitoring
- **Temperature Sensors**: Multiple sensor support with trend analysis
- **Process Management**: Real-time process monitoring and control
- **Service Management**: systemd service monitoring and control
- **Security Monitoring**: Security assessment and recommendations

### 🔔 **Advanced Alert System**
- Multi-level alerting (LOW, MEDIUM, HIGH, CRITICAL)
- Rule-based alert triggers with configurable thresholds
- Telegram notifications with rate limiting
- Alert acknowledgment and resolution tracking
- Cooldown periods to prevent spam

### 📊 **Comprehensive Reporting**
- Multiple report formats (TEXT, JSON, CSV, HTML)
- Scheduled automatic reports (daily, weekly, monthly)
- Historical data tracking and trend analysis
- Customizable report templates

### 👥 **User Management**
- Role-based access control (Admin, Power User, User, Read-Only, Guest)
- User authentication and session management
- Failed login attempt tracking with lockouts
- Activity logging and audit trails

### 🛡️ **Security & Safety**
- Input validation and sanitization
- Safe command execution with timeouts
- Secure service and process management
- Configuration-based feature toggles

## 📋 **Requirements**

### System Requirements
- Raspberry Pi (any model) with Raspbian/Ubuntu
- Python 3.8 or higher
- Internet connection for Telegram bot
- Minimum 1GB free disk space

### System Dependencies
```bash
sudo apt-get update
sudo apt-get install -y python3-dev python3-pip python3-venv
sudo apt-get install -y smartmontools lm-sensors  # For hardware monitoring
```

## 🚀 **Quick Start**

### 1. Clone and Setup
```bash
# Navigate to your desired installation directory
cd /opt

# Clone or copy the Advance_Monitoring folder
sudo cp -r /path/to/Advance_Monitoring /opt/raspberry-monitor
cd /opt/raspberry-monitor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Configuration Setup
```bash
# Copy and edit configuration
cp config/settings.py config/settings.py.backup

# Edit config/settings.py to set your Telegram bot token and admin user ID
nano config/settings.py
```

**Required Configuration:**
- `BOT_TOKEN`: Your Telegram bot token from @BotFather
- `ADMIN_USER_ID`: Your Telegram user ID (get from @userinfobot)

### 3. Create Telegram Bot
1. Message @BotFather on Telegram
2. Send `/newbot` and follow prompts
3. Copy the token to `config/settings.py`
4. Get your user ID from @userinfobot
5. Update `ADMIN_USER_ID` in configuration

### 4. Initialize and Run
```bash
# Make main script executable
chmod +x main.py

# Test run (press Ctrl+C to stop)
python3 main.py

# If successful, you should see:
# "Bot started successfully! Admin ID: YOUR_USER_ID"
```

### 5. Production Setup (Systemd Service)
```bash
# Create systemd service
sudo nano /etc/systemd/system/raspberry-monitor.service
```

**Service file content:**
```ini
[Unit]
Description=Advanced Raspberry Pi Monitor Bot
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/opt/raspberry-monitor
Environment=PATH=/opt/raspberry-monitor/venv/bin
ExecStart=/opt/raspberry-monitor/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable raspberry-monitor
sudo systemctl start raspberry-monitor

# Check status
sudo systemctl status raspberry-monitor

# View logs
journalctl -u raspberry-monitor -f
```

## 🎯 **Usage**

### Telegram Commands

#### Basic Monitoring
- `/start` - Start bot and show main menu
- `/status` - Complete system overview
- `/cpu` - CPU usage and statistics
- `/memory` - Memory usage details
- `/disk` - Disk usage and I/O stats
- `/temperature` - Temperature readings
- `/network` - Network interfaces and stats
- `/uptime` - System uptime information
- `/ip` - IP addresses and connectivity

#### System Management
- `/processes` - Running processes list
- `/services` - System services status
- `/security` - Security assessment
- `/alerts` - Current alerts and notifications
- `/reports` - System reports summary

#### Power User Commands (Requires elevated permissions)
- `/restart <service>` - Restart system service
- `/kill <pid>` - Kill process by PID

#### Admin Commands (Admin access required)
- `/users` - User management
- `/settings` - Bot configuration
- `/reboot` - System reboot (if enabled)
- `/shutdown` - System shutdown (if enabled)

### Keyboard Interface
The bot provides an intuitive keyboard interface with buttons for common commands. Use `/menu` to show the keyboard or "❌ Hide Menu" to hide it.

## ⚙️ **Configuration**

### Main Configuration File: `config/settings.py`

#### Bot Settings
```python
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
ADMIN_USER_ID = YOUR_USER_ID_HERE
AUTHORIZED_USERS = [YOUR_USER_ID_HERE]
```

#### Monitoring Thresholds
```python
THRESHOLDS.cpu_usage = {
    "info": 30.0,
    "warning": 70.0,
    "critical": 85.0,
    "danger": 95.0
}
```

#### Feature Toggles
```python
MONITORING_CONFIG.enable_alerts = True
MONITORING_CONFIG.enable_reports = True
MONITORING_CONFIG.allow_reboot = False  # Set to True for reboot capability
MONITORING_CONFIG.safe_mode = True      # Recommended for production
```

### File Structure
```
Advance_Monitoring/
├── main.py                 # Main bot script
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── config/
│   └── settings.py        # Configuration settings
├── utils/
│   └── helpers.py         # Utility functions
├── modules/               # Monitoring modules
│   ├── __init__.py
│   ├── system_monitor.py
│   ├── cpu_monitor.py
│   ├── memory_monitor.py
│   ├── disk_monitor.py
│   ├── network_monitor.py
│   ├── process_monitor.py
│   ├── service_monitor.py
│   ├── temperature_monitor.py
│   ├── security_monitor.py
│   ├── user_manager.py
│   ├── alert_manager.py
│   └── report_manager.py
├── data/                  # Data storage
│   ├── logs/             # Log files
│   ├── reports/          # Generated reports
│   ├── metrics/          # Metrics database
│   └── backups/          # Configuration backups
└── tests/                # Unit tests (optional)
```

## 🔐 **Security Considerations**

### Access Control
- The bot uses role-based permissions with 5 levels
- Users must be explicitly added by an admin
- Failed login attempts are tracked and can trigger lockouts
- All user actions are logged for auditing

### Safe Operation
- Commands are validated and sanitized
- System operations have safety checks
- Dangerous operations require admin privileges
- Safe mode prevents certain operations

### Network Security
- Bot communicates only with Telegram's servers
- No external services required (except Telegram)
- Local network scanning can be disabled
- Firewall-friendly design

## 📈 **Monitoring & Alerts**

### Alert Levels
- **LOW**: Informational alerts
- **MEDIUM**: Warning conditions
- **HIGH**: Serious issues requiring attention
- **CRITICAL**: Immediate action required

### Alert Types
- System resource thresholds (CPU, memory, disk)
- Temperature warnings
- Service failures
- Security events
- Network connectivity issues

### Report Types
- **System Reports**: Overall health and status
- **Performance Reports**: Resource usage trends
- **Security Reports**: Security assessment results
- **Comprehensive Reports**: All monitoring data combined

## 🛠️ **Troubleshooting**

### Common Issues

#### Bot Not Starting
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Check dependencies
pip list

# Check configuration
python3 -c "from config.settings import BOT_TOKEN; print('Token configured' if BOT_TOKEN else 'No token')"

# Check permissions
ls -la main.py
```

#### Permission Denied Errors
```bash
# Add user to required groups
sudo usermod -a -G adm,systemd-journal pi

# Check sudo configuration for service management
sudo visudo
```

#### High Resource Usage
```bash
# Check monitoring interval
grep "check_interval" config/settings.py

# Disable resource-intensive features
# Edit settings.py and set:
# MONITORING_CONFIG.enable_metrics = False
```

### Log Files
- System logs: `data/logs/system.log`
- Error logs: `data/logs/errors.log`
- Activity logs: `data/logs/activity.log`

### Support Commands
```bash
# Check system status
sudo systemctl status raspberry-monitor

# View recent logs
journalctl -u raspberry-monitor --since "1 hour ago"

# Test bot connectivity
python3 -c "import telegram; print('Telegram library working')"
```

## 🔄 **Updates and Maintenance**

### Updating the System
```bash
cd /opt/raspberry-monitor
git pull  # If using git
sudo systemctl restart raspberry-monitor
```

### Database Maintenance
The system automatically cleans old data based on retention settings in `config/settings.py`. Manual cleanup:
```bash
# Clean old logs (keeps last 30 days)
find data/logs -name "*.log" -mtime +30 -delete

# Clean old reports (keeps last 365 days)
find data/reports -name "*.txt" -mtime +365 -delete
```

### Backup Configuration
```bash
# Backup configuration and data
tar -czf raspberry-monitor-backup-$(date +%Y%m%d).tar.gz \
    config/ data/users.json data/metrics/
```

## 📝 **License**

This project is provided as-is for educational and personal use. Please ensure compliance with your local laws and Telegram's Terms of Service.

## 🤝 **Contributing**

To contribute improvements:
1. Test thoroughly on your Raspberry Pi
2. Ensure backward compatibility
3. Update documentation
4. Follow the existing code style
5. Add appropriate error handling

## 📞 **Support**

For issues and support:
1. Check the troubleshooting section above
2. Review the log files for error messages
3. Ensure all dependencies are properly installed
4. Verify Telegram bot token and permissions

---

**🎉 Congratulations!** You now have a professional-grade Raspberry Pi monitoring system. The bot will provide comprehensive insights into your system's health and performance, with intelligent alerting and detailed reporting capabilities.