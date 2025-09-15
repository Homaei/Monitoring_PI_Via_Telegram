#!/bin/bash

# Advanced Raspberry Pi Monitoring System - Installation Script
# This script automates the installation and setup process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/raspberry-monitor"
SERVICE_NAME="raspberry-monitor"
PYTHON_VERSION="3.8"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_python_version() {
    log_info "Checking Python version..."

    if command -v python3 &> /dev/null; then
        PYTHON_VER=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        if [[ $(echo "$PYTHON_VER >= $PYTHON_VERSION" | bc -l) -eq 1 ]]; then
            log_success "Python $PYTHON_VER found"
        else
            log_error "Python $PYTHON_VERSION or higher is required. Found: $PYTHON_VER"
            exit 1
        fi
    else
        log_error "Python 3 is not installed"
        exit 1
    fi
}

install_system_dependencies() {
    log_info "Installing system dependencies..."

    apt-get update
    apt-get install -y \
        python3-dev \
        python3-pip \
        python3-venv \
        smartmontools \
        lm-sensors \
        bc \
        curl \
        systemd

    log_success "System dependencies installed"
}

setup_installation_directory() {
    log_info "Setting up installation directory..."

    # Create installation directory
    mkdir -p "$INSTALL_DIR"

    # Copy files
    if [ -d "$(dirname "$0")" ]; then
        cp -r "$(dirname "$0")"/* "$INSTALL_DIR"/
    else
        log_error "Source directory not found"
        exit 1
    fi

    # Set ownership
    chown -R pi:pi "$INSTALL_DIR"

    log_success "Installation directory set up at $INSTALL_DIR"
}

setup_python_environment() {
    log_info "Setting up Python virtual environment..."

    cd "$INSTALL_DIR"

    # Create virtual environment as pi user
    sudo -u pi python3 -m venv venv

    # Install Python dependencies
    sudo -u pi "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
    sudo -u pi "$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

    # Make main script executable
    chmod +x main.py

    log_success "Python environment set up"
}

configure_bot_token() {
    log_info "Bot token configuration required..."

    echo ""
    echo "=========================================="
    echo "TELEGRAM BOT SETUP REQUIRED"
    echo "=========================================="
    echo ""
    echo "To complete the installation, you need to:"
    echo ""
    echo "1. Create a Telegram bot:"
    echo "   - Message @BotFather on Telegram"
    echo "   - Send /newbot and follow the prompts"
    echo "   - Copy the bot token"
    echo ""
    echo "2. Get your Telegram user ID:"
    echo "   - Message @userinfobot on Telegram"
    echo "   - Copy your user ID"
    echo ""
    echo "3. Edit the configuration file:"
    echo "   sudo nano $INSTALL_DIR/config/settings.py"
    echo ""
    echo "   Update these lines:"
    echo "   BOT_TOKEN = \"YOUR_BOT_TOKEN_HERE\""
    echo "   ADMIN_USER_ID = YOUR_USER_ID_HERE"
    echo ""

    log_warning "Configuration must be completed before starting the service"
}

create_systemd_service() {
    log_info "Creating systemd service..."

    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Advanced Raspberry Pi Monitor Bot
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"

    log_success "Systemd service created and enabled"
}

setup_log_rotation() {
    log_info "Setting up log rotation..."

    cat > "/etc/logrotate.d/$SERVICE_NAME" << EOF
$INSTALL_DIR/data/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su pi pi
}
EOF

    log_success "Log rotation configured"
}

setup_permissions() {
    log_info "Setting up permissions..."

    # Add pi user to required groups
    usermod -a -G adm,systemd-journal pi

    # Set up sudo permissions for service management (optional)
    cat > "/etc/sudoers.d/$SERVICE_NAME" << EOF
# Allow pi user to manage services (used by monitoring system)
pi ALL=(ALL) NOPASSWD: /bin/systemctl restart *
pi ALL=(ALL) NOPASSWD: /bin/systemctl start *
pi ALL=(ALL) NOPASSWD: /bin/systemctl stop *
pi ALL=(ALL) NOPASSWD: /bin/systemctl status *
EOF

    log_success "Permissions configured"
}

run_initial_test() {
    log_info "Running initial test..."

    cd "$INSTALL_DIR"

    # Test imports
    if sudo -u pi "$INSTALL_DIR/venv/bin/python" -c "
import sys
sys.path.insert(0, '.')
try:
    from config.settings import BOT_TOKEN, EMOJIS
    from utils.helpers import safe_execute, format_bytes
    from modules.system_monitor import SystemMonitor
    print('✅ All imports successful')
except Exception as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"; then
        log_success "Initial test passed"
    else
        log_error "Initial test failed"
        exit 1
    fi
}

show_completion_message() {
    echo ""
    echo "=========================================="
    echo "INSTALLATION COMPLETED"
    echo "=========================================="
    echo ""
    echo "✅ System dependencies installed"
    echo "✅ Python environment set up"
    echo "✅ Systemd service created"
    echo "✅ Log rotation configured"
    echo "✅ Permissions set up"
    echo ""
    echo "📋 NEXT STEPS:"
    echo ""
    echo "1. Configure bot token and admin user:"
    echo "   sudo nano $INSTALL_DIR/config/settings.py"
    echo ""
    echo "2. Start the service:"
    echo "   sudo systemctl start $SERVICE_NAME"
    echo ""
    echo "3. Check service status:"
    echo "   sudo systemctl status $SERVICE_NAME"
    echo ""
    echo "4. View logs:"
    echo "   journalctl -u $SERVICE_NAME -f"
    echo ""
    echo "5. Test the bot by messaging it on Telegram"
    echo ""
    echo "📁 Installation directory: $INSTALL_DIR"
    echo "🔧 Service name: $SERVICE_NAME"
    echo ""
    echo "📖 For detailed setup instructions, see:"
    echo "   $INSTALL_DIR/README.md"
    echo ""
}

# Main installation process
main() {
    echo ""
    echo "=========================================="
    echo "ADVANCED RASPBERRY PI MONITORING SYSTEM"
    echo "Installation Script"
    echo "=========================================="
    echo ""

    # Perform checks
    check_root
    check_python_version

    # Install components
    install_system_dependencies
    setup_installation_directory
    setup_python_environment
    create_systemd_service
    setup_log_rotation
    setup_permissions
    run_initial_test

    # Show configuration instructions
    configure_bot_token
    show_completion_message

    log_success "Installation completed successfully!"
}

# Handle script interruption
trap 'log_error "Installation interrupted"; exit 1' INT TERM

# Run main installation
main "$@"