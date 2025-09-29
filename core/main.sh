#!/bin/bash

# LockKnife Main Execution Module
# Coordinates all modules and provides the main application flow

# Load core modules
source "core/config_manager.sh"
source "core/logging.sh"
source "core/device.sh"
source "core/security.sh"

# Load feature modules
load_modules() {
    # Load all available modules
    for module in "$SCRIPT_DIR/modules"/*.sh; do
        if [[ -f "$module" ]]; then
            log "DEBUG" "Loading module: $(basename "$module")"
            source "$module"
        fi
    done
    log "INFO" "All modules loaded successfully"
}

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION=$(cat "$PROJECT_ROOT/version.txt" 2>/dev/null || echo "unknown")

# Initialize the application
init_lockknife() {
    # Set up error handling
    set -o errexit
    set -o pipefail
    [[ "$DEBUG_MODE" = "true" ]] && set -o xtrace

    # Initialize secure temp directory
    create_secure_temp_dir

    # Initialize logging
    init_logging

    log "INFO" "LockKnife v$VERSION initialized"

    # Load configuration
    load_config

    # Check secure environment
    check_secure_environment

    # Log system information
    log "DEBUG" "Script directory: $SCRIPT_DIR"
    log "DEBUG" "Project root: $PROJECT_ROOT"
    log "DEBUG" "User: $(whoami)"
    log "DEBUG" "PID: $$"
}

# Cleanup function
cleanup_lockknife() {
    local exit_code=$?

    log "INFO" "Performing cleanup..."

    # Secure cleanup of temp files
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        log "INFO" "Cleaning up temporary files..."

        # Remove all files securely
        find "$TEMP_DIR" -type f -exec bash -c 'secure_delete_file "$1"' _ {} \;

        # Remove temp directory
        rmdir "$TEMP_DIR" 2>/dev/null || true
    fi

    # Export logs if requested
    if [[ -n "$EXPORT_LOGS_FORMAT" ]]; then
        export_logs "$EXPORT_LOGS_FORMAT"
    fi

    # Final log entry
    log "INFO" "LockKnife execution completed with exit code $exit_code"

    exit $exit_code
}

# Set up signal handlers
setup_signal_handlers() {
    trap cleanup_lockknife EXIT INT TERM HUP
}

# Check and install dependencies
check_dependencies() {
    local dependencies=("adb" "curl")
    local optional_deps=("sqlite3" "parallel" "tshark" "openssl")
    local missing_required=()
    local missing_optional=()

    log "INFO" "Checking dependencies..."

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_required+=("$dep")
        fi
    done

    for dep in "${optional_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_optional+=("$dep")
        fi
    done

    # Handle missing required dependencies
    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log "ERROR" "Missing required dependencies: ${missing_required[*]}"

        # Try to install on supported systems
        if command -v apt &>/dev/null; then
            log "INFO" "Attempting to install missing dependencies with apt..."
            sudo apt update && sudo apt install -y "${missing_required[@]}"
        elif command -v brew &>/dev/null; then
            log "INFO" "Attempting to install missing dependencies with brew..."
            brew install "${missing_required[@]}"
        elif command -v dnf &>/dev/null; then
            log "INFO" "Attempting to install missing dependencies with dnf..."
            sudo dnf install -y "${missing_required[@]}"
        else
            log "ERROR" "Unsupported package manager. Please install dependencies manually."
            return 1
        fi
    fi

    # Report optional dependencies
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log "WARNING" "Optional dependencies not found: ${missing_optional[*]}"
        log "WARNING" "Some features may not be available. Install them for full functionality."
    fi

    log "INFO" "Dependency check completed"
    return 0
}

# Check for updates
check_for_updates() {
    if [[ "$AUTO_UPDATE_CHECK" != "true" ]]; then
        return 0
    fi

    log "INFO" "Checking for updates..."

    local repo_url="https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main"
    local latest_version

    latest_version=$(curl -sSL "$repo_url/version.txt" 2>/dev/null || echo "$VERSION")

    if [[ "$latest_version" != "$VERSION" ]]; then
        log "INFO" "New version available: $latest_version (current: $VERSION)"

        read -r -p "Would you like to update LockKnife? (y/n): " update_choice
        if [[ "$update_choice" = "y" ]]; then
            update_lockknife
        fi
    else
        log "INFO" "LockKnife is up to date (v$VERSION)"
    fi
}

# Update LockKnife
update_lockknife() {
    log "INFO" "Updating LockKnife..."

    local repo_url="https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main"
    local temp_script="$TEMP_DIR/LockKnife_new.sh"
    local temp_version="$TEMP_DIR/version_new.txt"

    # Download new version
    if ! curl -sSL "$repo_url/LockKnife.sh" -o "$temp_script"; then
        log_error "Failed to download update"
        return 1
    fi

    if ! curl -sSL "$repo_url/version.txt" -o "$temp_version"; then
        log_error "Failed to download version info"
        return 1
    fi

    # Verify downloads
    if [[ ! -s "$temp_script" || ! -s "$temp_version" ]]; then
        log_error "Downloaded files are empty"
        secure_delete_file "$temp_script"
        secure_delete_file "$temp_version"
        return 1
    fi

    # Install update
    mv "$temp_script" "$PROJECT_ROOT/LockKnife.sh"
    mv "$temp_version" "$PROJECT_ROOT/version.txt"

    chmod +x "$PROJECT_ROOT/LockKnife.sh"

    log "SUCCESS" "LockKnife updated to v$(cat "$PROJECT_ROOT/version.txt")"
    log "INFO" "Please restart LockKnife to use the new version"

    exit 0
}

# Parse command line arguments
parse_arguments() {
    EXPORT_LOGS_FORMAT=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG_MODE=true
                log "DEBUG" "Debug mode enabled via command line"
                shift
                ;;
            --config=*)
                local config_file="${1#*=}"
                if [[ -f "$config_file" ]]; then
                    source "$config_file"
                    CONFIG_FILE="$config_file"
                    log "INFO" "Loaded custom config from $config_file"
                else
                    log "ERROR" "Config file not found: $config_file"
                    exit 1
                fi
                shift
                ;;
            --create-config=*)
                local config_path="${1#*=}"
                create_default_config "$config_path"
                exit 0
                ;;
            --output-dir=*)
                OUTPUT_DIR="${1#*=}"
                log "DEBUG" "Output directory set to $OUTPUT_DIR via command line"
                shift
                ;;
            --wordlist=*)
                WORDLIST="${1#*=}"
                log "DEBUG" "Wordlist set to $WORDLIST via command line"
                shift
                ;;
            --export-logs=*)
                EXPORT_LOGS_FORMAT="${1#*=}"
                log "DEBUG" "Log export format set to $EXPORT_LOGS_FORMAT"
                shift
                ;;
            --version)
                echo "LockKnife v$VERSION"
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Show help information
show_help() {
    cat << EOF
LockKnife : The Ultimate Android Security Research Tool v$VERSION

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --debug                    Enable debug mode with verbose logging
    --config=FILE              Use specific configuration file
    --create-config=FILE       Create default configuration file at specified path
    --output-dir=DIR           Specify custom output directory
    --wordlist=FILE            Specify custom wordlist file
    --export-logs=FORMAT       Export logs in specified format (txt, json, csv)
    --version                  Show version information
    --help                     Show this help message

FEATURES:
    • Password Recovery (PIN, Pattern, Password)
    • Data Extraction (SMS, Calls, WiFi, Apps)
    • Forensic Analysis (Snapshots, Search, SQLite)
    • Network Analysis (Traffic Capture, Protocol Analysis)
    • Device Security Assessment
    • Advanced Memory Analysis
    • Kernel Analysis
    • Vulnerability Scanning
    • Malware Detection
    • Cloud Backup Extraction

For more information, visit: https://github.com/ImKKingshuk/LockKnife

EOF
}

# Display banner
display_banner() {
    local banner=(
        "****************************************************"
        "*                     LockKnife                    *"
        "*    The Ultimate Android Security Research Tool   *"
        "*                       v$VERSION                  *"
        "*      --------------------------------------      *"
        "*                              by @ImKKingshuk     *"
        "*      Github - https://github.com/ImKKingshuk     *"
        "****************************************************"
    )

    local width
    width=$(tput cols 2>/dev/null || echo 80)

    echo
    for line in "${banner[@]}"; do
        printf "%*s\n" $(((${#line} + width) / 2)) "$line"
    done
    echo
}

# Display disclaimer
display_disclaimer() {
    echo "⚠️  LEGAL DISCLAIMER ⚠️"
    echo
    echo "LockKnife is developed for research and educational purposes only."
    echo "It should be used responsibly and in compliance with all applicable laws and regulations."
    echo
    echo "PASSWORD RECOVERY TOOLS SHOULD ONLY BE USED FOR LEGITIMATE PURPOSES AND WITH PROPER AUTHORIZATION."
    echo
    echo "Using such tools without proper authorization is illegal and a violation of privacy."
    echo "Ensure proper authorization before using LockKnife for password recovery or data extraction."
    echo
    echo "Always adhere to ethical hacking practices and comply with all applicable laws and regulations."
    echo
    echo "The developer is not responsible for any misuse or illegal activities conducted with this tool."
    echo
}

# Security assessment function
check_security() {
    local device_serial="$1"
    local version
    version=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.release")
    local patch
    patch=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.security_patch")
    local rooted
    rooted=$(execute_shell_cmd "$device_serial" "su -c 'id'" | grep -q "uid=0" && echo "Yes" || echo "No")
    local api_level
    api_level=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.sdk")
    local build_fingerprint
    build_fingerprint=$(execute_shell_cmd "$device_serial" "getprop ro.build.fingerprint")

    local output_file="$OUTPUT_DIR/security_assessment_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "# LockKnife Security Assessment Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        echo "## Device Information"
        echo "- Android Version: $version"
        echo "- API Level: $api_level"
        echo "- Security Patch Level: $patch"
        echo "- Build Fingerprint: $build_fingerprint"
        echo "- Root Access: $rooted"
        echo ""

        echo "## Security Analysis"

        # Check for common security issues
        local encryption_status
        encryption_status=$(execute_shell_cmd "$device_serial" "getprop ro.crypto.state")
        echo "- Device Encryption: ${encryption_status:-Unknown}"

        local selinux_status
        selinux_status=$(execute_shell_cmd "$device_serial" "getprop ro.boot.selinux")
        echo "- SELinux: ${selinux_status:-Unknown}"

        local dm_verity
        dm_verity=$(execute_shell_cmd "$device_serial" "getprop ro.boot.veritymode")
        echo "- dm-verity: ${dm_verity:-Unknown}"

        # Check for vulnerable apps
        local vulnerable_apps
        vulnerable_apps=$(execute_shell_cmd "$device_serial" "pm list packages -u" | wc -l)
        echo "- Total Installed Apps: $vulnerable_apps"

        echo ""

        echo "## Recommendations"

        if [[ "$rooted" = "Yes" ]]; then
            echo "⚠️  WARNING: Device is rooted. This significantly reduces security."
            echo "   - Consider unrooting for better security"
            echo "   - Use security software designed for rooted devices"
        fi

        if [[ "$encryption_status" != "encrypted" ]]; then
            echo "⚠️  WARNING: Device storage may not be encrypted."
            echo "   - Enable full disk encryption in settings"
        fi

        if [[ -z "$patch" || "$patch" = "Unknown" ]]; then
            echo "⚠️  WARNING: Could not determine security patch level."
            echo "   - Ensure device is running the latest security updates"
        fi

        echo ""

        echo "## Risk Assessment"
        local risk_score=0

        [[ "$rooted" = "Yes" ]] && ((risk_score += 30))
        [[ "$encryption_status" != "encrypted" ]] && ((risk_score += 20))
        [[ "$vulnerable_apps" -gt 50 ]] && ((risk_score += 10))

        if [[ $risk_score -ge 50 ]]; then
            echo "🚨 HIGH RISK: Multiple security concerns detected"
        elif [[ $risk_score -ge 25 ]]; then
            echo "⚠️  MEDIUM RISK: Some security improvements needed"
        else
            echo "✅ LOW RISK: Device appears reasonably secure"
        fi

        echo "- Risk Score: $risk_score/100"

    } > "$output_file"

    log "SUCCESS" "Security assessment completed. Results saved to $output_file"

    # Display summary on screen
    echo
    echo "Security Assessment Summary:"
    echo "=========================="
    echo "Android Version: $version"
    echo "Security Patch: $patch"
    echo "Rooted: $rooted"
    echo "Device appears reasonably secure."
}

# Main menu system
main_menu() {
    local device_serial="$1"

    while true; do
        echo
        echo "LockKnife - Ultimate Android Security Research Tool"
        echo "=================================================="
        echo "Connected Device: $device_serial"
        echo
        echo "🔐 CORE FEATURES"
        echo "1. Password Recovery          2. Data Extraction"
        echo "3. Live Analysis             4. Security Assessment"
        echo
        echo "🔍 ANALYSIS TOOLS"
        echo "5. Runtime Analysis          6. SSL Pinning Bypass"
        echo "7. Advanced APK Analysis     8. Forensic Analysis"
        echo "9. Network Traffic Analysis  10. Advanced Memory Analysis"
        echo
        echo "⚙️ SYSTEM ANALYSIS"
        echo "11. Kernel & System Analysis 12. Hardware Security Analysis"
        echo "13. Bootloader Security      14. Vulnerability Scanning"
        echo "15. Malware Analysis         16. Cloud Backup Extraction"
        echo
        echo "🔬 ADVANCED FEATURES"
        echo "17. Biometric Data Analysis  18. System Service Analysis"
        echo "19. Firmware Extraction      20. Configuration & Tools"
        echo
        echo "0. Exit"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) submenu_password_recovery "$device_serial" ;;
            2) submenu_data_extraction "$device_serial" ;;
            3) live_analysis "$device_serial" ;;
            4) check_security "$device_serial" ;;
            5) runtime_analysis_menu "$device_serial" ;;
            6) ssl_pinning_bypass_menu "$device_serial" ;;
            7) advanced_apk_analysis_menu "$device_serial" ;;
            8) submenu_forensic_analysis "$device_serial" ;;
            9) submenu_network_analysis "$device_serial" ;;
            10) advanced_memory_analysis "$device_serial" ;;
            11) kernel_system_analysis "$device_serial" ;;
            12) hardware_security_analysis_menu "$device_serial" ;;
            13) bootloader_security_menu "$device_serial" ;;
            14) vulnerability_scanning "$device_serial" ;;
            15) malware_analysis "$device_serial" ;;
            16) cloud_backup_extraction "$device_serial" ;;
            17) biometric_analysis "$device_serial" ;;
            18) system_service_analysis "$device_serial" ;;
            19) firmware_extraction_menu "$device_serial" ;;
            20) configuration_tools ;;
            0)
                log "INFO" "User requested exit"
                return 0
                ;;
            *)
                log "ERROR" "Invalid choice: $choice"
                ;;
        esac
    done
}

# Configuration tools submenu
configuration_tools() {
    while true; do
        echo
        echo "Configuration & Tools"
        echo "====================="
        echo "1. Show Current Configuration"
        echo "2. Create New Configuration File"
        echo "3. Save Current Configuration"
        echo "4. Generate Security Report"
        echo "5. Export Logs"
        echo "6. Cleanup Old Files"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) show_config ;;
            2)
                read -r -p "Enter config file path: " config_path
                create_default_config "$config_path"
                ;;
            3) save_config ;;
            4) generate_security_report ;;
            5)
                echo "Available formats: txt, json, csv"
                read -r -p "Enter format: " format
                export_logs "$format"
                ;;
            6)
                read -r -p "Enter days to keep: " days
                cleanup_logs "$days"
                ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Main execution function
execute_lockknife() {
    # Initialize
    init_lockknife

    # Set up signal handlers
    setup_signal_handlers

    # Parse command line arguments
    parse_arguments "$@"

    # Display banner and disclaimer
    display_banner
    display_disclaimer

    # Check dependencies
    check_dependencies

    # Check for updates
    check_for_updates

    # Load modules
    load_modules

    # Check ADB
    check_adb

    # Select device
    local device_serial
    device_serial=$(select_device)

    if [[ -z "$device_serial" ]]; then
        log "ERROR" "No device selected. Exiting."
        exit 1
    fi

    # Connect to device
    connect_device_usb "$device_serial"

    # Wait for device to be ready
    wait_for_device "$device_serial"

    # Check root access
    check_root "$device_serial"

    # Enter main menu
    main_menu "$device_serial"

    # Success
    log "SUCCESS" "LockKnife execution completed successfully"
}

# Check for tool updates
check_for_updates() {
    local current_version
    current_version=$(cat "$PROJECT_ROOT/version.txt" 2>/dev/null || echo "unknown")
    local latest_version
    latest_version=$(curl -sSL "https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/version.txt" 2>/dev/null || echo "$current_version")

    if [ "$latest_version" != "$current_version" ] && [ "$latest_version" != "unknown" ]; then
        echo "A new version ($latest_version) is available. Current version: $current_version"
        read -r -p "Would you like to update LockKnife now? (y/n): " update_choice

        if [[ "$update_choice" = "y" || "$update_choice" = "Y" ]]; then
            update_tool
        else
            log "INFO" "Update skipped by user"
        fi
    else
        log "INFO" "LockKnife is up to date (version $current_version)"
    fi
}

# Update the tool to latest version
update_tool() {
    local repo_url="https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main"
    local temp_dir="$TEMP_DIR/update_temp"
    local backup_dir="$PROJECT_ROOT/backup_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Starting LockKnife update process..."

    # Create temporary directory
    mkdir -p "$temp_dir"

    # Create backup
    log "INFO" "Creating backup of current installation..."
    mkdir -p "$backup_dir"
    cp -r "$PROJECT_ROOT"/* "$backup_dir/" 2>/dev/null || true
    log "INFO" "Backup created in: $backup_dir"

    # Download latest files
    local files_to_update=(
        "LockKnife.sh"
        "version.txt"
        "README.md"
        "CHANGELOG.md"
        "core/main.sh"
        "core/config_manager.sh"
        "core/logging.sh"
        "core/device.sh"
        "core/security.sh"
    )

    local update_success=true

    for file in "${files_to_update[@]}"; do
        log "INFO" "Downloading: $file"
        if curl -sSL "$repo_url/$file" -o "$temp_dir/$file" 2>/dev/null; then
            log "DEBUG" "Downloaded: $file"
        else
            log "WARNING" "Failed to download: $file"
            update_success=false
        fi
    done

    # Download new modules if they exist
    log "INFO" "Checking for new modules..."
    local modules_list
    modules_list=$(curl -sSL "$repo_url/modules/" 2>/dev/null | grep -o 'href="[^"]*\.sh"' | sed 's/href="//' | sed 's/"//' 2>/dev/null || echo "")

    if [[ -n "$modules_list" ]]; then
        mkdir -p "$temp_dir/modules"
        for module in $modules_list; do
            if [[ "$module" =~ \.sh$ ]]; then
                log "INFO" "Downloading module: $module"
                curl -sSL "$repo_url/modules/$module" -o "$temp_dir/modules/$module" 2>/dev/null || log "WARNING" "Failed to download module: $module"
            fi
        done
    fi

    # Verify downloads
    if [[ "$update_success" = false ]]; then
        log "ERROR" "Some files failed to download. Update aborted."
        rm -rf "$temp_dir"
        return 1
    fi

    # Apply updates
    log "INFO" "Applying updates..."

    # Update core files
    for file in "${files_to_update[@]}"; do
        if [[ -f "$temp_dir/$file" ]]; then
            local target_dir
            target_dir=$(dirname "$file")
            if [[ "$target_dir" != "." ]]; then
                mkdir -p "$PROJECT_ROOT/$target_dir"
            fi
            cp "$temp_dir/$file" "$PROJECT_ROOT/$file"
            log "DEBUG" "Updated: $file"
        fi
    done

    # Update modules
    if [[ -d "$temp_dir/modules" ]]; then
        mkdir -p "$PROJECT_ROOT/modules"
        cp "$temp_dir/modules"/*.sh "$PROJECT_ROOT/modules/" 2>/dev/null || true
    fi

    # Cleanup
    rm -rf "$temp_dir"

    log "SUCCESS" "LockKnife has been updated successfully!"

    # Ask to restart
    read -r -p "Update complete. Would you like to restart LockKnife now? (y/n): " restart_choice
    if [[ "$restart_choice" = "y" || "$restart_choice" = "Y" ]]; then
        log "INFO" "Restarting LockKnife..."
        exec "$0" "$@"
    fi
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    execute_lockknife "$@"
fi
