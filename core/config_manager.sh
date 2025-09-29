#!/bin/bash

# LockKnife Configuration Manager Module
# Handles all configuration loading, validation, and management

# Default configuration values (using compatible syntax)
DEBUG_MODE_DEFAULT=false
MAX_RETRIES_DEFAULT=3
OUTPUT_DIR_DEFAULT="$HOME/lockknife_output"
SECURE_DELETE_DEFAULT=true
WORDLIST_DEFAULT="/usr/share/dict/words"
PARALLEL_JOBS_DEFAULT="50%"
PIN_LENGTH_DEFAULT=4
SNAPSHOT_DIRS_DEFAULT="/data/data /data/system /sdcard"
PCAP_FILTER_DEFAULT="port not 5555"
WHATSAPP_EXTRACT_MEDIA_DEFAULT=false
BROWSER_EXTRACT_FAVICONS_DEFAULT=false
SIGNAL_EXTRACT_ATTACHMENTS_DEFAULT=false
GATEKEEPER_EXPORT_HASHCAT_DEFAULT=true
KEYSTORE_MONITOR_DURATION_DEFAULT=60
BLUETOOTH_EXTRACT_ALL_DEFAULT=false
MEMORY_ANALYSIS_DEPTH_DEFAULT="basic"
KERNEL_ANALYSIS_ENABLED_DEFAULT=true
MALWARE_SCAN_DEPTH_DEFAULT="quick"
VULN_SCAN_TIMEOUT_DEFAULT=300
FIRMWARE_ANALYSIS_ENABLED_DEFAULT=false
BIOMETRIC_EXTRACTION_ENABLED_DEFAULT=true
SYSTEM_SERVICE_MONITORING_DEFAULT=true
AUTO_UPDATE_CHECK_DEFAULT=true
LOG_LEVEL_DEFAULT="INFO"
BACKUP_BEFORE_EXTRACTION_DEFAULT=true
ENCRYPTED_OUTPUT_DEFAULT=false
ANONYMOUS_MODE_DEFAULT=false

# Configuration file search paths (in order of precedence)
CONFIG_PATHS=(
    "./lockknife.conf"
    "$HOME/.config/lockknife/lockknife.conf"
    "$HOME/.lockknife.conf"
    "/etc/lockknife.conf"
)

# Load configuration from file
load_config() {
    local config_loaded=false

    for config_path in "${CONFIG_PATHS[@]}"; do
        if [[ -f "$config_path" ]]; then
            log "INFO" "Loading configuration from $config_path"
            # Source the config file safely
            if source "$config_path" 2>/dev/null; then
                config_loaded=true
                CONFIG_FILE="$config_path"
                break
            else
                log "WARNING" "Failed to load config from $config_path"
            fi
        fi
    done

    if [[ "$config_loaded" = false ]]; then
        log "DEBUG" "No configuration file found, using defaults"
    fi

    # Set defaults for any unset variables
    set_config_defaults

    # Validate and create output directory
    validate_output_dir

    # Validate configuration values
    validate_config
}

# Set default values for unset configuration variables
set_config_defaults() {
    for var in DEBUG_MODE MAX_RETRIES OUTPUT_DIR SECURE_DELETE WORDLIST PARALLEL_JOBS PIN_LENGTH SNAPSHOT_DIRS PCAP_FILTER WHATSAPP_EXTRACT_MEDIA BROWSER_EXTRACT_FAVICONS SIGNAL_EXTRACT_ATTACHMENTS GATEKEEPER_EXPORT_HASHCAT KEYSTORE_MONITOR_DURATION BLUETOOTH_EXTRACT_ALL MEMORY_ANALYSIS_DEPTH KERNEL_ANALYSIS_ENABLED MALWARE_SCAN_DEPTH VULN_SCAN_TIMEOUT FIRMWARE_ANALYSIS_ENABLED BIOMETRIC_EXTRACTION_ENABLED SYSTEM_SERVICE_MONITORING AUTO_UPDATE_CHECK LOG_LEVEL BACKUP_BEFORE_EXTRACTION ENCRYPTED_OUTPUT ANONYMOUS_MODE; do
        if [[ -z "${!var+x}" ]]; then
            default_var="${var}_DEFAULT"
            eval "$var=\"${!default_var}\""
        fi
    done
}

# Validate and create output directory
validate_output_dir() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            chmod 700 "$OUTPUT_DIR"
            log "DEBUG" "Created output directory: $OUTPUT_DIR"
        else
            log "ERROR" "Failed to create output directory: $OUTPUT_DIR"
            exit 1
        fi
    fi
}

# Validate configuration values
validate_config() {
    # Validate DEBUG_MODE
    if [[ "$DEBUG_MODE" != "true" && "$DEBUG_MODE" != "false" ]]; then
        log "WARNING" "Invalid DEBUG_MODE value: $DEBUG_MODE, using default: $DEBUG_MODE_DEFAULT"
        DEBUG_MODE="$DEBUG_MODE_DEFAULT"
    fi

    # Validate MAX_RETRIES
    if ! [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]] || [[ "$MAX_RETRIES" -lt 1 ]] || [[ "$MAX_RETRIES" -gt 10 ]]; then
        log "WARNING" "Invalid MAX_RETRIES value: $MAX_RETRIES, using default: $MAX_RETRIES_DEFAULT"
        MAX_RETRIES="$MAX_RETRIES_DEFAULT"
    fi

    # Validate PIN_LENGTH
    if ! [[ "$PIN_LENGTH" =~ ^[0-9]+$ ]] || [[ "$PIN_LENGTH" -lt 4 ]] || [[ "$PIN_LENGTH" -gt 12 ]]; then
        log "WARNING" "Invalid PIN_LENGTH value: $PIN_LENGTH, using default: $PIN_LENGTH_DEFAULT"
        PIN_LENGTH="$PIN_LENGTH_DEFAULT"
    fi

    # Validate LOG_LEVEL
    case "$LOG_LEVEL" in
        DEBUG|INFO|WARNING|ERROR)
            ;;
        *)
            log "WARNING" "Invalid LOG_LEVEL value: $LOG_LEVEL, using default: $LOG_LEVEL_DEFAULT"
            LOG_LEVEL="$LOG_LEVEL_DEFAULT"
            ;;
    esac
}

# Create default configuration file
create_default_config() {
    local config_path="$1"

    if [[ -f "$config_path" ]]; then
        log "WARNING" "Configuration file already exists at $config_path"
        read -r -p "Overwrite existing config? (y/n): " overwrite
        if [[ "$overwrite" != "y" ]]; then
            log "INFO" "Keeping existing configuration file"
            return 0
        fi
    fi

    log "INFO" "Creating default configuration file at $config_path"

    local config_dir
    config_dir=$(dirname "$config_path")
    if [[ ! -d "$config_dir" ]]; then
        mkdir -p "$config_dir"
    fi
    cat > "$config_path" << EOF
# LockKnife Configuration File
# Generated on $(date)

# General Settings
DEBUG_MODE=${DEBUG_MODE_DEFAULT}         # Set to true for verbose debugging
MAX_RETRIES=${MAX_RETRIES_DEFAULT}       # Number of retries for ADB commands
OUTPUT_DIR="${OUTPUT_DIR_DEFAULT}"       # Directory to save output files
SECURE_DELETE=${SECURE_DELETE_DEFAULT}   # Use secure deletion for sensitive files
AUTO_UPDATE_CHECK=${AUTO_UPDATE_CHECK_DEFAULT}  # Check for updates on startup
LOG_LEVEL=${LOG_LEVEL_DEFAULT}           # Logging level (DEBUG, INFO, WARNING, ERROR)

# Attack Settings
WORDLIST="${WORDLIST_DEFAULT}"           # Default wordlist for dictionary attacks
PARALLEL_JOBS="${PARALLEL_JOBS_DEFAULT}" # CPU percentage for parallel processing
PIN_LENGTH=${PIN_LENGTH_DEFAULT}         # Default PIN length for brute force

# Forensics Settings
SNAPSHOT_DIRS="${SNAPSHOT_DIRS_DEFAULT}" # Directories to include in device snapshot
PCAP_FILTER="${PCAP_FILTER_DEFAULT}"     # tcpdump filter for network capture
BACKUP_BEFORE_EXTRACTION=${BACKUP_BEFORE_EXTRACTION_DEFAULT}  # Create backups before extraction

# App-Specific Settings
WHATSAPP_EXTRACT_MEDIA=${WHATSAPP_EXTRACT_MEDIA_DEFAULT}      # Extract WhatsApp media files
BROWSER_EXTRACT_FAVICONS=${BROWSER_EXTRACT_FAVICONS_DEFAULT}  # Extract browser favicons
SIGNAL_EXTRACT_ATTACHMENTS=${SIGNAL_EXTRACT_ATTACHMENTS_DEFAULT}  # Extract Signal attachments

# Advanced Analysis Settings
MEMORY_ANALYSIS_DEPTH="${MEMORY_ANALYSIS_DEPTH_DEFAULT}"      # Memory analysis depth (basic, full, deep)
KERNEL_ANALYSIS_ENABLED=${KERNEL_ANALYSIS_ENABLED_DEFAULT}    # Enable kernel analysis
MALWARE_SCAN_DEPTH="${MALWARE_SCAN_DEPTH_DEFAULT}"           # Malware scan depth (quick, full, deep)
VULN_SCAN_TIMEOUT=${VULN_SCAN_TIMEOUT_DEFAULT}               # Vulnerability scan timeout (seconds)

# Experimental Features
FIRMWARE_ANALYSIS_ENABLED=${FIRMWARE_ANALYSIS_ENABLED_DEFAULT} # Enable firmware analysis
BIOMETRIC_EXTRACTION_ENABLED=${BIOMETRIC_EXTRACTION_ENABLED_DEFAULT}  # Enable biometric data extraction
SYSTEM_SERVICE_MONITORING=${SYSTEM_SERVICE_MONITORING_DEFAULT}  # Monitor system services

# Security Settings
ENCRYPTED_OUTPUT=${ENCRYPTED_OUTPUT_DEFAULT}   # Encrypt output files
ANONYMOUS_MODE=${ANONYMOUS_MODE_DEFAULT}      # Anonymous operation mode

# Gatekeeper Settings
GATEKEEPER_EXPORT_HASHCAT=${GATEKEEPER_EXPORT_HASHCAT_DEFAULT}  # Export hashes in hashcat format
# Bluetooth Settings
BLUETOOTH_EXTRACT_ALL=${BLUETOOTH_EXTRACT_ALL_DEFAULT}  # Extract all Bluetooth files

# Keystore Settings
KEYSTORE_MONITOR_DURATION=${KEYSTORE_MONITOR_DURATION_DEFAULT}  # Default monitoring duration (seconds)
EOF
CONFIG_FILE="$config_path"
    [[ -z "$config_path" ]] && config_path="$HOME/.config/lockknife/lockknife.conf"

    log "INFO" "Saving current configuration to $config_path"

    local config_dir
    if [[ ! -d "$config_dir" ]]; then
        mkdir -p "$config_dir"
    fi

    {
        echo "# LockKnife Configuration File"
        echo "# Generated on $(date)"
        echo ""
        echo "# General Settings"
        echo "DEBUG_MODE=$DEBUG_MODE"
        echo "MAX_RETRIES=$MAX_RETRIES"
        echo "OUTPUT_DIR=\"$OUTPUT_DIR\""
        echo "SECURE_DELETE=$SECURE_DELETE"
        echo "AUTO_UPDATE_CHECK=$AUTO_UPDATE_CHECK"
        echo "LOG_LEVEL=$LOG_LEVEL"
        echo ""
        echo "# Attack Settings"
        echo "WORDLIST=\"$WORDLIST\""
        echo "PARALLEL_JOBS=\"$PARALLEL_JOBS\""
        echo "PIN_LENGTH=$PIN_LENGTH"
        echo ""
        echo "# Forensics Settings"
        echo "SNAPSHOT_DIRS=\"$SNAPSHOT_DIRS\""
        echo "PCAP_FILTER=\"$PCAP_FILTER\""
        echo "BACKUP_BEFORE_EXTRACTION=$BACKUP_BEFORE_EXTRACTION"
        echo ""
        echo "# App-Specific Settings"
        echo "WHATSAPP_EXTRACT_MEDIA=$WHATSAPP_EXTRACT_MEDIA"
        echo "BROWSER_EXTRACT_FAVICONS=$BROWSER_EXTRACT_FAVICONS"
        echo "SIGNAL_EXTRACT_ATTACHMENTS=$SIGNAL_EXTRACT_ATTACHMENTS"
        echo ""
        echo "# Advanced Analysis Settings"
        echo "MEMORY_ANALYSIS_DEPTH=\"$MEMORY_ANALYSIS_DEPTH\""
        echo "KERNEL_ANALYSIS_ENABLED=$KERNEL_ANALYSIS_ENABLED"
        echo "MALWARE_SCAN_DEPTH=\"$MALWARE_SCAN_DEPTH\""
        echo "VULN_SCAN_TIMEOUT=$VULN_SCAN_TIMEOUT"
        echo ""
        echo "# Experimental Features"
        echo "FIRMWARE_ANALYSIS_ENABLED=$FIRMWARE_ANALYSIS_ENABLED"
        echo "BIOMETRIC_EXTRACTION_ENABLED=$BIOMETRIC_EXTRACTION_ENABLED"
        echo "SYSTEM_SERVICE_MONITORING=$SYSTEM_SERVICE_MONITORING"
        echo ""
        echo "# Security Settings"
        echo "ENCRYPTED_OUTPUT=$ENCRYPTED_OUTPUT"
        echo "ANONYMOUS_MODE=$ANONYMOUS_MODE"
        echo ""
        echo "# Gatekeeper Settings"
        echo "GATEKEEPER_EXPORT_HASHCAT=$GATEKEEPER_EXPORT_HASHCAT"
        echo ""
        echo "# Bluetooth Settings"
        echo "BLUETOOTH_EXTRACT_ALL=$BLUETOOTH_EXTRACT_ALL"
        echo ""
        echo "# Keystore Settings"
        echo "KEYSTORE_MONITOR_DURATION=$KEYSTORE_MONITOR_DURATION"
    } > "$config_path"

    chmod 600 "$config_path"
    log "INFO" "Configuration saved successfully"
}

# Show current configuration
show_config() {
    echo "Current LockKnife Configuration:"
    echo "================================"
    echo ""
    echo "General Settings:"
    echo "  Debug Mode: $DEBUG_MODE"
    echo "  Max Retries: $MAX_RETRIES"
    echo "  Output Directory: $OUTPUT_DIR"
    echo "  Secure Delete: $SECURE_DELETE"
    echo "  Auto Update Check: $AUTO_UPDATE_CHECK"
    echo "  Log Level: $LOG_LEVEL"
    echo ""
    echo "Attack Settings:"
    echo "  Wordlist: $WORDLIST"
    echo "  Parallel Jobs: $PARALLEL_JOBS"
    echo "  PIN Length: $PIN_LENGTH"
    echo ""
    echo "Forensics Settings:"
    echo "  Snapshot Directories: $SNAPSHOT_DIRS"
    echo "  PCAP Filter: $PCAP_FILTER"
    echo "  Backup Before Extraction: $BACKUP_BEFORE_EXTRACTION"
    echo ""
    echo "Advanced Features:"
    echo "  Memory Analysis Depth: $MEMORY_ANALYSIS_DEPTH"
    echo "  Kernel Analysis: $KERNEL_ANALYSIS_ENABLED"
    echo "  Malware Scan Depth: $MALWARE_SCAN_DEPTH"
    echo "  Vulnerability Scan Timeout: ${VULN_SCAN_TIMEOUT}s"
    echo ""
    echo "Experimental Features:"
    echo "  Firmware Analysis: $FIRMWARE_ANALYSIS_ENABLED"
    echo "  Biometric Extraction: $BIOMETRIC_EXTRACTION_ENABLED"
    echo "  System Service Monitoring: $SYSTEM_SERVICE_MONITORING"
    echo ""
    echo "Security Settings:"
    echo "  Encrypted Output: $ENCRYPTED_OUTPUT"
    echo "  Anonymous Mode: $ANONYMOUS_MODE"
}
