#!/bin/bash

# LockKnife Logging Module
# Provides comprehensive logging functionality with multiple levels and outputs

# Log levels (in order of verbosity)
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_WARNING=2
LOG_LEVEL_ERROR=3
LOG_LEVEL_SUCCESS=4

# Color codes for terminal output
LOG_COLOR_DEBUG="\033[36m"      # Cyan
LOG_COLOR_INFO="\033[32m"       # Green
LOG_COLOR_WARNING="\033[33m"    # Yellow
LOG_COLOR_ERROR="\033[31m"      # Red
LOG_COLOR_SUCCESS="\033[92m"    # Bright Green
LOG_COLOR_RESET="\033[0m"       # Reset

# Initialize logging
init_logging() {
    # Set up log file
    LOG_FILE="$TEMP_DIR/lockknife_$(date +%Y%m%d_%H%M%S).log"

    # Create log directory if it doesn't exist
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    [[ ! -d "$log_dir" ]] && mkdir -p "$log_dir"

    # Initialize log file with header
    {
        echo "=================================================="
        echo "LockKnife Log - $(date)"
        echo "Version: $(cat version.txt 2>/dev/null || echo 'unknown')"
        echo "PID: $$"
        echo "User: $(whoami)"
        echo "Host: $(hostname)"
        echo "=================================================="
        echo ""
    } > "$LOG_FILE"

    log "INFO" "LockKnife logging initialized"
    log "DEBUG" "Log file: $LOG_FILE"
}

# Main logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    # Get current log level threshold
    local current_level_var="LOG_LEVEL_${LOG_LEVEL:-INFO}"
    local current_level=${!current_level_var:-1}
    
    local message_level_var="LOG_LEVEL_$level"
    local message_level=${!message_level_var:-1}

    # Format log message
    local log_message="[$timestamp] [$level] $message"
    local color_var="LOG_COLOR_$level"
    local color_code=${!color_var:-$LOG_COLOR_RESET}
    local colored_message="${color_code}${log_message}${LOG_COLOR_RESET}"

    # Always write to log file (except for DEBUG if not in debug mode)
    if [[ "$DEBUG_MODE" = "true" || "$level" != "DEBUG" ]]; then
        echo "$log_message" >> "$LOG_FILE"
    fi

    # Output to console based on log level and debug mode
    case "$level" in
        "DEBUG")
            if [[ "$DEBUG_MODE" = "true" && $message_level -ge $current_level ]]; then
                echo -e "$colored_message"
            fi
            ;;
        "SUCCESS")
            # SUCCESS messages are always shown (like INFO)
            echo -e "$colored_message"
            ;;
        *)
            if [[ $message_level -ge $current_level ]]; then
                echo -e "$colored_message"
            fi
            ;;
    esac
}

# Progress logging functions
log_progress() {
    local current="$1"
    local total="$2"
    local description="${3:-Processing}"

    if [[ $total -gt 0 ]]; then
        local percentage=$((current * 100 / total))
        printf "\r%s: %d/%d (%d%%)" "$description" "$current" "$total" "$percentage"
    else
        printf "\r%s: %d" "$description" "$current"
    fi
}

log_progress_complete() {
    echo ""  # New line after progress
}

# Error logging with context
log_error() {
    local message="$1"
    local context="${2:-}"
    local exit_code="${3:-}"

    log "ERROR" "$message"

    if [[ -n "$context" ]]; then
        log "ERROR" "Context: $context"
    fi

    if [[ -n "$exit_code" ]]; then
        log "ERROR" "Exit code: $exit_code"
    fi

    # Add stack trace in debug mode
    if [[ "$DEBUG_MODE" = "true" ]]; then
        log "DEBUG" "Stack trace:"
        local frame=1
        while caller $frame; do
            ((frame++))
        done | while read -r line; do
            log "DEBUG" "  $line"
        done
    fi
}

# Success logging with timing
log_success() {
    local message="$1"
    local start_time="$2"

    log "SUCCESS" "$message"

    if [[ -n "$start_time" ]]; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log "INFO" "Operation completed in ${duration}s"
    fi
}

# File operation logging
log_file_operation() {
    local operation="$1"
    local file_path="$2"
    local size="${3:-}"

    local size_info=""
    if [[ -n "$size" ]]; then
        size_info=" (${size})"
    fi

    log "INFO" "File $operation: $file_path$size_info"
}

# Device operation logging
log_device_operation() {
    local operation="$1"
    local device_serial="$2"
    local details="${3:-}"

    local details_info=""
    if [[ -n "$details" ]]; then
        details_info=" - $details"
    fi

    log "INFO" "Device operation [$device_serial]: $operation$details_info"
}

# Security event logging
log_security_event() {
    local event="$1"
    local details="$2"
    local severity="${3:-INFO}"

    log "$severity" "Security Event: $event"

    if [[ -n "$details" ]]; then
        log "$severity" "Details: $details"
    fi

    # In anonymous mode, don't log sensitive details
    if [[ "$ANONYMOUS_MODE" = "true" ]]; then
        log "DEBUG" "Anonymous mode: detailed logging suppressed"
    fi
}

# Performance logging
log_performance() {
    local operation="$1"
    local start_time="$2"
    local end_time="$3"
    local metrics="${4:-}"

    local duration=$((end_time - start_time))
    log "INFO" "Performance: $operation completed in ${duration}s"

    if [[ -n "$metrics" ]]; then
        log "DEBUG" "Metrics: $metrics"
    fi
}

# Memory usage logging
log_memory_usage() {
    if command -v free &>/dev/null; then
        local mem_info
        mem_info=$(free -h | grep "^Mem:")
        log "DEBUG" "Memory usage: $mem_info"
    fi
}

# Disk usage logging
log_disk_usage() {
    local path="${1:-$OUTPUT_DIR}"
    if [[ -d "$path" ]]; then
        local disk_info
        disk_info=$(du -sh "$path" 2>/dev/null || echo "unknown")
        log "DEBUG" "Disk usage for $path: $disk_info"
    fi
}

# Rotate log files if they get too large
rotate_logs() {
    local max_size=${1:-10485760}  # 10MB default

    if [[ -f "$LOG_FILE" && $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null) -gt $max_size ]]; then
        local backup_log="${LOG_FILE}.$(date +%Y%m%d_%H%M%S).bak"
        mv "$LOG_FILE" "$backup_log"
        log "INFO" "Log file rotated: $backup_log"

        # Initialize new log file
        init_logging
    fi
}

# Export logs in different formats
export_logs() {
    local format="${1:-txt}"
    local output_file="$OUTPUT_DIR/lockknife_logs_$(date +%Y%m%d_%H%M%S)"

    case "$format" in
        "txt")
            cp "$LOG_FILE" "${output_file}.txt"
            ;;
        "json")
            # Convert log to JSON format
            awk '
            BEGIN { print "[" }
            {
                # Extract timestamp, level, and message
                if (match($0, /\[([0-9-]+ [0-9:]+)\] \[([A-Z]+)\] (.+)/, arr)) {
                    printf "{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\"}", arr[1], arr[2], arr[3]
                    if (getline next > 0) {
                        print ","
                    } else {
                        print ""
                    }
                }
            }
            END { print "]" }
            ' "$LOG_FILE" > "${output_file}.json"
            ;;
        "csv")
            # Convert log to CSV format
            {
                echo "timestamp,level,message"
                awk '
                {
                    if (match($0, /\[([0-9-]+ [0-9:]+)\] \[([A-Z]+)\] (.+)/, arr)) {
                        printf "\"%s\",\"%s\",\"%s\"\n", arr[1], arr[2], arr[3]
                    }
                }
                ' "$LOG_FILE"
            } > "${output_file}.csv"
            ;;
    esac

    log "INFO" "Logs exported to ${output_file}.$format"
}

# Cleanup old log files
cleanup_logs() {
    local days=${1:-30}

    # Remove old log files
    find "$TEMP_DIR" -name "lockknife_*.log" -mtime +$days -delete 2>/dev/null || true
    find "$TEMP_DIR" -name "lockknife_*.bak" -mtime +$days -delete 2>/dev/null || true

    log "DEBUG" "Cleaned up log files older than $days days"
}
