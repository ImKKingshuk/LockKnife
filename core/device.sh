#!/bin/bash

# LockKnife Device Management Module
# Handles Android device detection, connection, and management

# Device information cache (using compatible syntax)
DEVICE_CACHE_SERIAL=""
DEVICE_CACHE_STATE=""
DEVICE_CACHE_MODEL=""
DEVICE_CACHE_VERSION=""
DEVICE_CACHE_API=""
DEVICE_CACHE_ARCH=""

# Device connection states
DEVICE_STATE_DISCONNECTED=0
DEVICE_STATE_CONNECTED=1
DEVICE_STATE_AUTHORIZED=2
DEVICE_STATE_ROOT=3

# Execute command with retry logic
execute_with_retry() {
    local cmd="$1"
    local description="$2"
    local retry_count=0
    local max_retries=${3:-$MAX_RETRIES}
    local result=0
    local start_time
    start_time=$(date +%s)

    while [[ $retry_count -lt $max_retries ]]; do
        log "DEBUG" "Executing: $cmd"
        if [[ "$DEBUG_MODE" = "true" ]]; then
            eval "$cmd"
        else
            eval "$cmd" 2>/dev/null
        fi
        result=$?

        if [[ $result -eq 0 ]]; then
            [[ $retry_count -gt 0 ]] && log "INFO" "$description succeeded after $retry_count retries"
            log_performance "$description" "$start_time" "$(date +%s)"
            return 0
        else
            ((retry_count++))
            log "WARNING" "$description failed (attempt $retry_count/$max_retries)"
            sleep 2
        fi
    done

    log_error "$description failed after $max_retries attempts" "" "$result"
    return 1
}

# Check if ADB is available and functional
check_adb() {
    if ! command -v adb &>/dev/null; then
        log_error "ADB (Android Debug Bridge) not found. Please install ADB and make sure it's in your PATH."
        log_error "Download ADB from: https://developer.android.com/tools/releases/platform-tools"
        return 1
    fi

    # Check ADB version
    local adb_version
    adb_version=$(adb version 2>&1 | head -n1)
    log "INFO" "ADB version: $adb_version"

    # Start ADB server if not running
    if ! adb devices >/dev/null 2>&1; then
        log "INFO" "Starting ADB server..."
        if ! execute_with_retry "adb start-server" "ADB server start"; then
            log_error "Failed to start ADB server"
            return 1
        fi
    fi

    return 0
}

# Get list of connected devices
get_devices() {
    local devices=()
    local device_list
    device_list=$(adb devices 2>/dev/null | grep -v "List of devices" | grep -v "^$" | awk '{print $1}')

    while read -r device; do
        [[ -n "$device" ]] && devices+=("$device")
    done <<< "$device_list"

    echo "${devices[@]}"
}

# Get detailed device information
get_device_info() {
    local device_serial="$1"
    local cache_key="device_info_$device_serial"

    # Check cache first
    if [[ -n "${DEVICE_CACHE[$cache_key]}" ]]; then
        echo "${DEVICE_CACHE[$cache_key]}"
        return 0
    fi

    log "DEBUG" "Fetching device information for $device_serial"

    local device_info=""

    # Get basic device properties
    local props=("ro.product.model" "ro.product.manufacturer" "ro.build.version.release" "ro.build.version.sdk" "ro.build.version.security_patch")

    for prop in "${props[@]}"; do
        local value
        value=$(adb -s "$device_serial" shell getprop "$prop" 2>/dev/null | tr -d '\r')
        device_info+="$prop: $value"$'\n'
    done

    # Get root status
    local root_status
    if adb -s "$device_serial" shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
        root_status="Rooted"
    else
        root_status="Not Rooted"
    fi
    device_info+="Root Status: $root_status"$'\n'

    # Get device storage info
    local storage_info
    storage_info=$(adb -s "$device_serial" shell df /data 2>/dev/null | tail -n1 | awk '{print "Data partition: "$2"KB used, "$4"KB available"}')
    device_info+="$storage_info"$'\n'

    # Cache the result
    DEVICE_CACHE[$cache_key]="$device_info"

    echo "$device_info"
}

# Check device connection state
get_device_state() {
    local device_serial="$1"

    # Check if device is connected
    if ! adb devices 2>/dev/null | grep -q "^$device_serial"; then
        echo $DEVICE_STATE_DISCONNECTED
        return $DEVICE_STATE_DISCONNECTED
    fi

    # Check if device is authorized
    if adb -s "$device_serial" shell 'echo test' 2>&1 | grep -q "device unauthorized"; then
        echo $DEVICE_STATE_CONNECTED
        return $DEVICE_STATE_CONNECTED
    fi

    # Check if device has root access
    if adb -s "$device_serial" shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
        echo $DEVICE_STATE_ROOT
        return $DEVICE_STATE_ROOT
    fi

    # Device is connected and authorized but not rooted
    echo $DEVICE_STATE_AUTHORIZED
    return $DEVICE_STATE_AUTHORIZED
}

# Connect to device via USB
connect_device_usb() {
    local device_serial="$1"

    log_device_operation "USB connection attempt" "$device_serial"

    if ! execute_with_retry "adb connect $device_serial" "Device connection"; then
        log_error "Failed to connect to device: $device_serial"
        return 1
    fi

    # Wait for device to be ready
    sleep 2

    # Verify connection
    if ! adb devices 2>/dev/null | grep -q "^$device_serial"; then
        log_error "Device connection verification failed"
        return 1
    fi

    log_success "Successfully connected to device: $device_serial"
    return 0
}

# Connect to device via IP
connect_device_ip() {
    local device_ip="$1"
    local device_serial="${device_ip}:5555"

    log_device_operation "IP connection attempt" "$device_serial"

    # Enable TCP/IP mode on device
    log "INFO" "Enabling TCP/IP mode on device..."
    if ! execute_with_retry "adb tcpip 5555" "TCP/IP mode enable"; then
        log_error "Failed to enable TCP/IP mode"
        return 1
    fi

    # Disconnect USB and connect via IP
    sleep 2

    if ! execute_with_retry "adb connect $device_serial" "IP connection"; then
        log_error "Failed to connect to device at $device_ip"
        return 1
    fi

    # Verify connection
    if ! adb devices 2>/dev/null | grep -q "^$device_serial"; then
        log_error "IP connection verification failed"
        return 1
    fi

    log_success "Successfully connected to device via IP: $device_ip"
    echo "$device_serial"
    return 0
}

# Wait for device to be ready
wait_for_device() {
    local device_serial="$1"
    local timeout=${2:-30}
    local start_time
    start_time=$(date +%s)

    log "INFO" "Waiting for device $device_serial to be ready..."

    while [[ $(($(date +%s) - start_time)) -lt $timeout ]]; do
        if adb -s "$device_serial" shell 'echo ready' 2>/dev/null | grep -q "ready"; then
            log "INFO" "Device $device_serial is ready"
            return 0
        fi
        sleep 1
    done

    log_error "Device $device_serial did not become ready within $timeout seconds"
    return 1
}

# Select device from available devices
select_device() {
    local devices
    mapfile -t devices < <(get_devices)

    if [[ ${#devices[@]} -eq 0 ]]; then
        log "WARNING" "No devices found connected via USB."

        # Try IP connection
        read -r -p "Would you like to connect to a device via IP? (y/n): " connect_choice
        if [[ "$connect_choice" = "y" ]]; then
            read -r -p "Enter the IP address of the device: " device_ip

            if [[ ! "$device_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                log_error "Invalid IP address format"
                return 1
            fi

            local connected_device
            connected_device=$(connect_device_ip "$device_ip")
            [[ -n "$connected_device" ]] && echo "$connected_device" && return 0
        fi

        log_error "No devices available. Please connect a device and ensure ADB debugging is enabled."
        return 1
    fi

    if [[ ${#devices[@]} -eq 1 ]]; then
        local device="${devices[0]}"
        log "INFO" "Using device: $device"

        # Show device info
        local device_info
        device_info=$(get_device_info "$device")
        echo "Device Information:"
        echo "$device_info" | head -n5

        echo "$device"
        return 0
    fi

    # Multiple devices - let user select
    log "INFO" "Multiple devices found. Please select one:"
    echo ""

    for i in "${!devices[@]}"; do
        local device="${devices[$i]}"
        local device_info
        device_info=$(get_device_info "$device" | head -n1 | cut -d: -f2 | xargs)

        echo "$((i+1)). $device ($device_info)"
    done

    echo ""
    local valid_selection=false
    local num

    while [[ "$valid_selection" = false ]]; do
        read -r -p "Device number (1-${#devices[@]}): " num
        if [[ "$num" =~ ^[0-9]+$ && "$num" -ge 1 && "$num" -le ${#devices[@]} ]]; then
            valid_selection=true
        else
            log_error "Invalid selection. Please enter a number between 1 and ${#devices[@]}."
        fi
    done

    local selected_device="${devices[$((num-1))]}"
    log "INFO" "Selected device: $selected_device"

    echo "$selected_device"
    return 0
}

# Check if device is rooted
check_root() {
    local device_serial="$1"

    log_device_operation "Root check" "$device_serial"

    if execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log_success "Root access detected on device $device_serial"
        return 0
    else
        log "WARNING" "Root access not detected on device $device_serial. Some features may not be available."
        return 1
    fi
}

# Get device Android version
get_android_version() {
    local device_serial="$1"

    local version
    version=$(adb -s "$device_serial" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
    echo "$version"
}

# Get device API level
get_api_level() {
    local device_serial="$1"

    local api_level
    api_level=$(adb -s "$device_serial" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
    echo "$api_level"
}

# Check if device supports a specific feature
device_supports_feature() {
    local device_serial="$1"
    local feature="$2"

    case "$feature" in
        "tcpdump")
            adb -s "$device_serial" shell 'command -v tcpdump' 2>/dev/null | grep -q "tcpdump"
            ;;
        "tshark")
            command -v tshark &>/dev/null
            ;;
        "sqlite3")
            command -v sqlite3 &>/dev/null
            ;;
        "parallel")
            command -v parallel &>/dev/null
            ;;
        "root")
            check_root "$device_serial" &>/dev/null
            ;;
        *)
            # Unknown feature - assume not supported
            return 1
            ;;
    esac
}

# Get device architecture
get_device_arch() {
    local device_serial="$1"

    local arch
    arch=$(adb -s "$device_serial" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
    echo "$arch"
}

# Get device battery status
get_battery_status() {
    local device_serial="$1"

    local battery_info
    battery_info=$(adb -s "$device_serial" shell dumpsys battery 2>/dev/null | grep -E "(level|status|temperature)" | head -3)
    echo "$battery_info"
}

# Reboot device
reboot_device() {
    local device_serial="$1"
    local mode="${2:-normal}"  # normal, recovery, bootloader

    case "$mode" in
        "recovery")
            log_device_operation "Reboot to recovery" "$device_serial"
            execute_with_retry "adb -s $device_serial reboot recovery" "Reboot to recovery"
            ;;
        "bootloader")
            log_device_operation "Reboot to bootloader" "$device_serial"
            execute_with_retry "adb -s $device_serial reboot bootloader" "Reboot to bootloader"
            ;;
        *)
            log_device_operation "Reboot device" "$device_serial"
            execute_with_retry "adb -s $device_serial reboot" "Device reboot"
            ;;
    esac
}

# Push file to device
push_file_to_device() {
    local device_serial="$1"
    local local_path="$2"
    local remote_path="$3"

    log_file_operation "Push to device" "$local_path -> $remote_path"

    if [[ ! -f "$local_path" ]]; then
        log_error "Local file does not exist: $local_path"
        return 1
    fi

    if ! execute_with_retry "adb -s $device_serial push \"$local_path\" \"$remote_path\"" "File push"; then
        log_error "Failed to push file to device"
        return 1
    fi

    log_success "File pushed successfully"
    return 0
}

# Pull file from device
pull_file_from_device() {
    local device_serial="$1"
    local remote_path="$2"
    local local_path="$3"

    log_file_operation "Pull from device" "$remote_path -> $local_path"

    if ! execute_with_retry "adb -s $device_serial pull \"$remote_path\" \"$local_path\"" "File pull"; then
        log_error "Failed to pull file from device"
        return 1
    fi

    log_success "File pulled successfully"
    return 0
}

# Execute shell command on device
execute_shell_cmd() {
    local device_serial="$1"
    local command="$2"
    local description="${3:-Shell command}"

    log_device_operation "Shell command" "$device_serial" "$command"

    if ! execute_with_retry "adb -s $device_serial shell '$command'" "$description"; then
        log_error "Shell command failed"
        return 1
    fi

    return 0
}

# Execute root shell command on device
execute_root_cmd() {
    local device_serial="$1"
    local command="$2"
    local description="${3:-Root command}"

    if ! check_root "$device_serial"; then
        log_error "Root access required for this operation"
        return 1
    fi

    log_device_operation "Root command" "$device_serial" "$command"

    if ! execute_with_retry "adb -s $device_serial shell 'su -c \"$command\"'" "$description"; then
        log_error "Root command failed"
        return 1
    fi

    return 0
}

# Install APK on device
install_apk() {
    local device_serial="$1"
    local apk_path="$2"

    log_file_operation "APK install" "$apk_path"

    if [[ ! -f "$apk_path" ]]; then
        log_error "APK file does not exist: $apk_path"
        return 1
    fi

    if ! execute_with_retry "adb -s $device_serial install \"$apk_path\"" "APK install"; then
        log_error "Failed to install APK"
        return 1
    fi

    log_success "APK installed successfully"
    return 0
}

# Uninstall app from device
uninstall_app() {
    local device_serial="$1"
    local package_name="$2"

    log_device_operation "App uninstall" "$device_serial" "$package_name"

    if ! execute_with_retry "adb -s $device_serial uninstall \"$package_name\"" "App uninstall"; then
        log_error "Failed to uninstall app: $package_name"
        return 1
    fi

    log_success "App uninstalled successfully"
    return 0
}
