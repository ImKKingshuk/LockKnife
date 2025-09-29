#!/bin/bash

# LockKnife Runtime Analysis Module
# Provides comprehensive runtime analysis capabilities

# Runtime analysis submenu
runtime_analysis_menu() {
    local device_serial="$1"

    while true; do
        echo
        echo "Runtime Analysis"
        echo "================"
        echo "1. Process Monitoring"
        echo "2. Dynamic Behavior Analysis"
        echo "3. System Call Tracing"
        echo "4. Memory Runtime Analysis"
        echo "5. Frida Integration"
        echo "6. Hook Detection"
        echo "7. Anti-Debugging Detection"
        echo "8. Runtime Security Assessment"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) process_monitoring "$device_serial" ;;
            2) dynamic_behavior_analysis "$device_serial" ;;
            3) system_call_tracing "$device_serial" ;;
            4) runtime_memory_analysis "$device_serial" ;;
            5) frida_integration_menu "$device_serial" ;;
            6) hook_detection "$device_serial" ;;
            7) anti_debugging_detection "$device_serial" ;;
            8) runtime_security_assessment "$device_serial" ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Process monitoring and analysis
process_monitoring() {
    local device_serial="$1"

    log "INFO" "Starting process monitoring..."

    # Get running processes
    local process_list
    process_list=$(execute_shell_cmd "$device_serial" "ps -A")

    if [[ -z "$process_list" ]]; then
        log "ERROR" "Failed to retrieve process list"
        return 1
    fi

    # Save process information
    local output_file="$OUTPUT_DIR/process_monitor_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "# LockKnife Process Monitor Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""
        echo "## Running Processes"
        echo "$process_list"
        echo ""

        # Get detailed process information
        echo "## Process Details"
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*([0-9]+)[[:space:]]+.* ]]; then
                local pid="${BASH_REMATCH[1]}"
                local proc_info
                proc_info=$(execute_shell_cmd "$device_serial" "cat /proc/$pid/status 2>/dev/null || echo 'Process $pid not accessible'")
                echo "### PID: $pid"
                echo "$proc_info"
                echo ""
            fi
        done <<< "$process_list"

    } > "$output_file"

    log "SUCCESS" "Process monitoring completed. Results saved to $output_file"

    # Display summary
    echo
    echo "Process Monitoring Summary:"
    echo "=========================="
    local process_count
    process_count=$(echo "$process_list" | wc -l)
    echo "Total running processes: $process_count"
    echo "Results saved to: $output_file"
}

# Dynamic behavior analysis
dynamic_behavior_analysis() {
    local device_serial="$1"

    log "INFO" "Starting dynamic behavior analysis..."

    local output_file="$OUTPUT_DIR/behavior_analysis_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Dynamic Behavior Analysis"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Monitor system calls
        echo "## System Call Monitoring"
        log "INFO" "Monitoring system calls for 10 seconds..."
        local syscall_data
        syscall_data=$(execute_shell_cmd "$device_serial" "timeout 10 strace -c -p 1 2>/dev/null || echo 'strace not available or insufficient permissions'")
        echo "$syscall_data"
        echo ""

        # Monitor network activity
        echo "## Network Activity"
        local netstat_data
        netstat_data=$(execute_shell_cmd "$device_serial" "netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo 'Network tools not available'")
        echo "$netstat_data"
        echo ""

        # Monitor file access
        echo "## File System Activity"
        local file_activity
        file_activity=$(execute_shell_cmd "$device_serial" "lsof 2>/dev/null | head -20 || echo 'lsof not available'")
        echo "$file_activity"
        echo ""

    } > "$output_file"

    log "SUCCESS" "Dynamic behavior analysis completed. Results saved to $output_file"
}

# System call tracing
system_call_tracing() {
    local device_serial="$1"

    echo "System Call Tracing"
    echo "==================="
    echo "1. Trace specific process"
    echo "2. Trace system-wide calls"
    echo "3. Trace network-related calls"
    echo "4. Trace file system calls"
    echo "0. Back"
    echo

    read -r -p "Choice: " choice

    case $choice in
        1)
            read -r -p "Enter PID to trace: " pid
            trace_specific_process "$device_serial" "$pid"
            ;;
        2) trace_system_wide "$device_serial" ;;
        3) trace_network_calls "$device_serial" ;;
        4) trace_filesystem_calls "$device_serial" ;;
        0) return 0 ;;
        *) log "ERROR" "Invalid choice" ;;
    esac
}

# Trace specific process
trace_specific_process() {
    local device_serial="$1"
    local pid="$2"

    log "INFO" "Tracing system calls for PID: $pid"

    local output_file="$OUTPUT_DIR/strace_pid_${pid}_$(date +%Y%m%d_%H%M%S).txt"

    # Use strace to trace the process
    local trace_data
    trace_data=$(execute_shell_cmd "$device_serial" "timeout 30 strace -p $pid 2>&1 || echo 'strace failed or insufficient permissions'")

    {
        echo "# LockKnife System Call Trace"
        echo "# PID: $pid"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""
        echo "$trace_data"
    } > "$output_file"

    log "SUCCESS" "System call tracing completed. Results saved to $output_file"
}

# Frida integration menu
frida_integration_menu() {
    local device_serial="$1"

    echo "Frida Integration"
    echo "================="
    echo "1. Install Frida server"
    echo "2. Start Frida server"
    echo "3. List running applications"
    echo "4. Hook application methods"
    echo "5. Dump application memory"
    echo "6. SSL pinning bypass with Frida"
    echo "0. Back"
    echo

    read -r -p "Choice: " choice

    case $choice in
        1) install_frida_server "$device_serial" ;;
        2) start_frida_server "$device_serial" ;;
        3) frida_list_apps "$device_serial" ;;
        4) frida_hook_methods "$device_serial" ;;
        5) frida_dump_memory "$device_serial" ;;
        6) frida_ssl_bypass "$device_serial" ;;
        0) return 0 ;;
        *) log "ERROR" "Invalid choice" ;;
    esac
}

# Install Frida server on device
install_frida_server() {
    local device_serial="$1"

    log "INFO" "Installing Frida server..."

    # Download Frida server for Android
    local arch
    arch=$(execute_shell_cmd "$device_serial" "getprop ro.product.cpu.abi")

    if [[ -z "$arch" ]]; then
        log "ERROR" "Could not determine device architecture"
        return 1
    fi

    log "INFO" "Device architecture: $arch"

    # For now, we'll provide instructions since we can't download directly
    echo "Frida Server Installation Instructions:"
    echo "======================================"
    echo "1. Download frida-server for $arch from: https://github.com/vfsfitvnm/frida-il2cpp-bridge/releases"
    echo "2. Push to device: adb push frida-server /data/local/tmp/"
    echo "3. Set permissions: adb shell chmod 755 /data/local/tmp/frida-server"
    echo "4. Run: adb shell /data/local/tmp/frida-server &"

    log "INFO" "Frida server installation instructions provided"
}

# Runtime memory analysis
runtime_memory_analysis() {
    local device_serial="$1"

    log "INFO" "Starting runtime memory analysis..."

    local output_file="$OUTPUT_DIR/runtime_memory_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Runtime Memory Analysis"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get memory information
        echo "## System Memory Information"
        local meminfo
        meminfo=$(execute_shell_cmd "$device_serial" "cat /proc/meminfo")
        echo "$meminfo"
        echo ""

        # Get process memory maps for key processes
        echo "## Process Memory Maps"
        local key_processes="system_server zygote surfaceflinger"
        for process in $key_processes; do
            local pid
            pid=$(execute_shell_cmd "$device_serial" "pidof $process 2>/dev/null | head -1")
            if [[ -n "$pid" ]]; then
                echo "### $process (PID: $pid)"
                local maps
                maps=$(execute_shell_cmd "$device_serial" "cat /proc/$pid/maps 2>/dev/null | head -10")
                echo "$maps"
                echo ""
            fi
        done

    } > "$output_file"

    log "SUCCESS" "Runtime memory analysis completed. Results saved to $output_file"
}

# Hook detection
hook_detection() {
    local device_serial="$1"

    log "INFO" "Scanning for hooks and hooking frameworks..."

    local output_file="$OUTPUT_DIR/hook_detection_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Hook Detection Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check for Xposed framework
        echo "## Xposed Framework Detection"
        local xposed_check
        xposed_check=$(execute_shell_cmd "$device_serial" "ls -la /data/data/de.robv.android.xposed.installer/ 2>/dev/null && echo 'Xposed installer found' || echo 'Xposed installer not found'")
        echo "$xposed_check"

        local xposed_modules
        xposed_modules=$(execute_shell_cmd "$device_serial" "find /data/data -name '*xposed*' 2>/dev/null | head -10")
        echo "Xposed modules: $xposed_modules"
        echo ""

        # Check for Magisk modules
        echo "## Magisk Modules"
        local magisk_modules
        magisk_modules=$(execute_shell_cmd "$device_serial" "ls -la /data/adb/modules/ 2>/dev/null || echo 'Magisk modules directory not accessible'")
        echo "$magisk_modules"
        echo ""

        # Check for Substrate
        echo "## Substrate Detection"
        local substrate_check
        substrate_check=$(execute_shell_cmd "$device_serial" "pm list packages | grep -i substrate || echo 'Substrate not found'")
        echo "$substrate_check"
        echo ""

        # Check for Frida
        echo "## Frida Detection"
        local frida_check
        frida_check=$(execute_shell_cmd "$device_serial" "ps | grep -i frida || echo 'Frida server not running'")
        echo "$frida_check"
        echo ""

    } > "$output_file"

    log "SUCCESS"_hook detection completed. Results saved to $output_file"
}

# Anti-debugging detection
anti_debugging_detection() {
    local device_serial="$1"

    log "INFO" "Checking for anti-debugging measures..."

    local output_file="$OUTPUT_DIR/anti_debug_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Anti-Debugging Detection"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check for debugger detection
        echo "## Debugger Detection"
        local debugger_check
        debugger_check=$(execute_shell_cmd "$device_serial" "cat /proc/self/status | grep TracerPid")
        echo "Tracer PID: $debugger_check"

        # Check for common anti-debugging techniques
        echo "## Anti-Debugging Techniques"
        local anti_debug
        anti_debug=$(execute_shell_cmd "$device_serial" "getprop ro.debuggable")
        echo "Debuggable: $anti_debug"

        local secure
        secure=$(execute_shell_cmd "$device_serial" "getprop ro.secure")
        echo "Secure: $secure"
        echo ""

        # Check for ptrace restrictions
        echo "## Ptrace Restrictions"
        local ptrace_scope
        ptrace_scope=$(execute_shell_cmd "$device_serial" "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 'ptrace restrictions not accessible'")
        echo "Ptrace scope: $ptrace_scope"
        echo ""

    } > "$output_file"

    log "SUCCESS" "Anti-debugging detection completed. Results saved to $output_file"
}

# Runtime security assessment
runtime_security_assessment() {
    local device_serial="$1"

    log "INFO" "Performing runtime security assessment..."

    local output_file="$OUTPUT_DIR/runtime_security_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Runtime Security Assessment"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Overall security score calculation
        local security_score=100
        local findings=""

        # Check for running security services
        echo "## Security Services Status"
        local selinux_status
        selinux_status=$(execute_shell_cmd "$device_serial" "getprop ro.boot.selinux")
        echo "SELinux: $selinux_status"
        if [[ "$selinux_status" != "enforcing" ]]; then
            ((security_score -= 20))
            findings="${findings}SELinux not enforcing (-20), "
        fi

        # Check for debuggable applications
        echo "## Debuggable Applications"
        local debuggable_apps
        debuggable_apps=$(execute_shell_cmd "$device_serial" "pm list packages -f | xargs -n1 adb shell dumpsys package | grep -B1 'debuggable=true' | grep 'package:' | wc -l")
        echo "Debuggable apps: $debuggable_apps"
        if [[ "$debuggable_apps" -gt 0 ]]; then
            ((security_score -= 10))
            findings="${findings}Debuggable apps found (-10), "
        fi

        # Check for Frida server
        local frida_running
        frida_running=$(execute_shell_cmd "$device_serial" "ps | grep -c frida")
        echo "Frida servers running: $frida_running"
        if [[ "$frida_running" -gt 0 ]]; then
            ((security_score -= 15))
            findings="${findings}Frida server detected (-15), "
        fi

        echo ""
        echo "## Security Score: $security_score/100"
        echo "## Findings: ${findings:-None}"

        # Recommendations
        echo ""
        echo "## Recommendations"
        if [[ "$selinux_status" != "enforcing" ]]; then
            echo "- Enable SELinux enforcing mode"
        fi
        if [[ "$debuggable_apps" -gt 0 ]]; then
            echo "- Review debuggable applications"
        fi
        if [[ "$frida_running" -gt 0 ]]; then
            echo "- Investigate Frida server usage"
        fi

    } > "$output_file"

    log "SUCCESS" "Runtime security assessment completed. Score: $security_score/100. Results saved to $output_file"

    # Display summary
    echo
    echo "Runtime Security Assessment:"
    echo "==========================="
    echo "Security Score: $security_score/100"
    if [[ -n "$findings" ]]; then
        echo "Issues Found: ${findings%, }"
    else
        echo "No significant issues found"
    fi
}
