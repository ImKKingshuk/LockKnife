#!/bin/bash

# LockKnife Kernel & SELinux Analysis Module
# Provides comprehensive kernel and security policy analysis

# Kernel analysis types
KERNEL_ANALYSIS_MODULES=1
KERNEL_ANALYSIS_SYSCALLS=2
KERNEL_ANALYSIS_PARAMETERS=3
KERNEL_ANALYSIS_SECURITY=4

# SELinux analysis types
SELINUX_ANALYSIS_POLICY=1
SELINUX_ANALYSIS_CONTEXTS=2
SELINUX_ANALYSIS_AVC=3
SELINUX_ANALYSIS_DENIALS=4

# Analyze loaded kernel modules
analyze_kernel_modules() {
    local device_serial="$1"
    local output_file="$OUTPUT_DIR/kernel_modules_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing loaded kernel modules"

    if ! device_supports_feature "$device_serial" "root"; then
        log "ERROR" "Root access required for kernel module analysis"
        return 1
    fi

    # Get loaded modules
    local modules_info
    modules_info=$(execute_root_cmd "$device_serial" "lsmod" "Loaded modules")

    # Get module details from /proc/modules
    local proc_modules
    proc_modules=$(execute_root_cmd "$device_serial" "cat /proc/modules" "Proc modules")

    # Get module information from /sys/module
    local sys_modules
    sys_modules=$(execute_root_cmd "$device_serial" "find /sys/module -maxdepth 1 -type d | tail -n +2 | xargs basename" "Sys modules")

    {
        echo "# Kernel Modules Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Loaded Modules Summary"
        echo "Total modules loaded: $(echo "$modules_info" | wc -l)"
        echo ""

        echo "## Module Details"
        echo "$modules_info" | while read -r line; do
            if [[ -n "$line" ]]; then
                local module_name size use_count deps
                module_name=$(echo "$line" | awk '{print $1}')
                size=$(echo "$line" | awk '{print $2}')
                use_count=$(echo "$line" | awk '{print $3}')

                echo "### $module_name"
                echo "- Size: $((size / 1024)) KB"
                echo "- Use count: $use_count"

                # Check if module has parameters
                local mod_params
                mod_params=$(execute_root_cmd "$device_serial" "cat /sys/module/$module_name/parameters/* 2>/dev/null" "Module parameters" 2>/dev/null || echo "")
                if [[ -n "$mod_params" ]]; then
                    echo "- Parameters:"
                    echo "$mod_params" | while read -r param; do
                        echo "  $param"
                    done
                fi

                # Check for suspicious modules
                case "$module_name" in
                    *"rootkit"*|*"hide"*|*"hook"*|*"inject"*)
                        echo "⚠️  SUSPICIOUS MODULE DETECTED: $module_name"
                        ;;
                esac

                echo ""
            fi
        done

        echo "## Module Dependencies"
        echo "$proc_modules" | while read -r line; do
            local module deps
            module=$(echo "$line" | cut -d' ' -f1)
            deps=$(echo "$line" | cut -d' ' -f4)
            if [[ "$deps" != "-" && -n "$deps" ]]; then
                echo "- $module depends on: $deps"
            fi
        done

    } > "$output_file"

    log "SUCCESS" "Kernel modules analysis saved to $output_file"
    return 0
}

# Analyze system calls
analyze_system_calls() {
    local device_serial="$1"
    local output_file="$OUTPUT_DIR/system_calls_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing system call usage"

    # Get syscall statistics
    local syscall_stats
    syscall_stats=$(execute_shell_cmd "$device_serial" "cat /proc/*/task/*/syscall 2>/dev/null | head -50" "Syscall stats" 2>/dev/null || echo "")

    # Get syscall table
    local syscall_table
    syscall_table=$(execute_shell_cmd "$device_serial" "ausyscall --dump 2>/dev/null | head -50" "Syscall table" 2>/dev/null || echo "")

    {
        echo "# System Call Analysis"
        echo "# Generated: $(date)"
        echo ""

        if [[ -n "$syscall_stats" ]]; then
            echo "## System Call Statistics"
            echo "\`\`\`"
            echo "$syscall_stats"
            echo "\`\`\`"
            echo ""
        fi

        if [[ -n "$syscall_table" ]]; then
            echo "## System Call Table (Sample)"
            echo "\`\`\`"
            echo "$syscall_table"
            echo "\`\`\`\`"
            echo ""
        fi

        echo "## Common System Calls Analysis"

        # Analyze for suspicious syscall patterns
        local suspicious_patterns=("ptrace" "execve" "mprotect" "mmap")

        for pattern in "${suspicious_patterns[@]}"; do
            local count
            count=$(echo "$syscall_stats" | grep -c "$pattern" 2>/dev/null || echo "0")
            echo "- $pattern calls: $count"

            if [[ $count -gt 100 ]]; then
                echo "  ⚠️  HIGH FREQUENCY: $pattern may indicate suspicious activity"
            fi
        done

    } > "$output_file"

    log "SUCCESS" "System call analysis saved to $output_file"
    return 0
}

# Analyze kernel parameters
analyze_kernel_parameters() {
    local device_serial="$1"
    local output_file="$OUTPUT_DIR/kernel_parameters_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing kernel parameters"

    # Get kernel command line
    local cmdline
    cmdline=$(execute_shell_cmd "$device_serial" "cat /proc/cmdline" "Kernel cmdline")

    # Get sysctl parameters
    local sysctl_params
    sysctl_params=$(execute_shell_cmd "$device_serial" "sysctl -a 2>/dev/null | head -100" "Sysctl params")

    # Get kernel version
    local kernel_version
    kernel_version=$(execute_shell_cmd "$device_serial" "uname -a" "Kernel version")

    {
        echo "# Kernel Parameters Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Kernel Information"
        echo "Kernel version: $kernel_version"
        echo ""

        echo "## Kernel Command Line"
        echo "\`\`\`"
        echo "$cmdline"
        echo "\`\`\`"
        echo ""

        # Analyze cmdline for security features
        echo "## Security Features in Command Line"
        if echo "$cmdline" | grep -q "selinux=1"; then
            echo "✓ SELinux enabled"
        else
            echo "✗ SELinux not explicitly enabled"
        fi

        if echo "$cmdline" | grep -q "enforcing=1"; then
            echo "✓ SELinux enforcing mode"
        elif echo "$cmdline" | grep -q "permissive"; then
            echo "⚠️  SELinux permissive mode"
        fi

        if echo "$cmdline" | grep -q "audit=1"; then
            echo "✓ Audit enabled"
        fi

        if echo "$cmdline" | grep -q "grsecurity"; then
            echo "✓ Grsecurity patches detected"
        fi

        echo ""

        echo "## System Control Parameters (Sample)"
        echo "\`\`\`"
        echo "$sysctl_params"
        echo "\`\`\`"
        echo ""

        echo "## Security-Related Parameters"

        # Extract security parameters
        echo "$sysctl_params" | grep -E "(kernel\.|net\.|fs\.|security\.)" | while read -r line; do
            local param value
            param=$(echo "$line" | cut -d'=' -f1)
            value=$(echo "$line" | cut -d'=' -f2-)

            case "$param" in
                "kernel.kptr_restrict")
                    if [[ "$value" -eq 2 ]]; then
                        echo "✓ Kernel pointer restriction: Full"
                    elif [[ "$value" -eq 1 ]]; then
                        echo "⚠️  Kernel pointer restriction: Partial"
                    else
                        echo "✗ Kernel pointer restriction: Disabled"
                    fi
                    ;;
                "kernel.dmesg_restrict")
                    if [[ "$value" -eq 1 ]]; then
                        echo "✓ Dmesg access restricted"
                    else
                        echo "✗ Dmesg access not restricted"
                    fi
                    ;;
                "kernel.panic_on_oops")
                    if [[ "$value" -eq 1 ]]; then
                        echo "✓ Panic on oops enabled"
                    else
                        echo "⚠️  Panic on oops disabled"
                    fi
                    ;;
                "net.ipv4.tcp_syncookies")
                    if [[ "$value" -eq 1 ]]; then
                        echo "✓ TCP syncookies enabled"
                    else
                        echo "✗ TCP syncookies disabled"
                    fi
                    ;;
            esac
        done

    } > "$output_file"

    log "SUCCESS" "Kernel parameters analysis saved to $output_file"
    return 0
}

# Analyze SELinux policy
analyze_selinux_policy() {
    local device_serial="$1"
    local output_file="$OUTPUT_DIR/selinux_policy_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing SELinux policy"

    # Check SELinux status
    local selinux_status
    selinux_status=$(execute_shell_cmd "$device_serial" "getenforce 2>/dev/null || echo 'Not available'" "SELinux status")

    # Get SELinux contexts
    local contexts
    contexts=$(execute_shell_cmd "$device_serial" "ls -laZ / 2>/dev/null | head -20" "SELinux contexts")

    # Get SELinux policy version
    local policy_version
    policy_version=$(execute_root_cmd "$device_serial" "sestatus -v 2>/dev/null || echo 'Not available'" "Policy version")

    {
        echo "# SELinux Policy Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## SELinux Status"
        echo "Current mode: $selinux_status"
        echo ""

        if [[ "$selinux_status" == "Enforcing" ]]; then
            echo "✓ SELinux is in enforcing mode"
        elif [[ "$selinux_status" == "Permissive" ]]; then
            echo "⚠️  SELinux is in permissive mode (logging violations but not enforcing)"
        else
            echo "✗ SELinux is disabled"
        fi
        echo ""

        echo "## SELinux Contexts (Sample)"
        echo "\`\`\`"
        echo "$contexts"
        echo "\`\`\`"
        echo ""

        echo "## Policy Information"
        echo "\`\`\`"
        echo "$policy_version"
        echo "\`\`\`"
        echo ""

    } > "$output_file"

    log "SUCCESS" "SELinux policy analysis saved to $output_file"
    return 0
}

# Analyze SELinux contexts
analyze_selinux_contexts() {
    local device_serial="$1"
    local output_file="$OUTPUT_DIR/selinux_contexts_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing SELinux security contexts"

    # Get process contexts
    local process_contexts
    process_contexts=$(execute_shell_cmd "$device_serial" "ps -AZ | head -20" "Process contexts")

    # Get file contexts
    local file_contexts
    local important_files=("/system" "/data" "/vendor" "/proc" "/sys")
    file_contexts=""
    for dir in "${important_files[@]}"; do
        local context
        context=$(execute_shell_cmd "$device_serial" "ls -ldZ $dir 2>/dev/null" "File context for $dir")
        file_contexts+="$context"$'\n'
    done

    {
        echo "# SELinux Contexts Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Process Contexts"
        echo "\`\`\`"
        echo "$process_contexts"
        echo "\`\`\`"
        echo ""

        echo "## File Contexts"
        echo "\`\`\`"
        echo "$file_contexts"
        echo "\`\`\`"
        echo ""

        echo "## Context Analysis"

        # Analyze process contexts for anomalies
        echo "$process_contexts" | while read -r line; do
            local context
            context=$(echo "$line" | awk '{print $1}')
            if [[ "$context" == *"unconfined"* ]]; then
                echo "⚠️  Unconfined process context detected: $line"
            fi
        done

    } > "$output_file"

    log "SUCCESS" "SELinux contexts analysis saved to $output_file"
    return 0
}

# Analyze SELinux AVC denials
analyze_selinux_avc() {
    local device_serial="$1"
    local output_file="$OUTPUT_DIR/selinux_avc_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing SELinux AVC denials"

    # Get recent AVC denials from dmesg
    local avc_denials
    avc_denials=$(execute_root_cmd "$device_serial" "dmesg | grep 'avc:' | tail -50" "AVC denials")

    # Get SELinux audit logs if available
    local audit_logs
    audit_logs=$(execute_root_cmd "$device_serial" "cat /var/log/audit/audit.log 2>/dev/null | grep 'avc' | tail -20" "Audit logs")

    {
        echo "# SELinux AVC Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Recent AVC Denials (dmesg)"
        if [[ -n "$avc_denials" ]]; then
            echo "\`\`\`"
            echo "$avc_denials"
            echo "\`\`\`"
        else
            echo "No recent AVC denials found in dmesg"
        fi
        echo ""

        echo "## SELinux Audit Logs"
        if [[ -n "$audit_logs" ]]; then
            echo "\`\`\`"
            echo "$audit_logs"
            echo "\`\`\`"
        else
            echo "No SELinux audit logs available"
        fi
        echo ""

        echo "## Denial Analysis"

        if [[ -n "$avc_denials" ]]; then
            local denial_count
            denial_count=$(echo "$avc_denials" | wc -l)
            echo "Total AVC denials in recent logs: $denial_count"

            # Analyze denial types
            local permission_denials
            permission_denials=$(echo "$avc_denials" | grep -c "denied" 2>/dev/null || echo "0")
            echo "Permission denials: $permission_denials"

            # Look for common denial patterns
            local common_denials
            common_denials=$(echo "$avc_denials" | grep "denied" | awk '{print $3}' | sort | uniq -c | sort -nr | head -10)
            echo ""
            echo "## Most Common Denial Types"
            echo "$common_denials"
        fi

    } > "$output_file"

    log "SUCCESS" "SELinux AVC analysis saved to $output_file"
    return 0
}

# Analyze kernel security features
analyze_kernel_security() {
    local device_serial="$1"
    local output_file="$OUTPUT_DIR/kernel_security_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing kernel security features"

    # Check for various kernel security features
    local security_features=""

    # Check for ASLR
    local aslr_status
    aslr_status=$(execute_root_cmd "$device_serial" "cat /proc/sys/kernel/randomize_va_space" "ASLR status" 2>/dev/null || echo "0")

    # Check for kASLR (kernel ASLR)
    local kaslr_status
    kaslr_status=$(execute_shell_cmd "$device_serial" "grep -q 'CONFIG_RANDOMIZE_BASE=y' /proc/config.gz 2>/dev/null && echo 'Enabled' || echo 'Unknown'" "kASLR status")

    # Check for SMEP/SMAP
    local smep_smap
    smep_smap=$(execute_root_cmd "$device_serial" "grep -E '(smep|smap)' /proc/cpuinfo" "SMEP/SMAP status" 2>/dev/null || echo "")

    # Check for kernel stack protection
    local stack_protection
    stack_protection=$(execute_shell_cmd "$device_serial" "grep -q 'CONFIG_STACKPROTECTOR=y' /proc/config.gz 2>/dev/null && echo 'Enabled' || echo 'Unknown'" "Stack protection")

    # Check for hardened usercopy
    local hardened_usercopy
    hardened_usercopy=$(execute_shell_cmd "$device_serial" "grep -q 'CONFIG_HARDENED_USERCOPY=y' /proc/config.gz 2>/dev/null && echo 'Enabled' || echo 'Unknown'" "Hardened usercopy")

    {
        echo "# Kernel Security Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Address Space Layout Randomization (ASLR)"
        case "$aslr_status" in
            "0") echo "✗ ASLR disabled" ;;
            "1") echo "⚠️  ASLR enabled for stack/heap/mmap" ;;
            "2") echo "✓ ASLR enabled for everything" ;;
            *) echo "? ASLR status unknown" ;;
        esac
        echo ""

        echo "## Kernel ASLR (kASLR)"
        echo "Status: $kaslr_status"
        echo ""

        echo "## CPU Security Features"
        if [[ -n "$smep_smap" ]]; then
            echo "✓ CPU security features detected:"
            echo "$smep_smap"
        else
            echo "? CPU security features status unknown"
        fi
        echo ""

        echo "## Kernel Hardening Features"
        echo "Stack protection: $stack_protection"
        echo "Hardened usercopy: $hardened_usercopy"
        echo ""

        echo "## Security Assessment"

        local score=0
        local total=5

        [[ "$aslr_status" == "2" ]] && ((score++))
        [[ "$kaslr_status" == "Enabled" ]] && ((score++))
        [[ -n "$smep_smap" ]] && ((score++))
        [[ "$stack_protection" == "Enabled" ]] && ((score++))
        [[ "$hardened_usercopy" == "Enabled" ]] && ((score++))

        local percentage=$((score * 100 / total))
        echo "Security Score: $score/$total ($percentage%)"

        if [[ $percentage -ge 80 ]]; then
            echo "✓ Good kernel security posture"
        elif [[ $percentage -ge 60 ]]; then
            echo "⚠️  Moderate kernel security"
        else
            echo "✗ Poor kernel security posture"
        fi

    } > "$output_file"

    log "SUCCESS" "Kernel security analysis saved to $output_file"
    return 0
}

# Kernel and SELinux analysis menu
kernel_system_analysis() {
    local device_serial="$1"

    while true; do
        echo
        echo "Kernel & SELinux Analysis"
        echo "========================="
        echo "1. Analyze Kernel Modules"
        echo "2. Analyze System Calls"
        echo "3. Analyze Kernel Parameters"
        echo "4. Analyze Kernel Security Features"
        echo "5. Analyze SELinux Policy"
        echo "6. Analyze SELinux Contexts"
        echo "7. Analyze SELinux AVC Denials"
        echo "8. Full Kernel Security Assessment"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) analyze_kernel_modules "$device_serial" ;;
            2) analyze_system_calls "$device_serial" ;;
            3) analyze_kernel_parameters "$device_serial" ;;
            4) analyze_kernel_security "$device_serial" ;;
            5) analyze_selinux_policy "$device_serial" ;;
            6) analyze_selinux_contexts "$device_serial" ;;
            7) analyze_selinux_avc "$device_serial" ;;
            8) full_kernel_assessment "$device_serial" ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Full kernel security assessment
full_kernel_assessment() {
    local device_serial="$1"
    local output_dir="$OUTPUT_DIR/kernel_assessment_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Performing full kernel security assessment"

    mkdir -p "$output_dir"

    # Run all kernel analyses
    analyze_kernel_modules "$device_serial"
    mv "$OUTPUT_DIR/kernel_modules_"* "$output_dir/" 2>/dev/null

    analyze_kernel_parameters "$device_serial"
    mv "$OUTPUT_DIR/kernel_parameters_"* "$output_dir/" 2>/dev/null

    analyze_kernel_security "$device_serial"
    mv "$OUTPUT_DIR/kernel_security_"* "$output_dir/" 2>/dev/null

    analyze_selinux_policy "$device_serial"
    mv "$OUTPUT_DIR/selinux_policy_"* "$output_dir/" 2>/dev/null

    analyze_selinux_avc "$device_serial"
    mv "$OUTPUT_DIR/selinux_avc_"* "$output_dir/" 2>/dev/null

    # Create comprehensive report
    local report_file="$output_dir/comprehensive_report.txt"
    {
        echo "# Comprehensive Kernel Security Assessment"
        echo "# Generated: $(date)"
        echo ""

        echo "## Assessment Summary"
        echo ""

        # Aggregate findings from all reports
        echo "### Kernel Modules"
        local mod_file
        mod_file=$(find "$output_dir" -name "kernel_modules_*.txt" | head -1)
        if [[ -f "$mod_file" ]]; then
            local mod_count
            mod_count=$(grep "Total modules loaded:" "$mod_file" | awk '{print $4}' || echo "unknown")
            echo "- Total modules: $mod_count"

            local suspicious
            suspicious=$(grep -c "SUSPICIOUS MODULE" "$mod_file" 2>/dev/null || echo "0")
            if [[ $suspicious -gt 0 ]]; then
                echo "⚠️  Suspicious modules detected: $suspicious"
            fi
        fi
        echo ""

        echo "### Kernel Security"
        local sec_file
        sec_file=$(find "$output_dir" -name "kernel_security_*.txt" | head -1)
        if [[ -f "$sec_file" ]]; then
            local score
            score=$(grep "Security Score:" "$sec_file" | head -1 || echo "")
            echo "$score"
        fi
        echo ""

        echo "### SELinux Status"
        local selinux_file
        selinux_file=$(find "$output_dir" -name "selinux_policy_*.txt" | head -1)
        if [[ -f "$selinux_file" ]]; then
            local status
            status=$(grep "Current mode:" "$selinux_file" | cut -d: -f2 | xargs || echo "unknown")
            case "$status" in
                "Enforcing") echo "✓ SELinux enforcing" ;;
                "Permissive") echo "⚠️  SELinux permissive" ;;
                "Disabled") echo "✗ SELinux disabled" ;;
                *) echo "? SELinux status unknown" ;;
            esac
        fi
        echo ""

        echo "## Recommendations"
        echo ""

        # Generate recommendations based on findings
        if [[ -f "$sec_file" ]]; then
            local aslr_status
            aslr_status=$(grep "ASLR" "$sec_file" | grep -c "disabled\|Disabled" || echo "0")
            if [[ $aslr_status -gt 0 ]]; then
                echo "- Enable ASLR for better memory protection"
            fi
        fi

        if [[ -f "$selinux_file" ]]; then
            local selinux_mode
            selinux_mode=$(grep "Current mode:" "$selinux_file" | cut -d: -f2 | xargs)
            if [[ "$selinux_mode" != "Enforcing" ]]; then
                echo "- Enable SELinux in enforcing mode"
            fi
        fi

        echo "- Regularly audit kernel modules for unauthorized changes"
        echo "- Monitor SELinux AVC denials for policy violations"
        echo "- Keep kernel updated with latest security patches"

    } > "$report_file"

    log "SUCCESS" "Full kernel assessment completed. Results saved to $output_dir"
}
