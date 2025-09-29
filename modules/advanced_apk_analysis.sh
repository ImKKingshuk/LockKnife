#!/bin/bash

# LockKnife Advanced APK Analysis Module
# Provides comprehensive APK static analysis capabilities

# Advanced APK analysis submenu
advanced_apk_analysis_menu() {
    local device_serial="$1"

    while true; do
        echo
        echo "Advanced APK Analysis"
        echo "====================="
        echo "1. APK Static Analysis"
        echo "2. Permission Analysis"
        echo "3. Manifest Analysis"
        echo "4. Code Analysis (DEX/SMALI)"
        echo "5. Security Vulnerability Scan"
        echo "6. Malware Detection"
        echo "7. Dependency Analysis"
        echo "8. Signature Verification"
        echo "9. Comparative Analysis"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) apk_static_analysis "$device_serial" ;;
            2) apk_permission_analysis "$device_serial" ;;
            3) apk_manifest_analysis "$device_serial" ;;
            4) apk_code_analysis "$device_serial" ;;
            5) apk_vulnerability_scan "$device_serial" ;;
            6) apk_malware_detection "$device_serial" ;;
            7) apk_dependency_analysis "$device_serial" ;;
            8) apk_signature_verification "$device_serial" ;;
            9) apk_comparative_analysis "$device_serial" ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# APK static analysis
apk_static_analysis() {
    local device_serial="$1"

    read -r -p "Enter package name to analyze: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    # Get APK path
    local apk_path
    apk_path=$(execute_shell_cmd "$device_serial" "pm path $package_name 2>/dev/null | sed 's/package://'")

    if [[ -z "$apk_path" ]]; then
        log "ERROR" "Could not find APK for package: $package_name"
        return 1
    fi

    log "INFO" "Performing static analysis of $package_name"
    log "INFO" "APK path: $apk_path"

    local output_file="$OUTPUT_DIR/apk_static_analysis_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Static Analysis Report"
        echo "# Package: $package_name"
        echo "# APK Path: $apk_path"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Basic APK information
        echo "## APK Basic Information"
        local apk_size
        apk_size=$(execute_shell_cmd "$device_serial" "ls -lh $apk_path | awk '{print \$5}'")
        echo "Size: $apk_size"

        local apk_date
        apk_date=$(execute_shell_cmd "$device_serial" "ls -l $apk_path | awk '{print \$6,\$7,\$8}'")
        echo "Modified: $apk_date"
        echo ""

        # File structure analysis
        echo "## APK File Structure"
        local file_list
        file_list=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | tail -20")
        echo "$file_list"
        echo ""

        # Native libraries
        echo "## Native Libraries"
        local native_libs
        native_libs=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep '\.so$' | wc -l")
        echo "Native libraries found: $native_libs"

        if [[ "$native_libs" -gt 0 ]]; then
            echo "Native library details:"
            execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep '\.so$' | head -10"
        fi
        echo ""

        # Assets analysis
        echo "## Assets Analysis"
        local assets_info
        assets_info=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep '^.*assets/' | wc -l")
        echo "Asset files: $assets_info"

        local res_info
        res_info=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep '^.*res/' | wc -l")
        echo "Resource files: $res_info"
        echo ""

    } > "$output_file"

    log "SUCCESS" "APK static analysis completed. Results saved to $output_file"
}

# APK permission analysis
apk_permission_analysis() {
    local device_serial="$1"

    read -r -p "Enter package name to analyze: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    log "INFO" "Analyzing permissions for $package_name"

    local output_file="$OUTPUT_DIR/apk_permissions_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Permission Analysis"
        echo "# Package: $package_name"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get requested permissions
        echo "## Requested Permissions"
        local permissions
        permissions=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'requested permissions:' -A 100 | grep 'permission:' | sed 's/.*permission://'")
        echo "$permissions"
        echo ""

        # Analyze permission risks
        echo "## Permission Risk Analysis"
        local high_risk_perms=""
        local medium_risk_perms=""
        local low_risk_perms=""

        while IFS= read -r perm; do
            case "$perm" in
                *CAMERA*|*LOCATION*|*MICROPHONE*|*SMS*|*CALL_LOG*|*CONTACTS*)
                    high_risk_perms="${high_risk_perms}$perm\n"
                    ;;
                *STORAGE*|*PHONE*|*CALENDAR*)
                    medium_risk_perms="${medium_risk_perms}$perm\n"
                    ;;
                *)
                    low_risk_perms="${low_risk_perms}$perm\n"
                    ;;
            esac
        done <<< "$permissions"

        echo "### High Risk Permissions:"
        echo -e "$high_risk_perms"
        echo "### Medium Risk Permissions:"
        echo -e "$medium_risk_perms"
        echo "### Low Risk Permissions:"
        echo -e "$low_risk_perms"

        # Permission summary
        local total_perms
        total_perms=$(echo "$permissions" | wc -l)
        local high_count
        high_count=$(echo -e "$high_risk_perms" | grep -c ".")
        local medium_count
        medium_count=$(echo -e "$medium_risk_perms" | grep -c ".")

        echo ""
        echo "## Summary"
        echo "Total permissions: $total_perms"
        echo "High risk: $high_count"
        echo "Medium risk: $medium_count"
        echo "Low risk: $((total_perms - high_count - medium_count))"

        # Risk score
        local risk_score=$((high_count * 3 + medium_count * 2))
        echo "Risk Score: $risk_score/30"

        if [[ $risk_score -ge 20 ]]; then
            echo "⚠️ HIGH RISK: Review permissions carefully"
        elif [[ $risk_score -ge 10 ]]; then
            echo "⚠️ MEDIUM RISK: Some permissions require attention"
        else
            echo "✅ LOW RISK: Permissions appear reasonable"
        fi

    } > "$output_file"

    log "SUCCESS" "APK permission analysis completed. Results saved to $output_file"
}

# APK manifest analysis
apk_manifest_analysis() {
    local device_serial="$1"

    read -r -p "Enter package name to analyze: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    # Get APK path
    local apk_path
    apk_path=$(execute_shell_cmd "$device_serial" "pm path $package_name 2>/dev/null | sed 's/package://'")

    if [[ -z "$apk_path" ]]; then
        log "ERROR" "Could not find APK for package: $package_name"
        return 1
    fi

    log "INFO" "Analyzing AndroidManifest.xml for $package_name"

    local output_file="$OUTPUT_DIR/apk_manifest_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Manifest Analysis"
        echo "# Package: $package_name"
        echo "# APK Path: $apk_path"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Extract and analyze AndroidManifest.xml
        echo "## AndroidManifest.xml Analysis"
        local manifest_xml
        manifest_xml=$(execute_shell_cmd "$device_serial" "unzip -p $apk_path AndroidManifest.xml 2>/dev/null | head -50")

        if [[ -n "$manifest_xml" ]]; then
            echo "Manifest content (first 50 lines):"
            echo "$manifest_xml"
            echo ""
        else
            echo "Could not extract AndroidManifest.xml (likely binary format)"
            echo ""
        fi

        # Get app info from dumpsys
        echo "## Application Information"
        local app_info
        app_info=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -E '(versionName|versionCode|firstInstallTime|lastUpdateTime|dataDir|apkDir)'")
        echo "$app_info"
        echo ""

        # Component analysis
        echo "## Application Components"
        local activities
        activities=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'Activity:' | wc -l")
        echo "Activities: $activities"

        local services
        services=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'Service:' | wc -l")
        echo "Services: $services"

        local receivers
        receivers=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'Receiver:' | wc -l")
        echo "Broadcast Receivers: $receivers"

        local providers
        providers=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'Provider:' | wc -l")
        echo "Content Providers: $providers"
        echo ""

        # Intent filters
        echo "## Intent Filters"
        local intent_filters
        intent_filters=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -A 5 'filter' | head -20")
        echo "$intent_filters"
        echo ""

    } > "$output_file"

    log "SUCCESS" "APK manifest analysis completed. Results saved to $output_file"
}

# APK code analysis
apk_code_analysis() {
    local device_serial="$1"

    read -r -p "Enter package name to analyze: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    echo "Code Analysis Options:"
    echo "======================"
    echo "1. DEX file analysis"
    echo "2. SMALI decompilation"
    echo "3. Method signature analysis"
    echo "4. String extraction"
    echo "5. Class hierarchy analysis"
    echo "0. Back"
    echo

    read -r -p "Choice: " choice

    case $choice in
        1) analyze_dex_files "$device_serial" "$package_name" ;;
        2) smali_decompilation "$device_serial" "$package_name" ;;
        3) method_signature_analysis "$device_serial" "$package_name" ;;
        4) string_extraction "$device_serial" "$package_name" ;;
        5) class_hierarchy_analysis "$device_serial" "$package_name" ;;
        0) return 0 ;;
        *) log "ERROR" "Invalid choice" ;;
    esac
}

# Analyze DEX files
analyze_dex_files() {
    local device_serial="$1"
    local package_name="$2"

    log "INFO" "Analyzing DEX files for $package_name"

    local output_file="$OUTPUT_DIR/dex_analysis_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife DEX File Analysis"
        echo "# Package: $package_name"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get APK path
        local apk_path
        apk_path=$(execute_shell_cmd "$device_serial" "pm path $package_name 2>/dev/null | sed 's/package://'")

        if [[ -z "$apk_path" ]]; then
            echo "ERROR: Could not find APK path"
            return 1
        fi

        echo "## DEX File Information"
        local dex_files
        dex_files=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep '\.dex$'")
        echo "$dex_files"
        echo ""

        # DEX file sizes
        echo "## DEX File Sizes"
        execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep '\.dex$' | awk '{print \$1,\$4}'"
        echo ""

        # Basic DEX analysis (if dexdump available)
        echo "## DEX Dump Analysis"
        local dex_analysis
        dex_analysis=$(execute_shell_cmd "$device_serial" "dexdump -f $apk_path 2>/dev/null | head -20 || echo 'dexdump not available on device'")
        echo "$dex_analysis"
        echo ""

    } > "$output_file"

    log "SUCCESS" "DEX file analysis completed. Results saved to $output_file"
}

# APK vulnerability scanning
apk_vulnerability_scan() {
    local device_serial="$1"

    read -r -p "Enter package name to scan: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    log "INFO" "Scanning $package_name for vulnerabilities"

    local output_file="$OUTPUT_DIR/vulnerability_scan_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Vulnerability Scan"
        echo "# Package: $package_name"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get APK path
        local apk_path
        apk_path=$(execute_shell_cmd "$device_serial" "pm path $package_name 2>/dev/null | sed 's/package://'")

        if [[ -z "$apk_path" ]]; then
            echo "ERROR: Could not find APK path"
            return 1
        fi

        echo "## Vulnerability Assessment"
        echo ""

        # Check for debuggable flag
        echo "### Debuggable Application Check"
        local debuggable
        debuggable=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -c 'DEBUGGABLE'")
        if [[ "$debuggable" -gt 0 ]]; then
            echo "⚠️ VULNERABILITY: Application is debuggable"
            echo "Impact: Can be attached to debugger, sensitive data exposure"
        else
            echo "✅ SECURE: Application is not debuggable"
        fi
        echo ""

        # Check for backup flag
        echo "### Backup Flag Check"
        local backup_flag
        backup_flag=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -c 'ALLOW_BACKUP'")
        if [[ "$backup_flag" -gt 0 ]]; then
            echo "⚠️ VULNERABILITY: Application allows backup"
            echo "Impact: Sensitive data may be backed up and extracted"
        else
            echo "✅ SECURE: Application does not allow backup"
        fi
        echo ""

        # Check permissions for sensitive data access
        echo "### Sensitive Permission Analysis"
        local dangerous_perms=""
        local perms_list
        perms_list=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'permission:' | grep -E '(CAMERA|LOCATION|MICROPHONE|SMS|CONTACTS|STORAGE)' | wc -l")

        if [[ "$perms_list" -gt 0 ]]; then
            echo "⚠️ WARNING: Application requests sensitive permissions"
            dangerous_perms=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'permission:' | grep -E '(CAMERA|LOCATION|MICROPHONE|SMS|CONTACTS|STORAGE)' | sed 's/.*permission://'")
            echo "Sensitive permissions:"
            echo "$dangerous_perms"
        else
            echo "✅ SECURE: No sensitive permissions requested"
        fi
        echo ""

        # Check for exported components
        echo "### Exported Components Check"
        local exported_activities
        exported_activities=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -A 2 'Activity:' | grep -c 'exported=true'")
        if [[ "$exported_activities" -gt 0 ]]; then
            echo "⚠️ VULNERABILITY: $exported_activities exported activities found"
            echo "Impact: Potential for component hijacking attacks"
        else
            echo "✅ SECURE: No exported activities"
        fi

        local exported_services
        exported_services=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -A 2 'Service:' | grep -c 'exported=true'")
        if [[ "$exported_services" -gt 0 ]]; then
            echo "⚠️ VULNERABILITY: $exported_services exported services found"
        fi

        local exported_receivers
        exported_receivers=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -A 2 'Receiver:' | grep -c 'exported=true'")
        if [[ "$exported_receivers" -gt 0 ]]; then
            echo "⚠️ VULNERABILITY: $exported_receivers exported broadcast receivers found"
        fi

        echo ""
        echo "## Summary"
        local vuln_count=0
        [[ "$debuggable" -gt 0 ]] && ((vuln_count++))
        [[ "$backup_flag" -gt 0 ]] && ((vuln_count++))
        [[ "$perms_list" -gt 0 ]] && ((vuln_count++))
        [[ "$exported_activities" -gt 0 ]] && ((vuln_count++))
        [[ "$exported_services" -gt 0 ]] && ((vuln_count++))
        [[ "$exported_receivers" -gt 0 ]] && ((vuln_count++))

        echo "Total vulnerabilities found: $vuln_count"

        if [[ $vuln_count -ge 4 ]]; then
            echo "🚨 CRITICAL: High vulnerability count detected"
        elif [[ $vuln_count -ge 2 ]]; then
            echo "⚠️ WARNING: Multiple vulnerabilities found"
        else
            echo "✅ LOW RISK: Minimal vulnerabilities detected"
        fi

    } > "$output_file"

    log "SUCCESS" "Vulnerability scan completed. $vuln_count vulnerabilities found. Results saved to $output_file"
}

# APK malware detection
apk_malware_detection() {
    local device_serial="$1"

    read -r -p "Enter package name to scan: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    log "INFO" "Scanning $package_name for malware indicators"

    local output_file="$OUTPUT_DIR/malware_scan_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Malware Detection"
        echo "# Package: $package_name"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get APK path
        local apk_path
        apk_path=$(execute_shell_cmd "$device_serial" "pm path $package_name 2>/dev/null | sed 's/package://'")

        if [[ -z "$apk_path" ]]; then
            echo "ERROR: Could not find APK path"
            return 1
        fi

        echo "## Malware Indicators Analysis"
        echo ""

        # Check for suspicious file names
        echo "### Suspicious Files"
        local suspicious_files
        suspicious_files=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep -i -E '(hack|crack|keygen|trojan|virus|malware|exploit)' | wc -l")
        if [[ "$suspicious_files" -gt 0 ]]; then
            echo "⚠️ SUSPICIOUS: $suspicious_files suspicious file names found"
            execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep -i -E '(hack|crack|keygen|trojan|virus|malware|exploit)'"
        else
            echo "✅ CLEAN: No suspicious file names detected"
        fi
        echo ""

        # Check for obfuscated code indicators
        echo "### Code Obfuscation Detection"
        local obfuscation_check
        obfuscation_check=$(execute_shell_cmd "$device_serial" "unzip -p $apk_path classes.dex 2>/dev/null | strings | grep -c -E '(proguard|obfuscator|r8)' || echo '0'")
        if [[ "$obfuscation_check" -gt 0 ]]; then
            echo "ℹ️ INFO: Code obfuscation detected (not necessarily malicious)"
        else
            echo "ℹ️ INFO: No code obfuscation indicators found"
        fi
        echo ""

        # Check for native code
        echo "### Native Code Analysis"
        local native_code
        native_code=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep '\.so$' | wc -l")
        if [[ "$native_code" -gt 5 ]]; then
            echo "⚠️ SUSPICIOUS: High number of native libraries ($native_code)"
        elif [[ "$native_code" -gt 0 ]]; then
            echo "ℹ️ INFO: $native_code native libraries found"
        else
            echo "ℹ️ INFO: No native code detected"
        fi
        echo ""

        # Check file entropy (potential encryption/packing)
        echo "### File Entropy Analysis"
        echo "Note: High entropy files may indicate encryption or packing"
        execute_shell_cmd "$device_serial" "unzip -l $apk_path | awk 'NR>3 {print \$1, \$4}' | sort -nr | head -5"
        echo ""

        # Permission-based malware detection
        echo "### Permission-Based Analysis"
        local dangerous_perms
        dangerous_perms=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'permission:' | grep -c -E '(SEND_SMS|READ_SMS|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION|READ_CONTACTS|READ_CALL_LOG)'")
        if [[ "$dangerous_perms" -gt 3 ]]; then
            echo "⚠️ SUSPICIOUS: High number of dangerous permissions ($dangerous_perms)"
        else
            echo "ℹ️ INFO: $dangerous_perms dangerous permissions"
        fi
        echo ""

        # Overall risk assessment
        echo "## Malware Risk Assessment"
        local risk_score=0

        [[ "$suspicious_files" -gt 0 ]] && ((risk_score += 30))
        [[ "$native_code" -gt 5 ]] && ((risk_score += 20))
        [[ "$dangerous_perms" -gt 3 ]] && ((risk_score += 20))
        [[ "$debuggable" -gt 0 ]] && ((risk_score += 10))

        echo "Malware Risk Score: $risk_score/100"

        if [[ $risk_score -ge 70 ]]; then
            echo "🚨 HIGH RISK: Strong malware indicators detected"
        elif [[ $risk_score -ge 40 ]]; then
            echo "⚠️ MEDIUM RISK: Some suspicious indicators found"
        elif [[ $risk_score -ge 20 ]]; then
            echo "⚠️ LOW RISK: Minor indicators detected"
        else
            echo "✅ LOW RISK: No significant malware indicators"
        fi

    } > "$output_file"

    log "SUCCESS" "Malware detection scan completed. Risk score: $risk_score/100. Results saved to $output_file"
}

# APK signature verification
apk_signature_verification() {
    local device_serial="$1"

    read -r -p "Enter package name to verify: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    log "INFO" "Verifying APK signature for $package_name"

    local output_file="$OUTPUT_DIR/signature_verify_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Signature Verification"
        echo "# Package: $package_name"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get APK path
        local apk_path
        apk_path=$(execute_shell_cmd "$device_serial" "pm path $package_name 2>/dev/null | sed 's/package://'")

        if [[ -z "$apk_path" ]]; then
            echo "ERROR: Could not find APK path"
            return 1
        fi

        echo "## Signature Information"
        local signature_info
        signature_info=$(execute_shell_cmd "$device_serial" "jarsigner -verify -verbose -certs $apk_path 2>&1 | head -30 || echo 'jarsigner not available on device'")
        echo "$signature_info"
        echo ""

        # Check signature validity
        echo "## Signature Validation"
        local sig_valid
        sig_valid=$(execute_shell_cmd "$device_serial" "jarsigner -verify $apk_path >/dev/null 2>&1 && echo 'VALID' || echo 'INVALID'")
        echo "Signature Status: $sig_valid"

        if [[ "$sig_valid" = "VALID" ]]; then
            echo "✅ SIGNATURE VALID: APK signature is authentic"
        else
            echo "❌ SIGNATURE INVALID: APK may be tampered with or corrupted"
        fi
        echo ""

        # Certificate details
        echo "## Certificate Details"
        local cert_details
        cert_details=$(execute_shell_cmd "$device_serial" "jarsigner -verify -verbose -certs $apk_path 2>&1 | grep -A 10 'X.509' | head -15 || echo 'Certificate details not available'")
        echo "$cert_details"
        echo ""

    } > "$output_file"

    log "SUCCESS" "APK signature verification completed. Results saved to $output_file"
}

# APK comparative analysis
apk_comparative_analysis() {
    local device_serial="$1"

    echo "Comparative Analysis Options:"
    echo "============================"
    echo "1. Compare two APKs"
    echo "2. Compare with known good APK"
    echo "3. Version comparison"
    echo "0. Back"
    echo

    read -r -p "Choice: " choice

    case $choice in
        1) compare_two_apks "$device_serial" ;;
        2) compare_with_good_apk "$device_serial" ;;
        3) version_comparison "$device_serial" ;;
        0) return 0 ;;
        *) log "ERROR" "Invalid choice" ;;
    esac
}

# Compare two APKs
compare_two_apks() {
    local device_serial="$1"

    read -r -p "Enter first package name: " pkg1
    read -r -p "Enter second package name: " pkg2

    if [[ -z "$pkg1" || -z "$pkg2" ]]; then
        log "ERROR" "Both package names are required"
        return 1
    fi

    log "INFO" "Comparing $pkg1 vs $pkg2"

    local output_file="$OUTPUT_DIR/apk_comparison_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Comparative Analysis"
        echo "# Comparing: $pkg1 vs $pkg2"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get APK paths
        local apk1_path
        apk1_path=$(execute_shell_cmd "$device_serial" "pm path $pkg1 2>/dev/null | sed 's/package://'")
        local apk2_path
        apk2_path=$(execute_shell_cmd "$device_serial" "pm path $pkg2 2>/dev/null | sed 's/package://'")

        if [[ -z "$apk1_path" || -z "$apk2_path" ]]; then
            echo "ERROR: Could not find APK paths"
            return 1
        fi

        echo "## APK Information"
        echo "$pkg1: $apk1_path"
        echo "$pkg2: $apk2_path"
        echo ""

        # Size comparison
        echo "## Size Comparison"
        local size1
        size1=$(execute_shell_cmd "$device_serial" "ls -lh $apk1_path | awk '{print \$5}'")
        local size2
        size2=$(execute_shell_cmd "$device_serial" "ls -lh $apk2_path | awk '{print \$5}'")
        echo "$pkg1 size: $size1"
        echo "$pkg2 size: $size2"
        echo ""

        # File count comparison
        echo "## File Count Comparison"
        local files1
        files1=$(execute_shell_cmd "$device_serial" "unzip -l $apk1_path | wc -l")
        local files2
        files2=$(execute_shell_cmd "$device_serial" "unzip -l $apk2_path | wc -l")
        echo "$pkg1 files: $files1"
        echo "$pkg2 files: $files2"
        echo ""

        # Permission comparison
        echo "## Permission Comparison"
        local perms1
        perms1=$(execute_shell_cmd "$device_serial" "dumpsys package $pkg1 | grep 'permission:' | wc -l")
        local perms2
        perms2=$(execute_shell_cmd "$device_serial" "dumpsys package $pkg2 | grep 'permission:' | wc -l")
        echo "$pkg1 permissions: $perms1"
        echo "$pkg2 permissions: $perms2"
        echo ""

    } > "$output_file"

    log "SUCCESS" "APK comparative analysis completed. Results saved to $output_file"
}
