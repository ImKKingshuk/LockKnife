#!/bin/bash

# LockKnife Hardware Security Analysis Module
# Provides comprehensive hardware security assessment

# Hardware security analysis submenu
hardware_security_analysis_menu() {
    local device_serial="$1"

    while true; do
        echo
        echo "Hardware Security Analysis"
        echo "=========================="
        echo "1. TEE (Trusted Execution Environment) Analysis"
        echo "2. Hardware-Backed Keystore Analysis"
        echo "3. Secure Element Analysis"
        echo "4. Hardware Security Module (HSM) Check"
        echo "5. Biometric Hardware Analysis"
        echo "6. Cryptographic Hardware Assessment"
        echo "7. Hardware Attack Surface Analysis"
        echo "8. Hardware Security Assessment Report"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) tee_analysis "$device_serial" ;;
            2) hardware_keystore_analysis "$device_serial" ;;
            3) secure_element_analysis "$device_serial" ;;
            4) hsm_check "$device_serial" ;;
            5) biometric_hardware_analysis "$device_serial" ;;
            6) cryptographic_hardware_assessment "$device_serial" ;;
            7) hardware_attack_surface "$device_serial" ;;
            8) hardware_security_report "$device_serial" ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# TEE Analysis
tee_analysis() {
    local device_serial="$1"

    log "INFO" "Analyzing Trusted Execution Environment (TEE)"

    local output_file="$OUTPUT_DIR/tee_analysis_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife TEE Analysis Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check for TEE support
        echo "## TEE Support Detection"
        local tee_present="false"

        # Check for Qualcomm TEE (QSEE)
        local qsee_check
        qsee_check=$(execute_shell_cmd "$device_serial" "ls /system/lib/libQSEEComAPI.so 2>/dev/null && echo 'Present' || echo 'Not found'")
        if [[ "$qsee_check" = "Present" ]]; then
            tee_present="true"
            echo "✅ Qualcomm TEE (QSEE): Detected"
        else
            echo "❌ Qualcomm TEE (QSEE): Not detected"
        fi

        # Check for ARM TrustZone
        local tz_check
        tz_check=$(execute_shell_cmd "$device_serial" "getprop ro.hardware | grep -i -E '(qcom|mt[0-9]|hi[0-9])' && echo 'Likely TrustZone' || echo 'Unknown'")
        if [[ "$tz_check" = "Likely TrustZone" ]]; then
            tee_present="true"
            echo "✅ ARM TrustZone: Likely present"
        else
            echo "❓ ARM TrustZone: Unable to determine"
        fi

        # Check for TEE-related processes
        echo ""
        echo "## TEE Processes"
        local tee_processes
        tee_processes=$(execute_shell_cmd "$device_serial" "ps | grep -i -E '(tee|qsee|trustzone|secure)' | grep -v grep")
        if [[ -n "$tee_processes" ]]; then
            echo "TEE-related processes found:"
            echo "$tee_processes"
        else
            echo "No TEE-related processes detected"
        fi
        echo ""

        # TEE capabilities assessment
        echo "## TEE Capabilities Assessment"
        if [[ "$tee_present" = "true" ]]; then
            echo "✅ TEE SUPPORTED: Device has TEE capabilities"
            echo ""
            echo "### Security Implications:"
            echo "- Secure key storage available"
            echo "- Trusted applications can run in isolated environment"
            echo "- Hardware-backed cryptography support"
            echo "- Protection against software-based attacks"

            # Check TEE version/features
            local tee_version
            tee_version=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.security_patch 2>/dev/null || echo 'Unknown'")
            echo "- Security patch level: $tee_version"
        else
            echo "❌ TEE NOT SUPPORTED: Device lacks TEE capabilities"
            echo ""
            echo "### Security Implications:"
            echo "- No hardware-backed security isolation"
            echo "- Relies on software-based security measures"
            echo "- Higher vulnerability to advanced attacks"
            echo "- Limited protection for sensitive operations"
        fi
        echo ""

        # TEE vulnerability assessment
        echo "## TEE Vulnerability Assessment"
        local vuln_score=0
        local vulnerabilities=""

        # Check for known TEE vulnerabilities
        if [[ "$tee_present" = "true" ]]; then
            # Check security patch level
            local patch_level
            patch_level=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.security_patch | sed 's/-.*//'")
            if [[ -n "$patch_level" ]]; then
                # Convert to comparable format
                local patch_year=${patch_level%%-*}
                local patch_month=${patch_level#*-}
                patch_month=${patch_month#0}

                local current_year=$(date +%Y)
                local current_month=$(date +%m)
                current_month=${current_month#0}

                if [[ $patch_year -lt $current_year ]] || ([[ $patch_year -eq $current_year ]] && [[ $patch_month -lt $((current_month - 1)) ]]); then
                    ((vuln_score += 20))
                    vulnerabilities="${vulnerabilities}Outdated security patches, "
                fi
            fi
        fi

        echo "Vulnerability Score: $vuln_score/100"
        if [[ $vuln_score -gt 0 ]]; then
            echo "Vulnerabilities: ${vulnerabilities%, }"
        else
            echo "No significant TEE vulnerabilities detected"
        fi

    } > "$output_file"

    log "SUCCESS" "TEE analysis completed. Results saved to $output_file"
}

# Hardware-backed keystore analysis
hardware_keystore_analysis() {
    local device_serial="$1"

    log "INFO" "Analyzing hardware-backed keystore"

    local output_file="$OUTPUT_DIR/hardware_keystore_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Hardware Keystore Analysis"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check keystore support
        echo "## Keystore Support Detection"
        local keystore_support
        keystore_support=$(execute_shell_cmd "$device_serial" "getprop ro.hardware.keystore")

        if [[ -n "$keystore_support" ]]; then
            echo "✅ Hardware Keystore: Supported ($keystore_support)"
        else
            echo "❌ Hardware Keystore: Not detected"
        fi
        echo ""

        # Check keystore version
        echo "## Keystore Version Information"
        local keystore_version
        keystore_version=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.release")
        echo "Android Version: $keystore_version"

        # Check for Keymaster HAL
        local keymaster_check
        keymaster_check=$(execute_shell_cmd "$device_serial" "ls /system/lib/hw/ | grep -i keymaster || ls /system/lib64/hw/ | grep -i keymaster || echo 'Not found'")
        if [[ "$keymaster_check" != "Not found" ]]; then
            echo "✅ Keymaster HAL: Present"
            echo "Keymaster modules: $keymaster_check"
        else
            echo "❌ Keymaster HAL: Not found"
        fi
        echo ""

        # Check keystore keys
        echo "## Keystore Keys Analysis"
        local key_count
        key_count=$(execute_shell_cmd "$device_serial" "dumpsys keystore 2>/dev/null | grep -c 'Alias:' || echo '0'")
        echo "Stored keys: $key_count"

        if [[ "$key_count" -gt 0 ]]; then
            echo "Key aliases:"
            execute_shell_cmd "$device_serial" "dumpsys keystore 2>/dev/null | grep 'Alias:' | head -10"
        fi
        echo ""

        # Hardware-backed key assessment
        echo "## Hardware-Backed Key Assessment"
        local hw_keys=0
        local sw_keys=0

        if [[ "$key_count" -gt 0 ]]; then
            # Check for hardware-backed keys (this is approximate)
            local key_info
            key_info=$(execute_shell_cmd "$device_serial" "dumpsys keystore 2>/dev/null | grep -A 5 'Alias:' | head -50")
            hw_keys=$(echo "$key_info" | grep -c "Hardware")
            sw_keys=$((key_count - hw_keys))
        fi

        echo "Hardware-backed keys: $hw_keys"
        echo "Software keys: $sw_keys"

        if [[ $hw_keys -gt 0 ]]; then
            echo "✅ HARDWARE SECURITY: Device supports hardware-backed keys"
        else
            echo "⚠️ SOFTWARE ONLY: Keys stored in software only"
        fi
        echo ""

        # Security assessment
        echo "## Security Assessment"
        local security_score=50  # Base score

        [[ -n "$keystore_support" ]] && ((security_score += 20))
        [[ "$keymaster_check" != "Not found" ]] && ((security_score += 15))
        [[ $hw_keys -gt 0 ]] && ((security_score += 15))

        echo "Hardware Keystore Security Score: $security_score/100"

        if [[ $security_score -ge 80 ]]; then
            echo "✅ EXCELLENT: Strong hardware keystore protection"
        elif [[ $security_score -ge 60 ]]; then
            echo "✅ GOOD: Adequate hardware keystore security"
        elif [[ $security_score -ge 40 ]]; then
            echo "⚠️ FAIR: Basic hardware keystore support"
        else
            echo "❌ POOR: Weak or no hardware keystore protection"
        fi

    } > "$output_file"

    log "SUCCESS" "Hardware keystore analysis completed. Results saved to $output_file"
}

# Secure Element analysis
secure_element_analysis() {
    local device_serial="$1"

    log "INFO" "Analyzing Secure Element (SE)"

    local output_file="$OUTPUT_DIR/secure_element_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Secure Element Analysis"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check for Secure Element support
        echo "## Secure Element Detection"
        local se_present="false"

        # Check for eSE (embedded Secure Element)
        local ese_check
        ese_check=$(execute_shell_cmd "$device_serial" "ls /system/lib/libese* 2>/dev/null || ls /vendor/lib/libese* 2>/dev/null || echo 'Not found'")
        if [[ "$ese_check" != "Not found" ]]; then
            se_present="true"
            echo "✅ Embedded Secure Element (eSE): Detected"
            echo "Libraries: $ese_check"
        else
            echo "❌ Embedded Secure Element (eSE): Not detected"
        fi

        # Check for UICC/eUICC
        local uicc_check
        uicc_check=$(execute_shell_cmd "$device_serial" "getprop | grep -i uicc || echo 'Not found'")
        if [[ "$uicc_check" != "Not found" ]]; then
            se_present="true"
            echo "✅ UICC/eUICC: Detected"
        else
            echo "❌ UICC/eUICC: Not detected"
        fi

        # Check for NFC Secure Element
        local nfc_se_check
        nfc_se_check=$(execute_shell_cmd "$device_serial" "dumpsys nfc 2>/dev/null | grep -i secure || echo 'Not found'")
        if [[ "$nfc_se_check" != "Not found" ]]; then
            se_present="true"
            echo "✅ NFC Secure Element: Detected"
        else
            echo "❌ NFC Secure Element: Not detected"
        fi
        echo ""

        # SE capabilities
        echo "## Secure Element Capabilities"
        if [[ "$se_present" = "true" ]]; then
            echo "✅ SECURE ELEMENT SUPPORTED"
            echo ""
            echo "### Available Features:"
            [[ "$ese_check" != "Not found" ]] && echo "- Payment applications (Google Pay, etc.)"
            [[ "$uicc_check" != "Not found" ]] && echo "- SIM-based secure operations"
            [[ "$nfc_se_check" != "Not found" ]] && echo "- Contactless payment and authentication"

            echo ""
            echo "### Security Benefits:"
            echo "- Isolated execution environment"
            echo "- Protection against software attacks"
            echo "- Secure key storage"
            echo "- Tamper-resistant hardware"
        else
            echo "❌ NO SECURE ELEMENT DETECTED"
            echo ""
            echo "### Security Implications:"
            echo "- Relies on TEE or software-based security"
            echo "- Potentially vulnerable to advanced attacks"
            echo "- Limited secure payment capabilities"
        fi
        echo ""

        # SE applications
        echo "## Secure Element Applications"
        local se_apps=""

        # Check for payment apps that use SE
        execute_shell_cmd "$device_serial" "pm list packages | grep -E '(google.*pay|android.*pay|samsung.*pay)" >/dev/null 2>&1 && se_apps="${se_apps}Payment apps, "

        # Check for authentication apps
        execute_shell_cmd "$device_serial" "pm list packages | grep -E '(authenticator|microsoft.*authenticator|google.*authenticator)' >/dev/null 2>&1 && se_apps="${se_apps}Authenticator apps, "

        if [[ -n "$se_apps" ]]; then
            echo "SE-enabled applications detected: ${se_apps%, }"
        else
            echo "No SE-enabled applications detected"
        fi
        echo ""

    } > "$output_file"

    log "SUCCESS" "Secure Element analysis completed. Results saved to $output_file"
}

# HSM Check
hsm_check() {
    local device_serial="$1"

    log "INFO" "Checking for Hardware Security Module (HSM) support"

    local output_file="$OUTPUT_DIR/hsm_check_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife HSM Check Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # HSM detection is challenging on Android devices
        # Most consumer devices don't have dedicated HSMs
        echo "## HSM Detection Results"
        echo "Note: Dedicated HSMs are rare in consumer Android devices."
        echo "Most security functions are handled by TEE or Secure Elements."
        echo ""

        # Check for HSM-related libraries
        local hsm_libs
        hsm_libs=$(execute_shell_cmd "$device_serial" "find /system/lib -name '*hsm*' 2>/dev/null | head -5")

        if [[ -n "$hsm_libs" ]]; then
            echo "✅ Potential HSM Libraries Detected:"
            echo "$hsm_libs"
        else
            echo "❌ No HSM Libraries Found"
        fi
        echo ""

        # Check for cryptographic hardware acceleration
        echo "## Cryptographic Hardware Acceleration"
        local crypto_hw
        crypto_hw=$(execute_shell_cmd "$device_serial" "getprop | grep -i crypto")

        if [[ -n "$crypto_hw" ]]; then
            echo "Cryptographic hardware features:"
            echo "$crypto_hw"
        else
            echo "No cryptographic hardware properties detected"
        fi
        echo ""

        echo "## Assessment"
        echo "Consumer Android devices typically do not include dedicated HSMs."
        echo "Security functions are usually provided by:"
        echo "- Trusted Execution Environment (TEE)"
        echo "- Secure Elements (eSE, UICC)"
        echo "- Hardware-backed keystores"
        echo ""
        echo "For enterprise or specialized devices, consult manufacturer specifications."

    } > "$output_file"

    log "SUCCESS" "HSM check completed. Results saved to $output_file"
}

# Biometric hardware analysis
biometric_hardware_analysis() {
    local device_serial="$1"

    log "INFO" "Analyzing biometric hardware capabilities"

    local output_file="$OUTPUT_DIR/biometric_hw_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Biometric Hardware Analysis"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check biometric capabilities
        echo "## Biometric Hardware Detection"
        local biometric_caps=""
        local biometric_score=0

        # Fingerprint sensor
        local fp_check
        fp_check=$(execute_shell_cmd "$device_serial" "getprop | grep -i fingerprint")
        if [[ -n "$fp_check" ]]; then
            biometric_caps="${biometric_caps}Fingerprint, "
            ((biometric_score += 25))
            echo "✅ Fingerprint Sensor: Supported"
        else
            echo "❌ Fingerprint Sensor: Not detected"
        fi

        # Face unlock
        local face_check
        face_check=$(execute_shell_cmd "$device_serial" "pm list features | grep -i face")
        if [[ -n "$face_check" ]]; then
            biometric_caps="${biometric_caps}Face Unlock, "
            ((biometric_score += 20))
            echo "✅ Face Unlock: Supported"
        else
            echo "❌ Face Unlock: Not supported"
        fi

        # Iris scanner
        local iris_check
        iris_check=$(execute_shell_cmd "$device_serial" "getprop | grep -i iris")
        if [[ -n "$iris_check" ]]; then
            biometric_caps="${biometric_caps}Iris Scanner, "
            ((biometric_score += 15))
            echo "✅ Iris Scanner: Supported"
        else
            echo "❌ Iris Scanner: Not supported"
        fi

        # Voice recognition
        local voice_check
        voice_check=$(execute_shell_cmd "$device_serial" "pm list features | grep -i voice")
        if [[ -n "$voice_check" ]]; then
            biometric_caps="${biometric_caps}Voice Recognition, "
            ((biometric_score += 10))
            echo "✅ Voice Recognition: Supported"
        else
            echo "❌ Voice Recognition: Not supported"
        fi
        echo ""

        # Hardware security for biometrics
        echo "## Biometric Security Assessment"
        local hw_security="Unknown"

        # Check if biometrics use TEE
        local tee_biometric
        tee_biometric=$(execute_shell_cmd "$device_serial" "getprop | grep -i biometric | grep -i tee")
        if [[ -n "$tee_biometric" ]]; then
            hw_security="TEE Protected"
            ((biometric_score += 20))
        fi

        # Check for biometric HAL
        local biometric_hal
        biometric_hal=$(execute_shell_cmd "$device_serial" "ls /system/lib/hw/ | grep -i biometric || ls /vendor/lib/hw/ | grep -i biometric || echo 'Not found'")
        if [[ "$biometric_hal" != "Not found" ]]; then
            hw_security="Hardware HAL Present"
            ((biometric_score += 15))
        fi

        echo "Hardware Security: $hw_security"
        echo ""

        # Biometric data storage
        echo "## Biometric Data Storage"
        local biometric_data
        biometric_data=$(execute_shell_cmd "$device_serial" "find /data -name '*biometric*' 2>/dev/null | head -5")

        if [[ -n "$biometric_data" ]]; then
            echo "Biometric data locations:"
            echo "$biometric_data"
        else
            echo "No biometric data directories found"
        fi
        echo ""

        # Overall assessment
        echo "## Overall Biometric Assessment"
        echo "Supported modalities: ${biometric_caps%, }"
        echo "Security Score: $biometric_score/100"

        if [[ $biometric_score -ge 80 ]]; then
            echo "✅ EXCELLENT: Strong biometric security"
        elif [[ $biometric_score -ge 60 ]]; then
            echo "✅ GOOD: Adequate biometric protection"
        elif [[ $biometric_score -ge 40 ]]; then
            echo "⚠️ FAIR: Basic biometric capabilities"
        else
            echo "❌ POOR: Weak or no biometric security"
        fi

    } > "$output_file"

    log "SUCCESS" "Biometric hardware analysis completed. Results saved to $output_file"
}

# Cryptographic hardware assessment
cryptographic_hardware_assessment() {
    local device_serial="$1"

    log "INFO" "Assessing cryptographic hardware capabilities"

    local output_file="$OUTPUT_DIR/crypto_hw_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Cryptographic Hardware Assessment"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check for cryptographic hardware acceleration
        echo "## Hardware Cryptography Support"
        local crypto_hw="false"

        # Check for ARM Cryptography Extensions
        local arm_crypto
        arm_crypto=$(execute_shell_cmd "$device_serial" "getprop ro.product.cpu.abi | grep -i arm")
        if [[ -n "$arm_crypto" ]]; then
            # Check CPU features
            local cpu_features
            cpu_features=$(execute_shell_cmd "$device_serial" "cat /proc/cpuinfo | grep -i features | head -1")
            if [[ "$cpu_features" =~ (aes|sha|neon) ]]; then
                crypto_hw="true"
                echo "✅ ARM Cryptography Extensions: Supported"
                echo "Features: $cpu_features"
            fi
        fi

        # Check for Qualcomm crypto
        local qcrypto
        qcrypto=$(execute_shell_cmd "$device_serial" "ls /system/lib/libqcrypto* 2>/dev/null | head -3")
        if [[ -n "$qcrypto" ]]; then
            crypto_hw="true"
            echo "✅ Qualcomm Crypto: Supported"
            echo "Libraries: $qcrypto"
        fi

        # Check for OpenSSL hardware acceleration
        local openssl_hw
        openssl_hw=$(execute_shell_cmd "$device_serial" "openssl engine -t 2>/dev/null | grep -i hardware || echo 'Not available'")
        if [[ "$openssl_hw" != "Not available" ]]; then
            crypto_hw="true"
            echo "✅ OpenSSL Hardware Acceleration: Available"
        fi

        if [[ "$crypto_hw" = "false" ]]; then
            echo "❌ Hardware Cryptography: Not detected"
            echo "Note: Software-based cryptography only"
        fi
        echo ""

        # Supported algorithms
        echo "## Supported Cryptographic Algorithms"
        local supported_algos=""

        # Check for AES support
        execute_shell_cmd "$device_serial" "cat /proc/crypto | grep -q aes" && supported_algos="${supported_algos}AES, "

        # Check for SHA support
        execute_shell_cmd "$device_serial" "cat /proc/crypto | grep -q sha" && supported_algos="${supported_algos}SHA, "

        # Check for RSA support
        execute_shell_cmd "$device_serial" "cat /proc/crypto | grep -q rsa" && supported_algos="${supported_algos}RSA, "

        # Check for ECC support
        execute_shell_cmd "$device_serial" "cat /proc/crypto | grep -q ecdsa" && supported_algos="${supported_algos}ECC, "

        echo "Hardware-accelerated algorithms: ${supported_algos%, }"
        echo ""

        # Performance assessment
        echo "## Cryptographic Performance"
        local perf_score=0

        [[ "$crypto_hw" = "true" ]] && ((perf_score += 40))
        [[ "$supported_algos" =~ AES ]] && ((perf_score += 20))
        [[ "$supported_algos" =~ SHA ]] && ((perf_score += 15))
        [[ "$supported_algos" =~ RSA ]] && ((perf_score += 15))
        [[ "$supported_algos" =~ ECC ]] && ((perf_score += 10))

        echo "Cryptographic Performance Score: $perf_score/100"

        if [[ $perf_score -ge 80 ]]; then
            echo "✅ EXCELLENT: Strong cryptographic hardware acceleration"
        elif [[ $perf_score -ge 60 ]]; then
            echo "✅ GOOD: Adequate cryptographic performance"
        elif [[ $perf_score -ge 40 ]]; then
            echo "⚠️ FAIR: Basic cryptographic capabilities"
        else
            echo "❌ POOR: Weak cryptographic performance"
        fi

    } > "$output_file"

    log "SUCCESS" "Cryptographic hardware assessment completed. Results saved to $output_file"
}

# Hardware attack surface analysis
hardware_attack_surface() {
    local device_serial="$1"

    log "INFO" "Analyzing hardware attack surface"

    local output_file="$OUTPUT_DIR/hw_attack_surface_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Hardware Attack Surface Analysis"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Physical attack vectors
        echo "## Physical Attack Vectors"
        local physical_risks=""

        # Check for accessible ports
        local usb_ports
        usb_ports=$(execute_shell_cmd "$device_serial" "ls /sys/bus/usb/devices/ | wc -l")
        if [[ $usb_ports -gt 0 ]]; then
            physical_risks="${physical_risks}USB ports accessible, "
            echo "⚠️ USB Ports: $usb_ports accessible ports detected"
        fi

        # Check for JTAG/debug interfaces
        local jtag_check
        jtag_check=$(execute_shell_cmd "$device_serial" "getprop | grep -i jtag || echo 'Not found'")
        if [[ "$jtag_check" != "Not found" ]]; then
            physical_risks="${physical_risks}JTAG interface detected, "
            echo "⚠️ JTAG/Debug Interface: Detected"
        fi

        # Check for UART interfaces
        local uart_check
        uart_check=$(execute_shell_cmd "$device_serial" "ls /dev/tty* | grep -v tty0 | wc -l")
        if [[ $uart_check -gt 0 ]]; then
            physical_risks="${physical_risks}UART interfaces accessible, "
            echo "⚠️ UART Interfaces: $uart_check interfaces detected"
        fi
        echo ""

        # Side-channel attack vectors
        echo "## Side-Channel Attack Vectors"
        local side_channel_risks=""

        # Power consumption analysis
        echo "ℹ️ Power Analysis: Possible on all devices"
        side_channel_risks="${side_channel_risks}Power consumption analysis, "

        # Electromagnetic emissions
        echo "ℹ️ Electromagnetic Analysis: Possible with specialized equipment"
        side_channel_risks="${side_channel_risks}Electromagnetic emissions, "

        # Timing attacks
        echo "ℹ️ Timing Attacks: Possible against cryptographic operations"
        side_channel_risks="${side_channel_risks}Timing analysis, "
        echo ""

        # Hardware trojan detection
        echo "## Hardware Trojan Assessment"
        local trojan_risks="LOW"

        # Check for unusual hardware
        local unusual_hw
        unusual_hw=$(execute_shell_cmd "$device_serial" "lsusb 2>/dev/null | grep -v -E '(Linux Foundation|Google|Qualcomm|Samsung)' | wc -l || echo '0'")
        if [[ $unusual_hw -gt 0 ]]; then
            trojan_risks="MEDIUM"
            echo "⚠️ Unusual USB devices detected: $unusual_hw"
        else
            echo "✅ No unusual hardware detected"
        fi

        # Check for modified bootloaders
        local bootloader_status
        bootloader_status=$(execute_shell_cmd "$device_serial" "getprop ro.boot.verifiedbootstate")
        if [[ "$bootloader_status" = "orange" ]]; then
            trojan_risks="HIGH"
            echo "⚠️ CRITICAL: Bootloader integrity compromised"
        elif [[ "$bootloader_status" = "yellow" ]]; then
            trojan_risks="MEDIUM"
            echo "⚠️ WARNING: Bootloader modifications detected"
        else
            echo "✅ Bootloader integrity verified"
        fi
        echo ""

        # Overall risk assessment
        echo "## Attack Surface Risk Assessment"
        local attack_score=0

        [[ -n "$physical_risks" ]] && ((attack_score += 30))
        [[ "$trojan_risks" = "HIGH" ]] && ((attack_score += 40))
        [[ "$trojan_risks" = "MEDIUM" ]] && ((attack_score += 20))
        [[ -n "$side_channel_risks" ]] && ((attack_score += 10))  # Side channel is always possible

        echo "Physical Attack Vectors: ${physical_risks%, }"
        echo "Side-Channel Risks: ${side_channel_risks%, }"
        echo "Hardware Trojan Risk: $trojan_risks"
        echo ""
        echo "Overall Attack Surface Score: $attack_score/100"

        if [[ $attack_score -ge 70 ]]; then
            echo "🚨 HIGH RISK: Significant hardware attack surface"
        elif [[ $attack_score -ge 40 ]]; then
            echo "⚠️ MEDIUM RISK: Moderate hardware attack vectors"
        else
            echo "✅ LOW RISK: Limited hardware attack surface"
        fi

        # Mitigation recommendations
        echo ""
        echo "## Mitigation Recommendations"
        if [[ -n "$physical_risks" ]]; then
            echo "- Keep device physically secure"
            echo "- Use tamper-evident seals on ports"
            echo "- Avoid leaving device unattended"
        fi
        if [[ "$trojan_risks" != "LOW" ]]; then
            echo "- Verify device integrity regularly"
            echo "- Use trusted boot mechanisms"
            echo "- Consider hardware replacement if compromised"
        fi
        echo "- Implement application-level security measures"
        echo "- Use hardware-backed security features when available"

    } > "$output_file"

    log "SUCCESS" "Hardware attack surface analysis completed. Results saved to $output_file"
}

# Hardware security report
hardware_security_report() {
    local device_serial="$1"

    log "INFO" "Generating comprehensive hardware security report"

    local output_file="$OUTPUT_DIR/hardware_security_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Comprehensive Hardware Security Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Device information
        echo "## Device Information"
        local model
        model=$(execute_shell_cmd "$device_serial" "getprop ro.product.model")
        local manufacturer
        manufacturer=$(execute_shell_cmd "$device_serial" "getprop ro.product.manufacturer")
        local android_version
        android_version=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.release")
        local security_patch
        security_patch=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.security_patch")

        echo "Manufacturer: $manufacturer"
        echo "Model: $model"
        echo "Android Version: $android_version"
        echo "Security Patch: $security_patch"
        echo ""

        # Hardware security features summary
        echo "## Hardware Security Features Summary"

        # TEE status
        local tee_status="Not detected"
        execute_shell_cmd "$device_serial" "ls /system/lib/libQSEEComAPI.so" >/dev/null 2>&1 && tee_status="Qualcomm QSEE"
        execute_shell_cmd "$device_serial" "getprop ro.hardware | grep -i -E '(qcom|mt[0-9]|hi[0-9])'" >/dev/null 2>&1 && tee_status="Likely TrustZone"

        echo "TEE Support: $tee_status"

        # Keystore status
        local keystore_status
        keystore_status=$(execute_shell_cmd "$device_serial" "getprop ro.hardware.keystore")
        echo "Hardware Keystore: ${keystore_status:-Not supported}"

        # Secure Element status
        local se_status="Not detected"
        execute_shell_cmd "$device_serial" "ls /system/lib/libese*" >/dev/null 2>&1 && se_status="Embedded SE detected"
        echo "Secure Element: $se_status"

        # Biometric hardware
        local biometric_count=0
        execute_shell_cmd "$device_serial" "getprop | grep -i fingerprint" >/dev/null 2>&1 && ((biometric_count++))
        execute_shell_cmd "$device_serial" "pm list features | grep -i face" >/dev/null 2>&1 && ((biometric_count++))
        execute_shell_cmd "$device_serial" "getprop | grep -i iris" >/dev/null 2>&1 && ((biometric_count++))
        echo "Biometric Modalities: $biometric_count"

        # Cryptographic hardware
        local crypto_hw="Software only"
        execute_shell_cmd "$device_serial" "cat /proc/cpuinfo | grep -i features | grep -i aes" >/dev/null 2>&1 && crypto_hw="Hardware accelerated"
        echo "Cryptographic Acceleration: $crypto_hw"
        echo ""

        # Overall security score
        echo "## Overall Hardware Security Score"
        local hw_score=0

        [[ "$tee_status" != "Not detected" ]] && ((hw_score += 25))
        [[ -n "$keystore_status" ]] && ((hw_score += 20))
        [[ "$se_status" != "Not detected" ]] && ((hw_score += 15))
        [[ $biometric_count -gt 0 ]] && ((hw_score += 10))
        [[ "$crypto_hw" = "Hardware accelerated" ]] && ((hw_score += 15))
        [[ -n "$security_patch" ]] && ((hw_score += 15))

        echo "Hardware Security Score: $hw_score/100"

        # Grade assignment
        if [[ $hw_score -ge 90 ]]; then
            echo "Grade: A+ (Exceptional hardware security)"
        elif [[ $hw_score -ge 80 ]]; then
            echo "Grade: A (Excellent hardware security)"
        elif [[ $hw_score -ge 70 ]]; then
            echo "Grade: B (Good hardware security)"
        elif [[ $hw_score -ge 60 ]]; then
            echo "Grade: C (Adequate hardware security)"
        elif [[ $hw_score -ge 50 ]]; then
            echo "Grade: D (Basic hardware security)"
        else
            echo "Grade: F (Poor hardware security)"
        fi
        echo ""

        # Recommendations
        echo "## Security Recommendations"
        if [[ "$tee_status" = "Not detected" ]]; then
            echo "- Consider devices with TEE support for enhanced security"
        fi
        if [[ -z "$keystore_status" ]]; then
            echo "- Hardware keystore recommended for secure key storage"
        fi
        if [[ "$se_status" = "Not detected" ]]; then
            echo "- Secure Element provides additional security layer"
        fi
        if [[ $biometric_count -eq 0 ]]; then
            echo "- Consider devices with biometric authentication"
        fi
        echo "- Keep device updated with latest security patches"
        echo "- Use hardware-backed security features in applications"

    } > "$output_file"

    log "SUCCESS" "Comprehensive hardware security report generated. Score: $hw_score/100. Results saved to $output_file"

    # Display summary
    echo
    echo "Hardware Security Assessment Complete"
    echo "===================================="
    echo "Security Score: $hw_score/100"
    echo "Report saved to: $output_file"
}
