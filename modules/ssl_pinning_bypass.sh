#!/bin/bash

# LockKnife SSL Pinning Bypass Module
# Provides SSL pinning bypass capabilities

# SSL pinning bypass submenu
ssl_pinning_bypass_menu() {
    local device_serial="$1"

    while true; do
        echo
        echo "SSL Pinning Bypass"
        echo "=================="
        echo "1. Detect SSL Pinning"
        echo "2. Frida SSL Bypass"
        echo "3. APK Certificate Pinning Analysis"
        echo "4. Network Traffic Interception"
        echo "5. Certificate Installation"
        echo "6. Proxy Configuration"
        echo "7. Burp Suite Integration"
        echo "8. SSL Pinning Bypass Assessment"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) detect_ssl_pinning "$device_serial" ;;
            2) frida_ssl_bypass "$device_serial" ;;
            3) apk_certificate_analysis "$device_serial" ;;
            4) network_traffic_interception "$device_serial" ;;
            5) install_certificates "$device_serial" ;;
            6) configure_proxy "$device_serial" ;;
            7) burp_suite_integration "$device_serial" ;;
            8) ssl_bypass_assessment "$device_serial" ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Detect SSL pinning in applications
detect_ssl_pinning() {
    local device_serial="$1"

    log "INFO" "Detecting SSL pinning in installed applications..."

    local output_file="$OUTPUT_DIR/ssl_pinning_detection_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife SSL Pinning Detection Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Get list of installed applications
        local apps_list
        apps_list=$(execute_shell_cmd "$device_serial" "pm list packages -3")

        echo "## SSL Pinning Detection Results"
        echo ""

        local pinned_apps=""
        local total_apps=0
        local checked_apps=0

        while IFS= read -r line; do
            if [[ "$line" =~ package:(.+) ]]; then
                local package="${BASH_REMATCH[1]}"
                ((total_apps++))

                # Check for common SSL pinning indicators
                local apk_path
                apk_path=$(execute_shell_cmd "$device_serial" "pm path $package 2>/dev/null | sed 's/package://'")

                if [[ -n "$apk_path" ]]; then
                    # Check APK for SSL pinning libraries
                    local pinning_check
                    pinning_check=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path 2>/dev/null | grep -i -E '(okhttp|pinn|ssl|trustkit|certificate|network_security_config)' | wc -l")

                    if [[ "$pinning_check" -gt 0 ]]; then
                        echo "POTENTIAL SSL PINNING: $package"
                        pinned_apps="${pinned_apps}$package, "
                        ((checked_apps++))
                    fi
                fi
            fi
        done <<< "$apps_list"

        echo ""
        echo "## Summary"
        echo "Total user apps: $total_apps"
        echo "Apps checked: $checked_apps"
        echo "Potential SSL pinning: $(echo "$pinned_apps" | tr ',' '\n' | wc -l)"
        echo ""
        echo "## Detected Apps:"
        echo "${pinned_apps%, }"

    } > "$output_file"

    log "SUCCESS" "SSL pinning detection completed. Results saved to $output_file"
}

# Frida SSL bypass implementation
frida_ssl_bypass() {
    local device_serial="$1"

    echo "Frida SSL Pinning Bypass"
    echo "========================"
    echo "Note: Requires Frida server to be running on device"
    echo ""
    echo "1. Universal SSL bypass script"
    echo "2. OkHTTP pinning bypass"
    echo "3. TrustKit bypass"
    echo "4. Custom SSL bypass"
    echo "0. Back"
    echo

    read -r -p "Choice: " choice

    case $choice in
        1) frida_universal_ssl_bypass "$device_serial" ;;
        2) frida_okhttp_bypass "$device_serial" ;;
        3) frida_trustkit_bypass "$device_serial" ;;
        4) frida_custom_ssl_bypass "$device_serial" ;;
        0) return 0 ;;
        *) log "ERROR" "Invalid choice" ;;
    esac
}

# Universal Frida SSL bypass
frida_universal_ssl_bypass() {
    local device_serial="$1"

    log "INFO" "Applying universal SSL pinning bypass..."

    # Check if Frida is available
    local frida_check
    frida_check=$(command -v frida 2>/dev/null)

    if [[ -z "$frida_check" ]]; then
        log "ERROR" "Frida CLI not found. Please install Frida: pip install frida-tools"
        return 1
    fi

    read -r -p "Enter package name to bypass SSL pinning: " package_name

    if [[ -z "$package_name" ]]; then
        log "ERROR" "No package name provided"
        return 1
    fi

    # Create Frida script for SSL bypass
    local frida_script="/tmp/ssl_bypass_$(date +%s).js"
    cat > "$frida_script" << 'EOF'
Java.perform(function() {
    console.log("[+] SSL Pinning Bypass - Universal");

    // Bypass OkHTTP certificate pinning
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassed OkHTTP CertificatePinner.check() for ' + hostname);
            return;
        };
        console.log("[+] OkHTTP CertificatePinner bypassed");
    } catch (err) {
        console.log("[!] OkHTTP bypass failed: " + err);
    }

    // Bypass TrustManager checks
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.checkServerTrusted.implementation = function(chain, authType) {
            console.log('[+] Bypassed TrustManagerImpl.checkServerTrusted()');
            return;
        };
        console.log("[+] TrustManagerImpl bypassed");
    } catch (err) {
        console.log("[!] TrustManager bypass failed: " + err);
    }

    // Bypass SSLContext
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log('[+] Bypassed SSLContext.init()');
            return this.init(keyManagers, trustManagers, secureRandom);
        };
        console.log("[+] SSLContext bypassed");
    } catch (err) {
        console.log("[!] SSLContext bypass failed: " + err);
    }

    console.log("[+] SSL Pinning bypass script loaded successfully");
});
EOF

    log "INFO" "Starting Frida with SSL bypass script..."
    log "INFO" "Package: $package_name"
    log "INFO" "Script: $frida_script"

    echo "Frida SSL bypass is starting..."
    echo "Check the Frida console for bypass status"
    echo "Press Ctrl+C to stop"
    echo ""

    # Run Frida with the script
    frida -U -l "$frida_script" -f "$package_name" --no-pause

    # Cleanup
    rm -f "$frida_script"
}

# APK certificate analysis
apk_certificate_analysis() {
    local device_serial="$1"

    log "INFO" "Analyzing APK certificates and pinning configuration..."

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

    log "INFO" "APK path: $apk_path"

    local output_file="$OUTPUT_DIR/apk_cert_analysis_${package_name}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife APK Certificate Analysis"
        echo "# Package: $package_name"
        echo "# APK Path: $apk_path"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Extract certificate information
        echo "## Certificate Information"
        local cert_info
        cert_info=$(execute_shell_cmd "$device_serial" "keytool -printcert -jarfile $apk_path 2>/dev/null || echo 'keytool not available on device'")
        echo "$cert_info"
        echo ""

        # Check for network security config
        echo "## Network Security Configuration"
        local nsc_check
        nsc_check=$(execute_shell_cmd "$device_serial" "unzip -p $apk_path 'res/xml/network_security_config.xml' 2>/dev/null || echo 'No network_security_config.xml found'")
        echo "$nsc_check"
        echo ""

        # Check for OkHTTP pinning
        echo "## OkHTTP Pinning Detection"
        local okhttp_pinning
        okhttp_pinning=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep -i okhttp | grep -v '\.dex\|\.so' | head -10")
        echo "$okhttp_pinning"
        echo ""

        # Check for TrustKit
        echo "## TrustKit Detection"
        local trustkit_check
        trustkit_check=$(execute_shell_cmd "$device_serial" "unzip -l $apk_path | grep -i trustkit")
        echo "$trustkit_check"
        echo ""

    } > "$output_file"

    log "SUCCESS" "APK certificate analysis completed. Results saved to $output_file"
}

# Network traffic interception setup
network_traffic_interception() {
    local device_serial="$1"

    echo "Network Traffic Interception"
    echo "============================"
    echo "1. Setup system proxy"
    echo "2. Install Burp certificate"
    echo "3. Configure Charles proxy"
    echo "4. Setup mitmproxy"
    echo "5. Start tcpdump capture"
    echo "0. Back"
    echo

    read -r -p "Choice: " choice

    case $choice in
        1) setup_system_proxy "$device_serial" ;;
        2) install_burp_certificate "$device_serial" ;;
        3) configure_charles_proxy "$device_serial" ;;
        4) setup_mitmproxy "$device_serial" ;;
        5) start_tcpdump_capture "$device_serial" ;;
        0) return 0 ;;
        *) log "ERROR" "Invalid choice" ;;
    esac
}

# Setup system proxy on device
setup_system_proxy() {
    local device_serial="$1"

    read -r -p "Enter proxy host: " proxy_host
    read -r -p "Enter proxy port: " proxy_port

    if [[ -z "$proxy_host" || -z "$proxy_port" ]]; then
        log "ERROR" "Proxy host and port are required"
        return 1
    fi

    log "INFO" "Setting up system proxy: $proxy_host:$proxy_port"

    # Set global proxy settings
    execute_shell_cmd "$device_serial" "settings put global http_proxy $proxy_host:$proxy_port"
    execute_shell_cmd "$device_serial" "settings put global https_proxy $proxy_host:$proxy_port"

    log "SUCCESS" "System proxy configured"
    echo "Proxy settings applied. Restart apps to take effect."
}

# Install Burp Suite certificate
install_burp_certificate() {
    local device_serial="$1"

    log "INFO" "Installing Burp Suite certificate..."

    echo "Burp Certificate Installation:"
    echo "============================="
    echo "1. Export certificate from Burp: Proxy > Options > Export CA Certificate"
    echo "2. Save as 'cacert.der'"
    echo "3. Push to device: adb push cacert.der /sdcard/"
    echo "4. Install via Settings > Security > Install from SD card"
    echo ""
    echo "Or use the following commands:"
    echo "adb push cacert.der /sdcard/"
    echo "adb shell am start -a android.settings.SECURITY_SETTINGS"
    echo ""
    echo "Note: Certificate must be renamed to have .crt extension on some devices"
}

# Configure Charles proxy
configure_charles_proxy() {
    local device_serial="$1"

    log "INFO" "Configuring Charles proxy..."

    echo "Charles Proxy Setup:"
    echo "==================="
    echo "1. Start Charles proxy on your computer"
    echo "2. Note the proxy IP and port (usually 8888)"
    echo "3. Configure device proxy settings"
    echo "4. Install Charles certificate from http://charlesproxy.com/getssl"
    echo ""

    read -r -p "Enter Charles proxy IP: " charles_ip
    read -r -p "Enter Charles proxy port (default 8888): " charles_port

    charles_port=${charles_port:-8888}

    if [[ -n "$charles_ip" ]]; then
        execute_shell_cmd "$device_serial" "settings put global http_proxy $charles_ip:$charles_port"
        execute_shell_cmd "$device_serial" "settings put global https_proxy $charles_ip:$charles_port"
        log "SUCCESS" "Charles proxy configured"
    fi
}

# SSL bypass assessment
ssl_bypass_assessment() {
    local device_serial="$1"

    log "INFO" "Performing SSL bypass assessment..."

    local output_file="$OUTPUT_DIR/ssl_assessment_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife SSL Bypass Assessment"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""

        # Check current proxy settings
        echo "## Current Proxy Configuration"
        local http_proxy
        http_proxy=$(execute_shell_cmd "$device_serial" "settings get global http_proxy")
        echo "HTTP Proxy: ${http_proxy:-None}"

        local https_proxy
        https_proxy=$(execute_shell_cmd "$device_serial" "settings get global https_proxy")
        echo "HTTPS Proxy: ${https_proxy:-None}"
        echo ""

        # Check installed certificates
        echo "## Installed CA Certificates"
        local cert_count
        cert_count=$(execute_shell_cmd "$device_serial" "ls -la /system/etc/security/cacerts/ | wc -l")
        echo "System CA certificates: $cert_count"

        local user_cert_count
        user_cert_count=$(execute_shell_cmd "$device_serial" "ls -la /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l || echo 0")
        echo "User-installed certificates: $user_cert_count"
        echo ""

        # Check for proxy tools
        echo "## Proxy Tools Available"
        local proxy_tools=""
        execute_shell_cmd "$device_serial" "which proxydroid" >/dev/null 2>&1 && proxy_tools="${proxy_tools}ProxyDroid, "
        execute_shell_cmd "$device_serial" "which ssldroid" >/dev/null 2>&1 && proxy_tools="${proxy_tools}SSLDroid, "
        execute_shell_cmd "$device_serial" "which postern" >/dev/null 2>&1 && proxy_tools="${proxy_tools}Postern, "

        echo "Available proxy apps: ${proxy_tools:-None detected}"
        echo ""

        # Frida status
        echo "## Frida Integration"
        local frida_status
        frida_status=$(execute_shell_cmd "$device_serial" "ps | grep -c frida")
        echo "Frida servers running: $frida_status"

        local frida_cli
        frida_cli=$(command -v frida 2>/dev/null && echo "Available" || echo "Not available")
        echo "Frida CLI: $frida_cli"
        echo ""

        # Recommendations
        echo "## SSL Bypass Readiness Assessment"
        local readiness_score=0

        if [[ -n "$http_proxy" && "$http_proxy" != "null" ]]; then
            echo "✓ Proxy configured (+20)"
            ((readiness_score += 20))
        else
            echo "✗ No proxy configured"
        fi

        if [[ "$user_cert_count" -gt 0 ]]; then
            echo "✓ User certificates installed (+15)"
            ((readiness_score += 15))
        else
            echo "✗ No user certificates installed"
        fi

        if [[ "$frida_status" -gt 0 ]]; then
            echo "✓ Frida server running (+25)"
            ((readiness_score += 25))
        else
            echo "✗ Frida server not running"
        fi

        if command -v frida >/dev/null 2>&1; then
            echo "✓ Frida CLI available (+20)"
            ((readiness_score += 20))
        else
            echo "✗ Frida CLI not available"
        fi

        if [[ -n "$proxy_tools" ]]; then
            echo "✓ Proxy tools available (+20)"
            ((readiness_score += 20))
        else
            echo "✗ No proxy tools detected"
        fi

        echo ""
        echo "## Overall Readiness Score: $readiness_score/100"

        if [[ $readiness_score -ge 80 ]]; then
            echo "🎉 EXCELLENT: Ready for SSL bypass operations"
        elif [[ $readiness_score -ge 60 ]]; then
            echo "✅ GOOD: Minor setup may be needed"
        elif [[ $readiness_score -ge 40 ]]; then
            echo "⚠️ FAIR: Additional tools recommended"
        else
            echo "❌ POOR: Significant setup required"
        fi

    } > "$output_file"

    log "SUCCESS" "SSL bypass assessment completed. Readiness score: $readiness_score/100. Results saved to $output_file"
}
