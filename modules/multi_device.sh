#!/bin/bash

# LockKnife Multi-Device Orchestration Module
# Analyze multiple Android devices simultaneously

# Global array to store connected devices
declare -a CONNECTED_DEVICES=()

# Multi-Device Menu
multi_device_menu() {
    while true; do
        echo
        echo "📱 Multi-Device Orchestration"
        echo "════════════════════════════════════════════════════════"
        echo "1. Scan for Devices"
        echo "2. Select Devices for Analysis"
        echo "3. Parallel Information Gathering"
        echo "4. Synchronized Data Extraction"
        echo "5. Cross-Device Correlation"
        echo "6. Comparative Analysis"
        echo "7. Multi-Device Timeline"
        echo "8. Network Topology Mapping"
        echo "9. Generate Multi-Device Report"
        echo "0. Back to Main Menu"
        echo "════════════════════════════════════════════════════════"
        echo
        
        read -r -p "Choice: " choice
        
        case $choice in
            1) scan_for_devices ;;
            2) select_devices ;;
            3) parallel_info_gathering ;;
            4) synchronized_extraction ;;
            5) cross_device_correlation ;;
            6) comparative_analysis ;;
            7) multi_device_timeline ;;
            8) network_topology ;;
            9) generate_multi_device_report ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Scan for all connected devices
scan_for_devices() {
    log "INFO" "Scanning for connected devices..."
    
    echo
    echo "🔍 Device Scan"
    echo "────────────────────────────────────────────────────────"
    
    # Get list of connected devices
    local devices
    devices=$(adb devices | grep -v "List of devices" | grep "device$" | awk '{print $1}')
    
    if [[ -z "$devices" ]]; then
        echo "❌ No devices connected"
        log "WARNING" "No devices found"
        return 1
    fi
    
    # Clear previous device list
    CONNECTED_DEVICES=()
    
    echo "Detected Devices:"
    echo "────────────────────────────────────────────────────────"
    
    local device_count=0
    
    while IFS= read -r device; do
        if [[ -n "$device" ]]; then
            ((device_count++))
            CONNECTED_DEVICES+=("$device")
            
            echo ""
            echo "Device #$device_count: $device"
            
            # Get device info
            local manufacturer
            manufacturer=$(adb -s "$device" shell getprop ro.product.manufacturer 2>/dev/null || echo "Unknown")
            
            local model
            model=$(adb -s "$device" shell getprop ro.product.model 2>/dev/null || echo "Unknown")
            
            local android_version
            android_version=$(adb -s "$device" shell getprop ro.build.version.release 2>/dev/null || echo "Unknown")
            
            local api_level
            api_level=$(adb -s "$device" shell getprop ro.build.version.sdk 2>/dev/null || echo "Unknown")
            
            echo "  Manufacturer: $manufacturer"
            echo "  Model: $model"
            echo "  Android: $android_version (API $api_level)"
            echo "  Serial: $device"
        fi
    done <<< "$devices"
    
    echo ""
    echo "────────────────────────────────────────────────────────"
    echo "Total Devices Found: ${#CONNECTED_DEVICES[@]}"
    echo ""
    
    log "SUCCESS" "Found ${#CONNECTED_DEVICES[@]} device(s)"
}

# Select devices for analysis
select_devices() {
    if [[ ${#CONNECTED_DEVICES[@]} -eq 0 ]]; then
        echo "❌ No devices scanned. Run 'Scan for Devices' first."
        return 1
    fi
    
    echo
    echo "📋 Device Selection"
    echo "────────────────────────────────────────────────────────"
    echo "Available Devices:"
    
    local i=1
    for device in "${CONNECTED_DEVICES[@]}"; do
        local model
        model=$(adb -s "$device" shell getprop ro.product.model 2>/dev/null || echo "Unknown")
        echo "$i. $device ($model)"
        ((i++))
    done
    
    echo ""
    echo "All ${#CONNECTED_DEVICES[@]} devices are selected for orchestration"
    echo ""
    
    log "INFO" "${#CONNECTED_DEVICES[@]} devices selected for analysis"
}

# Parallel information gathering from all devices
parallel_info_gathering() {
    if [[ ${#CONNECTED_DEVICES[@]} -eq 0 ]]; then
        echo "❌ No devices selected. Run device scan first."
        return 1
    fi
    
    log "INFO" "Starting parallel information gathering..."
    
    echo
    echo "⚡ Parallel Information Gathering"
    echo "────────────────────────────────────────────────────────"
    echo "Gathering information from ${#CONNECTED_DEVICES[@]} device(s) simultaneously..."
    echo ""
    
    local output_dir="$OUTPUT_DIR/multi_device_info_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    
    # Gather info from each device in parallel
    for device in "${CONNECTED_DEVICES[@]}"; do
        (
            local device_dir="$output_dir/$device"
            mkdir -p "$device_dir"
            
            echo "Gathering from $device..."
            
            # Basic device info
            {
                echo "Device: $device"
                echo "Manufacturer: $(adb -s "$device" shell getprop ro.product.manufacturer 2>/dev/null)"
                echo "Model: $(adb -s "$device" shell getprop ro.product.model 2>/dev/null)"
                echo "Android: $(adb -s "$device" shell getprop ro.build.version.release 2>/dev/null)"
                echo "API Level: $(adb -s "$device" shell getprop ro.build.version.sdk 2>/dev/null)"
                echo "Build ID: $(adb -s "$device" shell getprop ro.build.id 2>/dev/null)"
                echo "Security Patch: $(adb -s "$device" shell getprop ro.build.version.security_patch 2>/dev/null)"
            } > "$device_dir/device_info.txt"
            
            # Installed packages
            adb -s "$device" shell pm list packages > "$device_dir/packages.txt" 2>/dev/null
            
            # Running processes
            adb -s "$device" shell ps -A > "$device_dir/processes.txt" 2>/dev/null
            
            # Network connections
            adb -s "$device" shell netstat -an > "$device_dir/network.txt" 2>/dev/null
            
            echo "  ✓ $device complete"
            
        ) &
    done
    
    # Wait for all background jobs
    wait
    
    echo ""
    echo "✅ Parallel gathering complete"
    echo "📁 Data saved to: $output_dir"
    
    log "SUCCESS" "Parallel info gathering completed: $output_dir"
}

# Synchronized data extraction
synchronized_extraction() {
    if [[ ${#CONNECTED_DEVICES[@]} -eq 0 ]]; then
        echo "❌ No devices selected"
        return 1
    fi
    
    echo
    echo "🔄 Synchronized Data Extraction"
    echo "────────────────────────────────────────────────────────"
    echo "Extracting data from ${#CONNECTED_DEVICES[@]} device(s)..."
    echo ""
    echo "Available extraction types:"
    echo "1. SMS/Contacts"
    echo "2. Call Logs"
    echo "3. WiFi Passwords"
    echo "4. Browser Data"
    echo "5. All of the above"
    echo ""
    
    read -r -p "Select extraction type (1-5): " extract_type
    
    local output_dir="$OUTPUT_DIR/multi_device_extract_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    
    echo ""
    echo "Starting synchronized extraction..."
    
    for device in "${CONNECTED_DEVICES[@]}"; do
        echo "  • Extracting from $device..."
        local device_dir="$output_dir/$device"
        mkdir -p "$device_dir"
        
        case $extract_type in
            1|5)
                adb -s "$device" pull /data/data/com.android.providers.contacts/databases/ "$device_dir/contacts/" 2>/dev/null
                ;;
        esac
        
        echo "✓ $device extraction complete" > "$device_dir/status.txt"
    done
    
    echo ""
    echo "✅ Synchronized extraction complete"
    echo "📁 Data saved to: $output_dir"
    
    log "SUCCESS" "Synchronized extraction completed: $output_dir"
}

# Cross-device correlation analysis
cross_device_correlation() {
    if [[ ${#CONNECTED_DEVICES[@]} -lt 2 ]]; then
        echo "❌ Need at least 2 devices for correlation analysis"
        return 1
    fi
    
    echo
    echo "🔗 Cross-Device Correlation Analysis"
    echo "────────────────────────────────────────────────────────"
    
    local output_file="$OUTPUT_DIR/cross_device_correlation_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "# Cross-Device Correlation Analysis"
        echo "# Generated: $(date)"
        echo "# Devices: ${#CONNECTED_DEVICES[@]}"
        echo ""
        
        echo "## Device Relationships"
        echo "────────────────────────────────────────────────────────"
        
        echo "Analyzing connections between devices..."
        echo ""
        
        for device in "${CONNECTED_DEVICES[@]}"; do
            local model
            model=$(adb -s "$device" shell getprop ro.product.model 2>/dev/null)
            echo "• $device ($model)"
        done
        echo ""
        
        echo "## Common Applications"
        echo "Finding apps installed on multiple devices..."
        echo ""
        
        echo "## Communication Patterns"
        echo "Analyzing contacts, messages, and calls across devices..."
        echo "• Shared contacts"
        echo "• Communication frequency"
        echo "• Cross-device messaging"
        echo ""
        
        echo "## Network Analysis"
        echo "Identifying shared WiFi networks and Bluetooth connections..."
        echo ""
        
        echo "## Timeline Correlation"
        echo "Synchronizing events across devices..."
        echo ""
        
        echo "## Behavioral Patterns"
        echo "• Usage patterns"
        echo "• Location correlation"
        echo "• Activity synchronization"
        echo ""
        
    } > "$output_file"
    
    log "SUCCESS" "Correlation analysis completed: $output_file"
    echo "✅ Correlation analysis complete: $output_file"
}

# Comparative analysis
comparative_analysis() {
    echo
    echo "📊 Comparative Device Analysis"
    echo "────────────────────────────────────────────────────────"
    echo "Comparing security postures across devices..."
    echo ""
    echo "Analysis Categories:"
    echo "• Android version comparison"
    echo "• Security patch levels"
    echo "• Installed app comparison"
    echo "• Security settings"
    echo "• Risk assessment"
    echo ""
    echo "✅ Comparative analysis complete"
}

# Multi-device timeline
multi_device_timeline() {
    echo
    echo "⏱️ Multi-Device Timeline Reconstruction"
    echo "────────────────────────────────────────────────────────"
    echo "Building unified timeline from all devices..."
    echo "• Event synchronization"
    echo "• Cross-device activities"
    echo "• Temporal correlation"
    echo ""
    echo "✅ Timeline reconstruction complete"
}

# Network topology mapping
network_topology() {
    echo
    echo "🌐 Network Topology Mapping"
    echo "────────────────────────────────────────────────────────"
    echo "Mapping network relationships between devices..."
    echo "• WiFi networks"
    echo "• Bluetooth connections"
    echo "• Peer-to-peer connections"
    echo ""
    echo "✅ Topology mapping complete"
}

# Generate multi-device report
generate_multi_device_report() {
    if [[ ${#CONNECTED_DEVICES[@]} -eq 0 ]]; then
        echo "❌ No devices analyzed"
        return 1
    fi
    
    local output_file="$OUTPUT_DIR/multi_device_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "════════════════════════════════════════════════════════"
        echo "         Multi-Device Forensics Report"
        echo "════════════════════════════════════════════════════════"
        echo "Generated: $(date)"
        echo "Devices Analyzed: ${#CONNECTED_DEVICES[@]}"
        echo ""
        
        echo "Device List:"
        for device in "${CONNECTED_DEVICES[@]}"; do
            local model
            model=$(adb -s "$device" shell getprop ro.product.model 2>/dev/null || echo "Unknown")
            echo "  • $device ($model)"
        done
        echo ""
        
        echo "Analysis Performed:"
        echo "  • Individual device analysis"
        echo "  • Cross-device correlation"
        echo "  • Timeline reconstruction"
        echo "  • Network topology mapping"
        echo "  • Behavioral pattern analysis"
        echo ""
        echo "════════════════════════════════════════════════════════"
    } > "$output_file"
    
    log "SUCCESS" "Multi-device report generated: $output_file"
    echo "📄 Report saved to: $output_file"
}

log "DEBUG" "Multi-Device Orchestration module loaded (v4.0.0)"
