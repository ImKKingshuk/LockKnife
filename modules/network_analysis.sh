#!/bin/bash

# LockKnife Network Analysis Module
# Provides comprehensive network traffic analysis capabilities

# Capture network traffic
capture_network_traffic() {
    local device_serial="$1"
    local duration="$2"
    local filter="${3:-$PCAP_FILTER}"
    local output_file="$OUTPUT_DIR/network_capture_$(date +%Y%m%d_%H%M%S).pcap"

    log "INFO" "Starting network traffic capture for $duration seconds..."
    log "DEBUG" "Using filter: $filter"

    if ! execute_with_retry "adb -s $device_serial shell 'command -v tcpdump'" "tcpdump check" | grep -q "tcpdump"; then
        log "ERROR" "tcpdump not found on device"
        log "INFO" "Attempting to push a static tcpdump binary..."

        local tcpdump_path="$TEMP_DIR/tcpdump"
        if [ -f "$tcpdump_path" ]; then
            log "DEBUG" "Using existing tcpdump binary"
        else
            log "ERROR" "No tcpdump binary available. Please install tcpdump on the device or provide a static binary."
            return 1
        fi

        execute_with_retry "adb -s $device_serial push $tcpdump_path /data/local/tmp/" "Push tcpdump"
        execute_with_retry "adb -s $device_serial shell 'chmod 755 /data/local/tmp/tcpdump'" "Set tcpdump permissions"

        local tcpdump_cmd="/data/local/tmp/tcpdump"
    else
        local tcpdump_cmd="tcpdump"
    fi

    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for network traffic capture"
        return 1
    fi

    local device_file="/data/local/tmp/network_capture.pcap"

    log "INFO" "Capturing network traffic for $duration seconds..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"$tcpdump_cmd -i any -w $device_file -s 0 $filter &\"'" "Start capture"

    sleep "$duration"

    log "INFO" "Stopping network traffic capture..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"pkill tcpdump\"'" "Stop capture"

    sleep 2

    log "INFO" "Pulling network capture file..."
    if execute_with_retry "adb -s $device_serial pull $device_file $output_file" "Pull capture"; then
        log "SUCCESS" "Network capture saved to $output_file"

        execute_with_retry "adb -s $device_serial shell 'rm $device_file'" "Remove device file" || true

        if [ -s "$output_file" ]; then
            log "INFO" "Capture file size: $(du -h "$output_file" | cut -f1)"

            analyze_network_capture "$output_file"
        else
            log "ERROR" "Capture file is empty. Capture may have failed."
            return 1
        fi
    else
        log "ERROR" "Failed to pull capture file"
        return 1
    fi

    return 0
}

# Analyze network capture file
analyze_network_capture() {
    local capture_file="$1"
    local analysis_file="${capture_file%.pcap}_analysis.txt"

    log "INFO" "Analyzing network capture file..."

    if ! command -v tshark &>/dev/null; then
        log "WARNING" "tshark not found. Basic analysis only."

        {
            echo "# LockKnife Network Capture Analysis"
            echo "# Capture file: $capture_file"
            echo "# Generated: $(date)"
            echo ""
            echo "Note: Install tshark for more detailed analysis."
            echo ""
            echo "Capture file size: $(du -h "$capture_file" | cut -f1)"
            echo ""
        } > "$analysis_file"
    else
        log "INFO" "Using tshark for detailed analysis..."

        {
            echo "# LockKnife Network Capture Analysis"
            echo "# Capture file: $capture_file"
            echo "# Generated: $(date)"
            echo ""

            echo "## Capture Summary"
            tshark -r "$capture_file" -q -z io,stat,1 2>/dev/null || echo "No packets captured"
            echo ""

            echo "## Protocol Hierarchy"
            tshark -r "$capture_file" -q -z io,phs 2>/dev/null || echo "Protocol hierarchy not available"
            echo ""

            echo "## HTTP Requests"
            tshark -r "$capture_file" -Y "http.request" -T fields -e http.host -e http.request.uri 2>/dev/null | sort | uniq -c | sort -nr | head -20 || echo "No HTTP requests found"
            echo ""

            echo "## DNS Queries"
            tshark -r "$capture_file" -Y "dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -nr | head -20 || echo "No DNS queries found"
            echo ""

            echo "## IP Conversations"
            tshark -r "$capture_file" -q -z conv,ip 2>/dev/null | head -20 || echo "No IP conversations found"
            echo ""

            echo "## Potentially Unencrypted Traffic"
            tshark -r "$capture_file" -Y "http and !(ssl or tls)" -T fields -e ip.dst -e http.request.full_uri 2>/dev/null | sort | uniq || echo "No unencrypted HTTP traffic detected"
            echo ""

            echo "## SSL/TLS Server Names"
            tshark -r "$capture_file" -Y "ssl.handshake.type == 1" -T fields -e ssl.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -nr || echo "No SSL/TLS server names found"

        } > "$analysis_file"
    fi

    log "SUCCESS" "Analysis saved to $analysis_file"
    return 0
}

# Network analysis submenu
submenu_network_analysis() {
    local device_serial="$1"
    log "INFO" "Network Traffic Analysis Options:"
    echo "1. Capture All Traffic (30s)"
    echo "2. Capture Traffic with Custom Duration"
    echo "3. Capture Traffic with Custom Filter"
    echo "4. Analyze Existing Capture"
    read -r -p "Choice: " choice
    case $choice in
        1) capture_network_traffic "$device_serial" 30 ;;
        2)
           read -r -p "Enter capture duration (seconds): " duration
           if [[ "$duration" =~ ^[0-9]+$ ]]; then
               capture_network_traffic "$device_serial" "$duration"
           else
               log "ERROR" "Invalid duration. Please enter a number."
           fi
           ;;
        3)
           read -r -p "Enter capture duration (seconds): " duration
           read -r -p "Enter capture filter (e.g., 'port 80' or 'host 8.8.8.8'): " filter
           if [[ "$duration" =~ ^[0-9]+$ ]]; then
               capture_network_traffic "$device_serial" "$duration" "$filter"
           else
               log "ERROR" "Invalid duration. Please enter a number."
           fi
           ;;
        4)
           local captures
           mapfile -t captures < <(find "$OUTPUT_DIR" -name "network_capture_*.pcap" | sort -r)
           if [ ${#captures[@]} -eq 0 ]; then
               log "ERROR" "No capture files found. Create a capture first."
               return 1
           fi

           echo "Available captures:"
           for i in "${!captures[@]}"; do
               echo "$((i+1)). $(basename "${captures[$i]}")"
           done

           read -r -p "Select capture number: " capture_num

           if [[ "$capture_num" =~ ^[0-9]+$ && "$capture_num" -ge 1 && "$capture_num" -le ${#captures[@]} ]]; then
               analyze_network_capture "${captures[$((capture_num-1))]}"
           else
               log "ERROR" "Invalid selection."
           fi
           ;;
        *) log "ERROR" "Invalid choice." ;;
    esac
}
