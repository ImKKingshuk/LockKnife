#!/bin/bash

# LockKnife Advanced Memory Analysis Module
# Provides comprehensive memory analysis and dumping capabilities

# Memory analysis types
MEMORY_ANALYSIS_BASIC=1
MEMORY_ANALYSIS_FULL=2
MEMORY_ANALYSIS_DEEP=3

# Memory regions to analyze
MEMORY_REGIONS=(
    "heap"      # Application heap
    "stack"     # Stack memory
    "anon"      # Anonymous memory
    "ashmem"    # Android shared memory
    "dmabuf"    # DMA buffer memory
    "gpu"       # GPU memory
)

# Memory dump tools
MEMORY_TOOLS=(
    "memdump"           # Basic memory dumping
    "procmem"          # Process memory analysis
    "frida"            # Dynamic instrumentation
    "gdb"              # GNU debugger
    "lldb"             # LLVM debugger
)

# Analyze process memory maps
analyze_memory_maps() {
    local device_serial="$1"
    local pid="${2:-$$}"
    local output_file="$OUTPUT_DIR/memory_maps_${pid}_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing memory maps for PID: $pid"

    if ! device_supports_feature "$device_serial" "root"; then
        log "ERROR" "Root access required for memory analysis"
        return 1
    fi

    # Get memory maps
    local maps_content
    maps_content=$(execute_root_cmd "$device_serial" "cat /proc/$pid/maps" "Memory maps dump")

    if [[ -z "$maps_content" ]]; then
        log "ERROR" "Failed to read memory maps for PID $pid"
        return 1
    fi

    # Analyze memory regions
    {
        echo "# Memory Maps Analysis for PID $pid"
        echo "# Generated: $(date)"
        echo ""
        echo "## Memory Regions Summary"
        echo ""

        echo "$maps_content" | awk '
        BEGIN {
            total_regions = 0
            heap_size = 0
            stack_size = 0
            anon_size = 0
        }
        {
            total_regions++
            start_addr = strtonum("0x" $1)
            end_addr = strtonum("0x" $2)
            size = end_addr - start_addr

            if ($6 ~ /heap/) heap_size += size
            if ($6 ~ /stack/) stack_size += size
            if ($6 ~ /\[anon\]/) anon_size += size
        }
        END {
            print "Total memory regions:", total_regions
            print "Heap size:", heap_size / 1024 / 1024, "MB"
            print "Stack size:", stack_size / 1024, "KB"
            print "Anonymous memory:", anon_size / 1024 / 1024, "MB"
        }
        '

        echo ""
        echo "## Detailed Memory Maps"
        echo ""
        echo "Start Addr    End Addr      Permissions  Offset     Device     Path"
        echo "------------  ------------  -----------  ---------  ---------  ----"

        echo "$maps_content" | while read -r line; do
            # Format and display memory map entry
            echo "$line"
        done

        echo ""
        echo "## Suspicious Memory Regions"
        echo ""

        # Look for suspicious memory regions
        echo "$maps_content" | awk '
        {
            # Check for executable anonymous memory (potential code injection)
            if ($2 ~ /^rwx/ && $6 ~ /\[anon\]/) {
                print "POTENTIAL CODE INJECTION: " $1 " - " $2 " " $6
            }

            # Check for large anonymous mappings
            if ($6 ~ /\[anon\]/) {
                start_addr = strtonum("0x" $1)
                end_addr = strtonum("0x" $2)
                size = end_addr - start_addr
                if (size > 104857600) { # 100MB
                    print "LARGE ANONYMOUS MAPPING: " $1 " - " $2 " (" size/1024/1024 "MB) " $6
                }
            }
        }
        '

    } > "$output_file"

    log "SUCCESS" "Memory maps analysis saved to $output_file"
    return 0
}

# Dump process memory
dump_process_memory() {
    local device_serial="$1"
    local pid="$2"
    local output_dir="$OUTPUT_DIR/memory_dump_${pid}_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Dumping memory for process PID: $pid"

    if ! device_supports_feature "$device_serial" "root"; then
        log "ERROR" "Root access required for memory dumping"
        return 1
    fi

    mkdir -p "$output_dir"

    # Get memory maps first
    local maps_file="$output_dir/maps.txt"
    execute_root_cmd "$device_serial" "cat /proc/$pid/maps" "Memory maps" > "$maps_file"

    # Dump each memory region
    local dumped_regions=0
    local total_size=0

    while read -r start end perms offset device inode path; do
        # Skip non-readable regions
        [[ "$perms" != *r* ]] && continue

        # Convert hex addresses to decimal for size calculation
        local start_dec=$((16#${start%:*}))
        local end_dec=$((16#${end%:*}))
        local size=$((end_dec - start_dec))

        # Skip very large regions (>1GB) to avoid excessive dump size
        [[ $size -gt 1073741824 ]] && continue

        # Skip regions that are all zeros (often just reserved memory)
        if [[ "$MEMORY_ANALYSIS_DEPTH" != "deep" ]]; then
            # Quick check if region is all zeros
            local sample
            sample=$(execute_root_cmd "$device_serial" "dd if=/proc/$pid/mem bs=1 skip=$start_dec count=1024 2>/dev/null | od -t x1 | head -5" "Memory sample")
            if echo "$sample" | grep -q "00000000"; then
                continue
            fi
        fi

        # Create filename for this region
        local region_name
        if [[ -n "$path" ]]; then
            region_name=$(basename "$path" | sed 's/[^a-zA-Z0-9]/_/g')
        else
            region_name="anon_${start}"
        fi

        local dump_file="$output_dir/${region_name}_${start}.mem"

        log "DEBUG" "Dumping memory region: $start-$end ($size bytes) -> $dump_file"

        # Dump the memory region
        if execute_root_cmd "$device_serial" "dd if=/proc/$pid/mem bs=1 skip=$start_dec count=$size of=/data/local/tmp/mem_dump.tmp 2>/dev/null" "Memory dump"; then
            # Pull the dump file
            pull_file_from_device "$device_serial" "/data/local/tmp/mem_dump.tmp" "$dump_file"

            # Clean up device temp file
            execute_root_cmd "$device_serial" "rm /data/local/tmp/mem_dump.tmp" "Cleanup temp file"

            # Analyze the dumped memory
            analyze_memory_dump "$dump_file" "$output_dir"

            ((dumped_regions++))
            ((total_size += size))
        fi

        # Progress indicator
        log_progress "$dumped_regions" 50 "Dumping memory regions"

    done < "$maps_file"

    log_progress_complete

    # Create summary
    local summary_file="$output_dir/dump_summary.txt"
    {
        echo "# Memory Dump Summary"
        echo "# PID: $pid"
        echo "# Generated: $(date)"
        echo ""
        echo "Regions dumped: $dumped_regions"
        echo "Total size: $((total_size / 1024 / 1024)) MB"
        echo "Analysis depth: $MEMORY_ANALYSIS_DEPTH"
        echo ""
        echo "## Dumped Files"
        find "$output_dir" -name "*.mem" -exec basename {} \; | while read -r file; do
            local file_size
            file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            echo "- $file ($(($file_size / 1024)) KB)"
        done
    } > "$summary_file"

    log "SUCCESS" "Memory dump completed. $dumped_regions regions dumped ($((total_size / 1024 / 1024)) MB)"
    log "INFO" "Results saved to $output_dir"

    return 0
}

# Analyze memory dump file
analyze_memory_dump() {
    local dump_file="$1"
    local output_dir="$2"
    local analysis_file="${dump_file}.analysis"

    log "DEBUG" "Analyzing memory dump: $(basename "$dump_file")"

    {
        echo "# Memory Dump Analysis: $(basename "$dump_file")"
        echo "# Generated: $(date)"
        echo ""

        # File information
        local file_size
        file_size=$(stat -f%z "$dump_file" 2>/dev/null || stat -c%s "$dump_file" 2>/dev/null)
        echo "File size: $(($file_size / 1024)) KB"

        # Entropy analysis
        local entropy
        entropy=$(analyze_memory_entropy "$dump_file")
        echo "Entropy: $entropy"

        # String analysis
        echo ""
        echo "## Extracted Strings"
        strings "$dump_file" 2>/dev/null | head -20 | while read -r string; do
            [[ ${#string} -gt 4 ]] && echo "- $string"
        done

        # Pattern analysis based on depth
        case "$MEMORY_ANALYSIS_DEPTH" in
            "basic")
                # Basic analysis - just strings and entropy
                ;;
            "full")
                # Full analysis - look for common patterns
                echo ""
                echo "## Pattern Analysis"

                # Look for URLs
                local urls
                urls=$(strings "$dump_file" 2>/dev/null | grep -E 'https?://[^[:space:]]+' | head -10)
                if [[ -n "$urls" ]]; then
                    echo "### URLs Found"
                    echo "$urls" | while read -r url; do
                        echo "- $url"
                    done
                fi

                # Look for email addresses
                local emails
                emails=$(strings "$dump_file" 2>/dev/null | grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -10)
                if [[ -n "$emails" ]]; then
                    echo "### Email Addresses Found"
                    echo "$emails" | while read -r email; do
                        echo "- $email"
                    done
                fi
                ;;
            "deep")
                # Deep analysis - cryptographic material, keys, etc.
                echo ""
                echo "## Cryptographic Analysis"

                # Look for potential cryptographic keys
                local potential_keys
                potential_keys=$(strings "$dump_file" 2>/dev/null | grep -E '^([0-9a-fA-F]{32}|[0-9a-fA-F]{64})$' | head -10)
                if [[ -n "$potential_keys" ]]; then
                    echo "### Potential Cryptographic Keys"
                    echo "$potential_keys" | while read -r key; do
                        echo "- $key (${#key} chars)"
                    done
                fi

                # Look for base64 encoded data
                local b64_data
                b64_data=$(strings "$dump_file" 2>/dev/null | grep -E '^[A-Za-z0-9+/=]{20,}$' | head -5)
                if [[ -n "$b64_data" ]]; then
                    echo "### Base64 Encoded Data"
                    echo "$b64_data" | while read -r data; do
                        echo "- $data (${#data} chars)"
                    done
                fi
                ;;
        esac

    } > "$analysis_file"

    log "DEBUG" "Analysis completed for $(basename "$dump_file")"
}

# Calculate memory entropy
analyze_memory_entropy() {
    local file="$1"

    if ! command -v ent &>/dev/null; then
        # Fallback entropy calculation
        local bytes
        bytes=$(od -t u1 -An "$file" 2>/dev/null | tr -s ' ' | head -1000)
        local unique_bytes
        unique_bytes=$(echo "$bytes" | tr ' ' '\n' | sort | uniq | wc -l)
        echo "scale=2; $unique_bytes / 256" | bc 2>/dev/null || echo "unknown"
    else
        ent "$file" 2>/dev/null | grep "Entropy" | awk '{print $3}'
    fi
}

# Find processes by name
find_processes_by_name() {
    local device_serial="$1"
    local process_name="$2"

    log "INFO" "Finding processes matching: $process_name"

    local processes
    processes=$(execute_shell_cmd "$device_serial" "ps -A | grep '$process_name'" "Process search")

    if [[ -z "$processes" ]]; then
        log "WARNING" "No processes found matching: $process_name"
        return 1
    fi

    echo "$processes" | while read -r line; do
        # Parse process info (USER, PID, PPID, VSIZE, RSS, WCHAN, PC, NAME)
        local pid
        pid=$(echo "$line" | awk '{print $2}')
        local name
        name=$(echo "$line" | awk '{for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)

        echo "$pid:$name"
    done

    return 0
}

# Monitor process memory usage
monitor_memory_usage() {
    local device_serial="$1"
    local pid="$2"
    local duration="${3:-60}"
    local interval="${4:-5}"
    local output_file="$OUTPUT_DIR/memory_monitor_${pid}_$(date +%Y%m%d_%H%M%S).csv"

    log "INFO" "Monitoring memory usage for PID $pid (duration: ${duration}s, interval: ${interval}s)"

    {
        echo "timestamp,pid,vsize,rss,pss,uss"
        local start_time
        start_time=$(date +%s)

        while [[ $(($(date +%s) - start_time)) -lt $duration ]]; do
            local mem_info
            mem_info=$(execute_shell_cmd "$device_serial" "cat /proc/$pid/status | grep -E '(VmSize|VmRSS)'" "Memory status")

            local vsize
            vsize=$(echo "$mem_info" | grep VmSize | awk '{print $2}' || echo "0")
            local rss
            rss=$(echo "$mem_info" | grep VmRSS | awk '{print $2}' || echo "0")

            # Try to get PSS and USS if available (requires root for some processes)
            local pss
            pss=$(execute_root_cmd "$device_serial" "cat /proc/$pid/smaps_rollup | grep Pss | awk '{print \$2}'" "PSS memory" 2>/dev/null || echo "0")
            local uss
            uss=$(execute_root_cmd "$device_serial" "cat /proc/$pid/smaps_rollup | grep Private | awk '{sum+=\$2} END {print sum}'" "USS memory" 2>/dev/null || echo "0")

            echo "$(date +%s),$pid,$vsize,$rss,$pss,$uss"

            sleep "$interval"
        done
    } > "$output_file"

    log "SUCCESS" "Memory monitoring data saved to $output_file"
    return 0
}

# Analyze memory leaks
analyze_memory_leaks() {
    local device_serial="$1"
    local pid="$2"
    local output_file="$OUTPUT_DIR/memory_leaks_${pid}_$(date +%Y%m%d_%H%M%S).txt"

    log "INFO" "Analyzing potential memory leaks for PID $pid"

    # Monitor memory growth over time
    local initial_mem
    initial_mem=$(execute_shell_cmd "$device_serial" "cat /proc/$pid/status | grep VmRSS | awk '{print \$2}'" "Initial memory")

    sleep 10

    local final_mem
    final_mem=$(execute_shell_cmd "$device_serial" "cat /proc/$pid/status | grep VmRSS | awk '{print \$2}'" "Final memory")

    local growth=$((final_mem - initial_mem))

    {
        echo "# Memory Leak Analysis for PID $pid"
        echo "# Generated: $(date)"
        echo ""
        echo "Initial RSS memory: ${initial_mem} KB"
        echo "Final RSS memory: ${final_mem} KB"
        echo "Memory growth: ${growth} KB"
        echo ""

        if [[ $growth -gt 1000 ]]; then  # More than 1MB growth
            echo "⚠️  POTENTIAL MEMORY LEAK DETECTED"
            echo "Memory grew by more than 1MB in 10 seconds"
        else
            echo "✓ No significant memory growth detected"
        fi

        echo ""
        echo "## Memory Map Changes"
        # Compare memory maps
        local initial_maps
        initial_maps=$(execute_shell_cmd "$device_serial" "cat /proc/$pid/maps | wc -l" "Initial maps count")
        sleep 10
        local final_maps
        final_maps=$(execute_shell_cmd "$device_serial" "cat /proc/$pid/maps | wc -l" "Final maps count")

        echo "Initial memory regions: $initial_maps"
        echo "Final memory regions: $final_maps"
        echo "Region change: $((final_maps - initial_maps))"

    } > "$output_file"

    log "SUCCESS" "Memory leak analysis saved to $output_file"
    return 0
}

# Advanced memory analysis menu
advanced_memory_analysis() {
    local device_serial="$1"

    while true; do
        echo
        echo "Advanced Memory Analysis"
        echo "======================="
        echo "1. Analyze Process Memory Maps"
        echo "2. Dump Process Memory"
        echo "3. Find Processes by Name"
        echo "4. Monitor Memory Usage"
        echo "5. Analyze Memory Leaks"
        echo "6. Full System Memory Analysis"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1)
                read -r -p "Enter PID (default: current shell): " pid
                pid=${pid:-$$}
                analyze_memory_maps "$device_serial" "$pid"
                ;;
            2)
                read -r -p "Enter PID to dump: " pid
                if [[ -n "$pid" ]]; then
                    dump_process_memory "$device_serial" "$pid"
                fi
                ;;
            3)
                read -r -p "Enter process name pattern: " pattern
                if [[ -n "$pattern" ]]; then
                    local processes
                    mapfile -t processes < <(find_processes_by_name "$device_serial" "$pattern")
                    if [[ ${#processes[@]} -gt 0 ]]; then
                        echo "Found processes:"
                        for proc in "${processes[@]}"; do
                            local pid name
                            IFS=':' read -r pid name <<< "$proc"
                            echo "PID: $pid - $name"
                        done
                    fi
                fi
                ;;
            4)
                read -r -p "Enter PID to monitor: " pid
                read -r -p "Enter duration in seconds (default: 60): " duration
                duration=${duration:-60}
                if [[ -n "$pid" ]]; then
                    monitor_memory_usage "$device_serial" "$pid" "$duration"
                fi
                ;;
            5)
                read -r -p "Enter PID to analyze for memory leaks: " pid
                if [[ -n "$pid" ]]; then
                    analyze_memory_leaks "$device_serial" "$pid"
                fi
                ;;
            6)
                full_system_memory_analysis "$device_serial"
                ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Full system memory analysis
full_system_memory_analysis() {
    local device_serial="$1"
    local output_dir="$OUTPUT_DIR/system_memory_analysis_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Performing full system memory analysis"

    mkdir -p "$output_dir"

    # Get system memory information
    local meminfo_file="$output_dir/meminfo.txt"
    execute_shell_cmd "$device_serial" "cat /proc/meminfo" "System memory info" > "$meminfo_file"

    # Get process memory usage summary
    local proc_mem_file="$output_dir/process_memory.txt"
    execute_shell_cmd "$device_serial" "ps -A -o pid,ppid,comm,rss,vsize --sort=-rss | head -20" "Process memory summary" > "$proc_mem_file"

    # Analyze memory fragmentation
    local buddyinfo_file="$output_dir/buddyinfo.txt"
    execute_root_cmd "$device_serial" "cat /proc/buddyinfo" "Memory fragmentation" > "$buddyinfo_file" 2>/dev/null || echo "Buddyinfo not available" > "$buddyinfo_file"

    # Create analysis report
    local report_file="$output_dir/analysis_report.txt"
    {
        echo "# System Memory Analysis Report"
        echo "# Generated: $(date)"
        echo ""

        echo "## System Memory Information"
        echo "\`\`\`"
        cat "$meminfo_file"
        echo "\`\`\`"
        echo ""

        echo "## Top Memory-Consuming Processes"
        echo "\`\`\`"
        cat "$proc_mem_file"
        echo "\`\`\`"
        echo ""

        echo "## Memory Fragmentation"
        echo "\`\`\`"
        cat "$buddyinfo_file"
        echo "\`\`\`"
        echo ""

        echo "## Analysis Summary"

        # Calculate total memory
        local total_mem
        total_mem=$(grep "MemTotal:" "$meminfo_file" | awk '{print $2}')
        echo "Total system memory: $((total_mem / 1024)) MB"

        # Calculate available memory
        local avail_mem
        avail_mem=$(grep "MemAvailable:" "$meminfo_file" 2>/dev/null || grep "MemFree:" "$meminfo_file" | awk '{print $2}')
        echo "Available memory: $((avail_mem / 1024)) MB"

        # Memory usage percentage
        local used_percent
        used_percent=$(( (total_mem - avail_mem) * 100 / total_mem ))
        echo "Memory usage: ${used_percent}%"

        if [[ $used_percent -gt 90 ]]; then
            echo "⚠️  HIGH MEMORY USAGE DETECTED"
        elif [[ $used_percent -gt 80 ]]; then
            echo "⚠️  Moderate memory usage"
        else
            echo "✓ Memory usage is normal"
        fi

    } > "$report_file"

    log "SUCCESS" "Full system memory analysis completed. Results saved to $output_dir"
}
