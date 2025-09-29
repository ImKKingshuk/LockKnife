#!/bin/bash

# LockKnife Data Extraction Module
# Provides comprehensive data extraction capabilities

# Recover SMS messages
recover_sms() {
    local device_serial="$1"
    local sms_db="$TEMP_DIR/mmssms.db"

    log "INFO" "Attempting to pull SMS database (root required)..."

    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 /data/data/com.android.providers.telephony/databases/mmssms.db\"'" "Setting permissions" || true

    if ! execute_with_retry "adb -s $device_serial pull /data/data/com.android.providers.telephony/databases/mmssms.db $sms_db" "SMS database transfer"; then
        log "ERROR" "Failed to pull SMS database. Root access required."
        return 1
    fi

    if [ ! -f "$sms_db" ]; then
        log "ERROR" "SMS database file not found after pull attempt. Check transfer."
        return 1
    fi

    log "INFO" "Extracting recent SMS messages..."

    local output_file="$OUTPUT_DIR/sms_messages_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "# SMS Messages Extraction Report"
        echo "# Generated: $(date)"
        echo ""

        if command -v sqlite3 &>/dev/null; then
            echo "## Recent SMS Messages"
            sqlite3 "$sms_db" "SELECT datetime(date/1000,'unixepoch') as date_time, address, body, type FROM sms WHERE date > strftime('%s','now','-30 days')*1000 ORDER BY date DESC LIMIT 50;" 2>/dev/null | while read -r line; do
                echo "$line"
            done

            echo ""
            echo "## SMS Statistics"
            local total_sms
            total_sms=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms;" 2>/dev/null || echo "N/A")
            local sent_sms
            sent_sms=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms WHERE type=2;" 2>/dev/null || echo "N/A")
            local received_sms
            received_sms=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms WHERE type=1;" 2>/dev/null || echo "N/A")

            echo "Total SMS: $total_sms"
            echo "Sent: $sent_sms"
            echo "Received: $received_sms"
        else
            echo "sqlite3 not available for database analysis"
        fi
    } > "$output_file"

    secure_delete_file "$sms_db"

    log "SUCCESS" "SMS extraction completed. Results saved to $output_file"
    return 0
}

# Recover call logs
recover_call_logs() {
    local device_serial="$1"
    local calls_db="$TEMP_DIR/contacts2.db"

    log "INFO" "Attempting to pull call logs database (root required)..."

    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 /data/data/com.android.providers.contacts/databases/contacts2.db\"'" "Setting permissions" || true

    if ! execute_with_retry "adb -s $device_serial pull /data/data/com.android.providers.contacts/databases/contacts2.db $calls_db" "Call logs database transfer"; then
        log "ERROR" "Failed to pull contacts database. Root access required."
        return 1
    fi

    if [ ! -f "$calls_db" ]; then
        log "ERROR" "Call logs database file not found after pull attempt. Check transfer."
        return 1
    fi

    log "INFO" "Extracting recent call logs..."

    local output_file="$OUTPUT_DIR/call_logs_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "# Call Logs Extraction Report"
        echo "# Generated: $(date)"
        echo ""

        if command -v sqlite3 &>/dev/null; then
            echo "## Recent Call Logs"
            sqlite3 "$calls_db" "SELECT datetime(date/1000,'unixepoch') as date_time, number, duration, type FROM calls WHERE date > strftime('%s','now','-30 days')*1000 ORDER BY date DESC LIMIT 50;" 2>/dev/null | while read -r line; do
                # Translate call type
                local call_type
                case $(echo "$line" | awk '{print $4}') in
                    1) call_type="INCOMING" ;;
                    2) call_type="OUTGOING" ;;
                    3) call_type="MISSED" ;;
                    4) call_type="VOICEMAIL" ;;
                    5) call_type="REJECTED" ;;
                    6) call_type="BLOCKED" ;;
                    *) call_type="UNKNOWN" ;;
                esac
                echo "$line | $call_type"
            done

            echo ""
            echo "## Call Statistics"
            local total_calls
            total_calls=$(sqlite3 "$calls_db" "SELECT COUNT(*) FROM calls;" 2>/dev/null || echo "N/A")
            local incoming_calls
            incoming_calls=$(sqlite3 "$calls_db" "SELECT COUNT(*) FROM calls WHERE type=1;" 2>/dev/null || echo "N/A")
            local outgoing_calls
            outgoing_calls=$(sqlite3 "$calls_db" "SELECT COUNT(*) FROM calls WHERE type=2;" 2>/dev/null || echo "N/A")
            local missed_calls
            missed_calls=$(sqlite3 "$calls_db" "SELECT COUNT(*) FROM calls WHERE type=3;" 2>/dev/null || echo "N/A")

            echo "Total Calls: $total_calls"
            echo "Incoming: $incoming_calls"
            echo "Outgoing: $outgoing_calls"
            echo "Missed: $missed_calls"
        else
            echo "sqlite3 not available for database analysis"
        fi
    } > "$output_file"

    secure_delete_file "$calls_db"

    log "SUCCESS" "Call logs extraction completed. Results saved to $output_file"
    return 0
}

# Extract WhatsApp data
extract_whatsapp_data() {
    local device_serial="$1"
    local whatsapp_dir="$OUTPUT_DIR/whatsapp_data_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting WhatsApp data..."

    mkdir -p "$whatsapp_dir"

    # Check if WhatsApp is installed
    if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q com.whatsapp"; then
        if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q com.whatsapp.w4b"; then
            log "WARNING" "WhatsApp not found on device"
            return 1
        fi
    fi

    # WhatsApp data paths
    local whatsapp_paths=(
        "/data/data/com.whatsapp/databases/msgstore.db"
        "/data/data/com.whatsapp/databases/wa.db"
        "/data/data/com.whatsapp/databases/contacts.db"
        "/data/data/com.whatsapp.w4b/databases/msgstore.db"
        "/data/data/com.whatsapp.w4b/databases/wa.db"
        "/data/data/com.whatsapp.w4b/databases/contacts.db"
    )

    local extracted_files=()

    for db_path in "${whatsapp_paths[@]}"; do
        if execute_shell_cmd "$device_serial" "test -f $db_path"; then
            log "INFO" "Found WhatsApp database: $db_path"

            execute_root_cmd "$device_serial" "chmod 644 $db_path" "Set permissions" || true

            local filename
            filename=$(basename "$db_path")
            if pull_file_from_device "$device_serial" "$db_path" "$whatsapp_dir/$filename"; then
                extracted_files+=("$filename")
                log "SUCCESS" "Extracted $filename"
            fi
        fi
    done

    # Extract WhatsApp media if available
    local media_paths=(
        "/data/media/0/WhatsApp/Media"
        "/sdcard/WhatsApp/Media"
    )

    for media_path in "${media_paths[@]}"; do
        if execute_shell_cmd "$device_serial" "test -d $media_path"; then
            log "INFO" "Found WhatsApp media directory: $media_path"

            local media_count
            media_count=$(execute_shell_cmd "$device_serial" "find $media_path -type f | wc -l" "Count media files")

            if [[ $media_count -gt 0 && $media_count -lt 100 ]]; then
                log "INFO" "Extracting $media_count WhatsApp media files..."
                execute_shell_cmd "$device_serial" "find $media_path -type f -name '*.jpg' -o -name '*.mp4' -o -name '*.opus' | head -20" "Find media files" | while read -r media_file; do
                    if [[ -n "$media_file" ]]; then
                        local media_filename
                        media_filename=$(basename "$media_file")
                        pull_file_from_device "$device_serial" "$media_file" "$whatsapp_dir/media_$media_filename"
                    fi
                done
            else
                log "INFO" "Media directory found but contains $media_count files (too many to extract automatically)"
            fi
            break
        fi
    done

    # Analyze extracted databases
    local analysis_file="$whatsapp_dir/whatsapp_analysis.txt"
    {
        echo "# WhatsApp Data Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Extracted Files"
        for file in "${extracted_files[@]}"; do
            echo "- $file"
        done
        echo ""

        # Analyze databases if sqlite3 is available
        if command -v sqlite3 &>/dev/null; then
            for db_file in "$whatsapp_dir"/*.db; do
                if [[ -f "$db_file" ]]; then
                    local db_name
                    db_name=$(basename "$db_file")
                    echo "## Analysis of $db_name"

                    case "$db_name" in
                        "msgstore.db")
                            local message_count
                            message_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM messages;" 2>/dev/null || echo "N/A")
                            echo "- Total messages: $message_count"

                            local chat_count
                            chat_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM chat_list;" 2>/dev/null || echo "N/A")
                            echo "- Total chats: $chat_count"
                            ;;

                        "wa.db")
                            local contact_count
                            contact_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM wa_contacts;" 2>/dev/null || echo "N/A")
                            echo "- Total contacts: $contact_count"
                            ;;

                        "contacts.db")
                            local phone_count
                            phone_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM wa_contacts;" 2>/dev/null || echo "N/A")
                            echo "- Phone contacts: $phone_count"
                            ;;
                    esac
                    echo ""
                fi
            done
        fi

        echo "## WhatsApp Data Summary"
        echo "- Application package: com.whatsapp"
        echo "- Data location: /data/data/com.whatsapp/"
        echo "- Media location: /data/media/0/WhatsApp/Media/"
        echo "- Backup location: /data/media/0/WhatsApp/Databases/"

    } > "$analysis_file"

    log "SUCCESS" "WhatsApp data extraction completed. Results saved to $whatsapp_dir"
    return 0
}

# Extract Telegram data
extract_telegram_data() {
    local device_serial="$1"
    local telegram_dir="$OUTPUT_DIR/telegram_data_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting Telegram data..."

    mkdir -p "$telegram_dir"

    # Check if Telegram is installed
    if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q org.telegram"; then
        if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q org.telegram.messenger"; then
            log "WARNING" "Telegram not found on device"
            return 1
        fi
    fi

    # Telegram data paths
    local telegram_paths=(
        "/data/data/org.telegram.messenger/databases/cache4.db"
        "/data/data/org.telegram.messenger/databases/telegram.db"
        "/data/data/org.telegram.messenger/databases/users.db"
        "/data/data/org.telegram.messenger/files"
        "/data/data/org.telegram.messenger/shared_prefs"
    )

    local extracted_files=()

    for data_path in "${telegram_paths[@]}"; do
        # Check if it's a file
        if execute_shell_cmd "$device_serial" "test -f $data_path"; then
            log "INFO" "Found Telegram file: $data_path"

            execute_root_cmd "$device_serial" "chmod 644 $data_path" "Set permissions" || true

            local filename
            filename=$(basename "$data_path")
            if pull_file_from_device "$device_serial" "$data_path" "$telegram_dir/$filename"; then
                extracted_files+=("$filename")
            fi
        elif execute_shell_cmd "$device_serial" "test -d $data_path"; then
            log "INFO" "Found Telegram directory: $data_path"

            # Extract some key files from directories
            execute_root_cmd "$device_serial" "find $data_path -type f -name '*.db' -o -name '*.xml' | head -10" "Find Telegram files" | while read -r tg_file; do
                if [[ -n "$tg_file" ]]; then
                    execute_root_cmd "$device_serial" "chmod 644 '$tg_file'" "Set permissions" || true

                    local tg_filename
                    tg_filename=$(basename "$tg_file" | sed 's/\//_/g')
                    pull_file_from_device "$device_serial" "$tg_file" "$telegram_dir/${tg_filename}"
                    extracted_files+=("$tg_filename")
                fi
            done
        fi
    done

    # Analyze extracted data
    local analysis_file="$telegram_dir/telegram_analysis.txt"
    {
        echo "# Telegram Data Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Extracted Files"
        for file in "${extracted_files[@]}"; do
            echo "- $file"
        done
        echo ""

        # Analyze databases
        if command -v sqlite3 &>/dev/null; then
            for db_file in "$telegram_dir"/*.db; do
                if [[ -f "$db_file" ]]; then
                    local db_name
                    db_name=$(basename "$db_file")
                    echo "## Analysis of $db_name"

                    # Basic analysis
                    local table_count
                    table_count=$(sqlite3 "$db_file" ".tables" 2>/dev/null | wc -w 2>/dev/null || echo "N/A")
                    echo "- Tables: $table_count"

                    local record_count
                    record_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "N/A")
                    echo "- Records: $record_count"
                    echo ""
                fi
            done
        fi

        echo "## Telegram Data Summary"
        echo "- Application package: org.telegram.messenger"
        echo "- Data location: /data/data/org.telegram.messenger/"
        echo "- MTProto implementation: Custom encryption"
        echo "- Media storage: Encrypted and distributed"

    } > "$analysis_file"

    log "SUCCESS" "Telegram data extraction completed. Results saved to $telegram_dir"
    return 0
}

# Extract Signal data
extract_signal_data() {
    local device_serial="$1"
    local signal_dir="$OUTPUT_DIR/signal_data_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting Signal data (root required)..."

    mkdir -p "$signal_dir"

    # Check if Signal is installed
    if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q org.thoughtcrime.securesms"; then
        log "WARNING" "Signal not found on device"
        return 1
    fi

    # Signal data paths (Signal uses SQLCipher for encryption)
    local signal_paths=(
        "/data/data/org.thoughtcrime.securesms/databases/signal.db"
        "/data/data/org.thoughtcrime.securesms/databases/signal-plain.db"
        "/data/data/org.thoughtcrime.securesms/shared_prefs/"
    )

    local extracted_files=()

    for data_path in "${signal_paths[@]}"; do
        if execute_shell_cmd "$device_serial" "test -f $data_path"; then
            log "INFO" "Found Signal file: $data_path"

            execute_root_cmd "$device_serial" "chmod 644 $data_path" "Set permissions" || true

            local filename
            filename=$(basename "$data_path")
            if pull_file_from_device "$device_serial" "$data_path" "$signal_dir/$filename"; then
                extracted_files+=("$filename")
            fi
        elif execute_shell_cmd "$device_serial" "test -d $data_path"; then
            log "INFO" "Found Signal directory: $data_path"

            execute_root_cmd "$device_serial" "find $data_path -type f -name '*.xml' | head -5" "Find Signal config files" | while read -r signal_file; do
                if [[ -n "$signal_file" ]]; then
                    execute_root_cmd "$device_serial" "chmod 644 '$signal_file'" "Set permissions" || true

                    local signal_filename
                    signal_filename=$(basename "$signal_file")
                    pull_file_from_device "$device_serial" "$signal_file" "$signal_dir/${signal_filename}"
                    extracted_files+=("$signal_filename")
                fi
            done
        fi
    done

    # Create analysis report
    local analysis_file="$signal_dir/signal_analysis.txt"
    {
        echo "# Signal Data Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Extracted Files"
        for file in "${extracted_files[@]}"; do
            echo "- $file"
        done
        echo ""

        echo "## Signal Security Notes"
        echo "- Uses SQLCipher for database encryption"
        echo "- End-to-end encryption for all messages"
        echo "- Forward secrecy implementation"
        echo "- No plain text message storage"
        echo ""

        echo "## Signal Data Summary"
        echo "- Application package: org.thoughtcrime.securesms"
        echo "- Database encryption: SQLCipher with user passphrase"
        echo "- Protocol: Signal Protocol (Double Ratchet)"
        echo "- Media encryption: Automatic for all attachments"

        if [[ ${#extracted_files[@]} -eq 0 ]]; then
            echo ""
            echo "## Warning"
            echo "No Signal data files were successfully extracted."
            echo "This may be due to:"
            echo "- Insufficient root permissions"
            echo "- Signal's security measures"
            echo "- Device encryption"
        fi

    } > "$analysis_file"

    log "SUCCESS" "Signal data extraction completed. Results saved to $signal_dir"
    return 0
}

# Extract browser data
extract_browser_data() {
    local device_serial="$1"
    local browser_type="$2"
    local browser_dir="$OUTPUT_DIR/${browser_type}_data_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting $browser_type browser data..."

    mkdir -p "$browser_dir"

    # Browser package mappings
    declare -A browser_packages=(
        ["chrome"]="com.android.chrome"
        ["firefox"]="org.mozilla.firefox"
        ["brave"]="com.brave.browser"
        ["edge"]="com.microsoft.emmx"
    )

    local package_name="${browser_packages[$browser_type]}"

    if [[ -z "$package_name" ]]; then
        log "ERROR" "Unknown browser type: $browser_type"
        return 1
    fi

    # Check if browser is installed
    if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q $package_name"; then
        log "WARNING" "$browser_type not found on device"
        return 1
    fi

    # Browser data paths
    local browser_data_paths=(
        "/data/data/$package_name/app_chrome/Default/History"
        "/data/data/$package_name/app_chrome/Default/Cookies"
        "/data/data/$package_name/app_chrome/Default/Login Data"
        "/data/data/$package_name/app_chrome/Default/Web Data"
        "/data/data/$package_name/files/mozilla/*.db"
        "/data/data/$package_name/databases/"
    )

    local extracted_files=()

    for data_path in "${browser_data_paths[@]}"; do
        # Handle wildcards
        if [[ "$data_path" == *"*"* ]]; then
            execute_root_cmd "$device_serial" "ls $data_path 2>/dev/null" "List browser files" | while read -r browser_file; do
                if [[ -n "$browser_file" ]]; then
                    execute_root_cmd "$device_serial" "chmod 644 '$browser_file'" "Set permissions" || true

                    local browser_filename
                    browser_filename=$(basename "$browser_file")
                    if pull_file_from_device "$device_serial" "$browser_file" "$browser_dir/${browser_filename}"; then
                        extracted_files+=("$browser_filename")
                    fi
                fi
            done
        else
            if execute_shell_cmd "$device_serial" "test -f $data_path"; then
                execute_root_cmd "$device_serial" "chmod 644 $data_path" "Set permissions" || true

                local filename
                filename=$(basename "$data_path")
                if pull_file_from_device "$device_serial" "$data_path" "$browser_dir/$filename"; then
                    extracted_files+=("$filename")
                fi
            fi
        fi
    done

    # Analyze extracted data
    local analysis_file="$browser_dir/browser_analysis.txt"
    {
        echo "# $browser_type Browser Data Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Extracted Files"
        for file in "${extracted_files[@]}"; do
            echo "- $file"
        done
        echo ""

        # Analyze specific file types
        if command -v sqlite3 &>/dev/null; then
            for db_file in "$browser_dir"/*.db; do
                if [[ -f "$db_file" ]]; then
                    local db_name
                    db_name=$(basename "$db_file")
                    echo "## Analysis of $db_name"

                    case "$db_name" in
                        "History")
                            local history_count
                            history_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM urls;" 2>/dev/null || echo "N/A")
                            echo "- Browsing history entries: $history_count"
                            ;;

                        "Cookies")
                            local cookie_count
                            cookie_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM cookies;" 2>/dev/null || echo "N/A")
                            echo "- Stored cookies: $cookie_count"
                            ;;

                        "Login Data")
                            local login_count
                            login_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM logins;" 2>/dev/null || echo "N/A")
                            echo "- Saved passwords: $login_count"
                            ;;
                    esac
                    echo ""
                fi
            done
        fi

        echo "## Browser Security Notes"
        echo "- History: Contains browsing activity"
        echo "- Cookies: Session and authentication data"
        echo "- Login Data: Saved credentials (encrypted)"
        echo "- Web Data: Form data and autofill information"

    } > "$analysis_file"

    log "SUCCESS" "$browser_type browser data extraction completed. Results saved to $browser_dir"
    return 0
}

# Extract Bluetooth pairing keys
extract_bluetooth_keys() {
    local device_serial="$1"
    local bluetooth_dir="$OUTPUT_DIR/bluetooth_data_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting Bluetooth pairing keys..."

    mkdir -p "$bluetooth_dir"

    # Bluetooth data paths
    local bluetooth_paths=(
        "/data/misc/bluedroid/bt_config.xml"
        "/data/misc/bluetoothd/"
        "/data/misc/bt_config.conf"
        "/data/property/persist.bluetooth."
    )

    local extracted_files=()

    for bt_path in "${bluetooth_paths[@]}"; do
        if execute_shell_cmd "$device_serial" "test -f $bt_path"; then
            log "INFO" "Found Bluetooth file: $bt_path"

            execute_root_cmd "$device_serial" "chmod 644 $bt_path" "Set permissions" || true

            local filename
            filename=$(basename "$bt_path")
            if pull_file_from_device "$device_serial" "$bt_path" "$bluetooth_dir/$filename"; then
                extracted_files+=("$filename")
            fi
        elif execute_shell_cmd "$device_serial" "test -d $bt_path"; then
            log "INFO" "Found Bluetooth directory: $bt_path"

            execute_root_cmd "$device_serial" "find $bt_path -type f | head -10" "Find Bluetooth files" | while read -r bt_file; do
                if [[ -n "$bt_file" ]]; then
                    execute_root_cmd "$device_serial" "chmod 644 '$bt_file'" "Set permissions" || true

                    local bt_filename
                    bt_filename=$(basename "$bt_file" | sed 's/\//_/g')
                    pull_file_from_device "$device_serial" "$bt_file" "$bluetooth_dir/${bt_filename}"
                    extracted_files+=("$bt_filename")
                fi
            done
        fi
    done

    # Get current Bluetooth status
    local bt_status
    bt_status=$(execute_shell_cmd "$device_serial" "settings get global bluetooth_on" "Bluetooth status")

    # Get paired devices
    local paired_devices
    paired_devices=$(execute_shell_cmd "$device_serial" "bt-device -l 2>/dev/null || bluetoothctl paired-devices 2>/dev/null" "Paired devices")

    # Create analysis report
    local analysis_file="$bluetooth_dir/bluetooth_analysis.txt"
    {
        echo "# Bluetooth Data Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Bluetooth Status"
        echo "Bluetooth enabled: $bt_status"
        echo ""

        echo "## Extracted Files"
        for file in "${extracted_files[@]}"; do
            echo "- $file"
        done
        echo ""

        echo "## Paired Devices"
        if [[ -n "$paired_devices" ]]; then
            echo "$paired_devices"
        else
            echo "No paired devices information available"
        fi
        echo ""

        echo "## Bluetooth Security Notes"
        echo "- Pairing keys are used for device authentication"
        echo "- Bluetooth Low Energy (BLE) uses different security model"
        echo "- Classic Bluetooth uses PIN/Link Key for pairing"
        echo "- Keys are typically stored encrypted"

    } > "$analysis_file"

    log "SUCCESS" "Bluetooth data extraction completed. Results saved to $bluetooth_dir"
    return 0
}

# Data extraction submenu
submenu_data_extraction() {
    local device_serial="$1"
    echo "Data Extraction Options:"
    echo "1. SMS Messages"
    echo "2. Call Logs"
    echo "3. Wi-Fi Passwords"
    echo "4. WhatsApp Data"
    echo "5. Telegram Data"
    echo "6. Signal Data"
    echo "7. Browser Data"
    echo "8. Bluetooth Pairing Keys"
    read -r -p "Choice: " choice
    case $choice in
        1) recover_sms "$device_serial" ;;
        2) recover_call_logs "$device_serial" ;;
        3) recover_wifi_passwords "$device_serial" ;;
        4) extract_whatsapp_data "$device_serial" ;;
        5) extract_telegram_data "$device_serial" ;;
        6) extract_signal_data "$device_serial" ;;
        7)
           echo "Select browser type:"
           echo "1. Chrome"
           echo "2. Firefox"
           echo "3. Brave"
           echo "4. Edge"
           read -r -p "Browser: " browser_choice
           case $browser_choice in
               1) extract_browser_data "$device_serial" "chrome" ;;
               2) extract_browser_data "$device_serial" "firefox" ;;
               3) extract_browser_data "$device_serial" "brave" ;;
               4) extract_browser_data "$device_serial" "edge" ;;
               *) log "ERROR" "Invalid browser choice." ;;
           esac
           ;;
        8) extract_bluetooth_keys "$device_serial" ;;
        *) echo "[ERROR] Invalid choice." ;;
    esac
}
