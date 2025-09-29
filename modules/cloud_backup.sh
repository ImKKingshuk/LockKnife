#!/bin/bash

# LockKnife Cloud Backup Extraction Module
# Provides capabilities to extract data from various cloud backup services

# Supported cloud services
CLOUD_SERVICES=(
    "google_drive"
    "samsung_cloud"
    "xiaomi_cloud"
    "huawei_cloud"
    "oneplus_cloud"
    "icloud"  # Limited support due to cross-platform nature
)

# Cloud service configurations
declare -A CLOUD_CONFIGS=(
    ["google_drive:path"]="/data/data/com.google.android.gms/databases"
    ["google_drive:packages"]="com.google.android.gms"
    ["samsung_cloud:path"]="/data/data/com.samsung.android.scloud/databases"
    ["samsung_cloud:packages"]="com.samsung.android.scloud"
    ["xiaomi_cloud:path"]="/data/data/com.miui.cloudservice/databases"
    ["xiaomi_cloud:packages"]="com.miui.cloudservice"
    ["huawei_cloud:path"]="/data/data/com.huawei.cloud/databases"
    ["huawei_cloud:packages"]="com.huawei.cloud"
    ["oneplus_cloud:path"]="/data/data/net.oneplus.cloud/databases"
    ["oneplus_cloud:packages"]="net.oneplus.cloud"
)

# Extract Google Drive backup data
extract_google_drive_data() {
    local device_serial="$1"
    local output_dir="$OUTPUT_DIR/google_drive_backup_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting Google Drive backup data"

    mkdir -p "$output_dir"

    # Check if Google Play Services is installed
    if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q com.google.android.gms"; then
        log "WARNING" "Google Play Services not found on device"
        return 1
    fi

    # Extract Google account information
    local accounts_file="$output_dir/accounts.db"
    execute_root_cmd "$device_serial" "cp /data/system/users/0/accounts.db $accounts_file" "Copy accounts database"
    pull_file_from_device "$device_serial" "/data/system/users/0/accounts.db" "$accounts_file"

    if [[ -f "$accounts_file" ]]; then
        log "INFO" "Extracting Google account information"

        # Analyze accounts database
        local accounts_analysis="$output_dir/accounts_analysis.txt"
        {
            echo "# Google Accounts Analysis"
            echo "# Generated: $(date)"
            echo ""

            # Extract account information
            if command -v sqlite3 &>/dev/null; then
                echo "## Google Accounts"
                sqlite3 "$accounts_file" "SELECT name, type FROM accounts WHERE type LIKE '%google%';" 2>/dev/null | while read -r line; do
                    echo "- $line"
                done
                echo ""

                echo "## Authentication Tokens"
                sqlite3 "$accounts_file" "SELECT accounts.name, authtokens.type FROM accounts LEFT JOIN authtokens ON accounts._id = authtokens.accounts_id WHERE accounts.type LIKE '%google%' LIMIT 10;" 2>/dev/null | while read -r line; do
                    echo "- $line"
                done
            else
                echo "sqlite3 not available for database analysis"
            fi

        } > "$accounts_analysis"
    fi

    # Extract Google Drive app data if available
    if execute_shell_cmd "$device_serial" "pm list packages | grep -q com.google.android.apps.docs"; then
        log "INFO" "Google Drive app detected, extracting app data"

        local drive_app_dir="$output_dir/drive_app_data"
        mkdir -p "$drive_app_dir"

        # Extract Drive app databases
        local drive_db_path="/data/data/com.google.android.apps.docs/databases"
        execute_root_cmd "$device_serial" "find $drive_db_path -name '*.db' 2>/dev/null" "Find Drive databases" | while read -r db_file; do
            if [[ -n "$db_file" ]]; then
                local filename
                filename=$(basename "$db_file")
                pull_file_from_device "$device_serial" "$db_file" "$drive_app_dir/$filename"
            fi
        done

        # Extract Drive preferences
        local drive_prefs_path="/data/data/com.google.android.apps.docs/shared_prefs"
        execute_root_cmd "$device_serial" "find $drive_prefs_path -name '*.xml' 2>/dev/null" "Find Drive preferences" | while read -r pref_file; do
            if [[ -n "$pref_file" ]]; then
                local filename
                filename=$(basename "$pref_file")
                pull_file_from_device "$device_serial" "$pref_file" "$drive_app_dir/${filename}"
            fi
        done
    fi

    # Extract Google Photos backup data if available
    if execute_shell_cmd "$device_serial" "pm list packages | grep -q com.google.android.apps.photos"; then
        log "INFO" "Google Photos detected, extracting backup metadata"

        local photos_dir="$output_dir/photos_backup"
        mkdir -p "$photos_dir"

        # Extract Photos app data
        execute_root_cmd "$device_serial" "find /data/data/com.google.android.apps.photos -name '*.db' 2>/dev/null | head -5" "Find Photos databases" | while read -r db_file; do
            if [[ -n "$db_file" ]]; then
                local filename
                filename=$(basename "$db_file")
                pull_file_from_device "$device_serial" "$db_file" "$photos_dir/$filename"
            fi
        done
    fi

    # Create summary report
    local summary_file="$output_dir/extraction_summary.txt"
    {
        echo "# Google Drive Backup Extraction Summary"
        echo "# Generated: $(date)"
        echo ""

        echo "## Extracted Data"
        find "$output_dir" -type f | while read -r file; do
            local size
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            echo "- $(basename "$file") ($(($size / 1024)) KB)"
        done
        echo ""

        echo "## Analysis Notes"
        echo "- Account information extracted from system accounts database"
        echo "- Google Drive app data includes sync metadata and preferences"
        echo "- Photos backup data contains upload/sync information"
        echo "- Full file contents require additional cloud API access"
        echo ""

        echo "## Recommendations for Full Analysis"
        echo "1. Use Google Takeout for complete cloud data extraction"
        echo "2. Access Google Drive API with proper authentication"
        echo "3. Review Google account activity logs"
        echo "4. Check device backup settings and history"

    } > "$summary_file"

    log "SUCCESS" "Google Drive backup extraction completed. Results saved to $output_dir"
    return 0
}

# Extract Samsung Cloud backup data
extract_samsung_cloud_data() {
    local device_serial="$1"
    local output_dir="$OUTPUT_DIR/samsung_cloud_backup_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting Samsung Cloud backup data"

    mkdir -p "$output_dir"

    # Check if Samsung Cloud is installed
    if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q com.samsung.android.scloud"; then
        log "WARNING" "Samsung Cloud not found on device"
        return 1
    fi

    # Extract Samsung account information
    local samsung_accounts="$output_dir/samsung_accounts.txt"
    execute_root_cmd "$device_serial" "cat /data/system/users/0/accounts.db" "Samsung accounts" > "$samsung_accounts" 2>/dev/null || echo "Account extraction failed" > "$samsung_accounts"

    # Extract Samsung Cloud databases
    local cloud_db_path="/data/data/com.samsung.android.scloud/databases"
    execute_root_cmd "$device_serial" "ls $cloud_db_path/*.db 2>/dev/null" "List Samsung Cloud databases" | while read -r db_file; do
        if [[ -n "$db_file" ]]; then
            local filename
            filename=$(basename "$db_file")
            pull_file_from_device "$device_serial" "$db_file" "$output_dir/$filename"
        fi
    done

    # Extract Samsung Cloud preferences
    local cloud_prefs_path="/data/data/com.samsung.android.scloud/shared_prefs"
    execute_root_cmd "$device_serial" "find $cloud_prefs_path -name '*.xml' 2>/dev/null" "Find Samsung Cloud preferences" | while read -r pref_file; do
        if [[ -n "$pref_file" ]]; then
            local filename
            filename=$(basename "$pref_file")
            pull_file_from_device "$device_serial" "$pref_file" "$output_dir/${filename}"
        fi
    done

    # Extract Smart Switch data if available
    if execute_shell_cmd "$device_serial" "pm list packages | grep -q com.samsung.android.smartswitch"; then
        log "INFO" "Samsung Smart Switch detected, extracting data"

        local smartswitch_dir="$output_dir/smartswitch_data"
        mkdir -p "$smartswitch_dir"

        execute_root_cmd "$device_serial" "find /data/data/com.samsung.android.smartswitch -name '*.db' 2>/dev/null | head -3" "Find Smart Switch databases" | while read -r db_file; do
            if [[ -n "$db_file" ]]; then
                local filename
                filename=$(basename "$db_file")
                pull_file_from_device "$device_serial" "$db_file" "$smartswitch_dir/$filename"
            fi
        done
    fi

    # Create analysis report
    local analysis_file="$output_dir/samsung_analysis.txt"
    {
        echo "# Samsung Cloud Backup Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Samsung Account Information"
        if [[ -f "$samsung_accounts" ]]; then
            grep -i samsung "$samsung_accounts" 2>/dev/null || echo "No Samsung accounts found in extracted data"
        fi
        echo ""

        echo "## Extracted Databases"
        find "$output_dir" -name "*.db" | while read -r db_file; do
            echo "### $(basename "$db_file")"
            if command -v sqlite3 &>/dev/null; then
                sqlite3 "$db_file" ".tables" 2>/dev/null | head -5 | while read -r table; do
                    [[ -n "$table" ]] && echo "- Table: $table"
                done
            fi
            echo ""
        done

        echo "## Backup Configuration"
        find "$output_dir" -name "*.xml" | while read -r xml_file; do
            echo "### $(basename "$xml_file")"
            grep -E "(backup|sync|cloud)" "$xml_file" 2>/dev/null | head -5
            echo ""
        done

    } > "$analysis_file"

    log "SUCCESS" "Samsung Cloud backup extraction completed. Results saved to $output_dir"
    return 0
}

# Extract Xiaomi Cloud backup data
extract_xiaomi_cloud_data() {
    local device_serial="$1"
    local output_dir="$OUTPUT_DIR/xiaomi_cloud_backup_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting Xiaomi Cloud backup data"

    mkdir -p "$output_dir"

    # Check if Xiaomi Cloud is installed
    if ! execute_shell_cmd "$device_serial" "pm list packages | grep -q com.miui.cloudservice"; then
        log "WARNING" "Xiaomi Cloud not found on device"
        return 1
    fi

    # Extract Xiaomi account information
    local mi_accounts="$output_dir/mi_accounts.txt"
    execute_root_cmd "$device_serial" "find /data/system -name '*mi*' -o -name '*xiaomi*' 2>/dev/null" "Find Xiaomi account files" | while read -r file; do
        if [[ -n "$file" ]]; then
            execute_root_cmd "$device_serial" "cat '$file' 2>/dev/null" "Read Xiaomi file $file" >> "$mi_accounts"
        fi
    done

    # Extract Xiaomi Cloud databases
    local cloud_db_path="/data/data/com.miui.cloudservice/databases"
    execute_root_cmd "$device_serial" "ls $cloud_db_path/*.db 2>/dev/null" "List Xiaomi Cloud databases" | while read -r db_file; do
        if [[ -n "$db_file" ]]; then
            local filename
            filename=$(basename "$db_file")
            pull_file_from_device "$device_serial" "$db_file" "$output_dir/$filename"
        fi
    done

    # Extract Mi Cloud preferences
    local cloud_prefs_path="/data/data/com.miui.cloudservice/shared_prefs"
    execute_root_cmd "$device_serial" "find $cloud_prefs_path -name '*.xml' 2>/dev/null" "Find Mi Cloud preferences" | while read -r pref_file; do
        if [[ -n "$pref_file" ]]; then
            local filename
            filename=$(basename "$pref_file")
            pull_file_from_device "$device_serial" "$pref_file" "$output_dir/${filename}"
        fi
    done

    # Create analysis report
    local analysis_file="$output_dir/xiaomi_analysis.txt"
    {
        echo "# Xiaomi Cloud Backup Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## Account Information"
        if [[ -f "$mi_accounts" && -s "$mi_accounts" ]]; then
            echo "Xiaomi account data extracted"
            wc -l "$mi_accounts"
        else
            echo "No Xiaomi account information found"
        fi
        echo ""

        echo "## Cloud Services Analysis"
        echo "- Xiaomi Cloud databases extracted"
        echo "- Preferences and configuration files analyzed"
        echo "- Account sync data preserved"

    } > "$analysis_file"

    log "SUCCESS" "Xiaomi Cloud backup extraction completed. Results saved to $output_dir"
    return 0
}

# Generic cloud backup extraction
extract_generic_cloud_data() {
    local device_serial="$1"
    local cloud_service="$2"
    local output_dir="$OUTPUT_DIR/${cloud_service}_backup_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Extracting $cloud_service backup data"

    mkdir -p "$output_dir"

    # Get cloud service configuration
    local service_path="${CLOUD_CONFIGS[${cloud_service}:path]}"
    local service_packages="${CLOUD_CONFIGS[${cloud_service}:packages]}"

    if [[ -z "$service_path" ]]; then
        log "ERROR" "Unknown cloud service: $cloud_service"
        return 1
    fi

    # Check if service is installed
    local package_found=false
    for package in $service_packages; do
        if execute_shell_cmd "$device_serial" "pm list packages | grep -q $package"; then
            package_found=true
            break
        fi
    done

    if [[ "$package_found" = false ]]; then
        log "WARNING" "$cloud_service not found on device"
        return 1
    fi

    # Extract databases
    execute_root_cmd "$device_serial" "find $service_path -name '*.db' 2>/dev/null" "Find cloud databases" | while read -r db_file; do
        if [[ -n "$db_file" ]]; then
            local filename
            filename=$(basename "$db_file")
            pull_file_from_device "$device_serial" "$db_file" "$output_dir/$filename"
        fi
    done

    # Extract preferences
    local prefs_path="${service_path/databases/shared_prefs}"
    execute_root_cmd "$device_serial" "find $prefs_path -name '*.xml' 2>/dev/null" "Find preferences" | while read -r pref_file; do
        if [[ -n "$pref_file" ]]; then
            local filename
            filename=$(basename "$pref_file")
            pull_file_from_device "$device_serial" "$pref_file" "$output_dir/${filename}"
        fi
    done

    # Create summary
    local summary_file="$output_dir/extraction_summary.txt"
    {
        echo "# $cloud_service Backup Extraction Summary"
        echo "# Generated: $(date)"
        echo ""

        echo "## Extracted Files"
        find "$output_dir" -type f -not -name "extraction_summary.txt" | while read -r file; do
            local size
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            echo "- $(basename "$file") ($(($size / 1024)) KB)"
        done
        echo ""

        echo "## Service Information"
        echo "- Package(s): $service_packages"
        echo "- Data path: $service_path"
        echo ""

        echo "## Analysis Notes"
        echo "- Database files contain sync metadata and account information"
        echo "- Preferences include backup settings and authentication tokens"
        echo "- Full cloud content requires API access with proper credentials"

    } > "$summary_file"

    log "SUCCESS" "$cloud_service backup extraction completed. Results saved to $output_dir"
    return 0
}

# Cloud backup extraction menu
cloud_backup_extraction() {
    local device_serial="$1"

    while true; do
        echo
        echo "Cloud Backup Extraction"
        echo "======================="
        echo "1. Google Drive Backup"
        echo "2. Samsung Cloud Backup"
        echo "3. Xiaomi Cloud Backup"
        echo "4. Huawei Cloud Backup"
        echo "5. OnePlus Cloud Backup"
        echo "6. iCloud Backup (Limited)"
        echo "7. Auto-Detect Available Services"
        echo "0. Back to Main Menu"
        echo

        read -r -p "Choice: " choice

        case $choice in
            1) extract_google_drive_data "$device_serial" ;;
            2) extract_samsung_cloud_data "$device_serial" ;;
            3) extract_xiaomi_cloud_data "$device_serial" ;;
            4) extract_generic_cloud_data "$device_serial" "huawei_cloud" ;;
            5) extract_generic_cloud_data "$device_serial" "oneplus_cloud" ;;
            6) extract_generic_cloud_data "$device_serial" "icloud" ;;
            7) auto_detect_cloud_services "$device_serial" ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Auto-detect available cloud services
auto_detect_cloud_services() {
    local device_serial="$1"
    local output_dir="$OUTPUT_DIR/cloud_services_scan_$(date +%Y%m%d_%H%M%S)"

    log "INFO" "Scanning for available cloud services"

    mkdir -p "$output_dir"

    local detected_services=()
    local scan_results="$output_dir/scan_results.txt"

    {
        echo "# Cloud Services Detection Report"
        echo "# Generated: $(date)"
        echo ""

        for service in "${CLOUD_SERVICES[@]}"; do
            local packages="${CLOUD_CONFIGS[${service}:packages]}"
            local found=false

            for package in $packages; do
                if execute_shell_cmd "$device_serial" "pm list packages | grep -q $package"; then
                    found=true
                    break
                fi
            done

            if [[ "$found" = true ]]; then
                detected_services+=("$service")
                echo "✓ $service detected"
            else
                echo "✗ $service not found"
            fi
        done

        echo ""
        echo "## Detected Services: ${#detected_services[@]}"
        for service in "${detected_services[@]}"; do
            echo "- $service"
        done

    } > "$scan_results"

    if [[ ${#detected_services[@]} -gt 0 ]]; then
        echo ""
        echo "Detected cloud services:"
        for service in "${detected_services[@]}"; do
            echo "- $service"
        done
        echo ""
        read -r -p "Extract data from all detected services? (y/n): " extract_all

        if [[ "$extract_all" = "y" ]]; then
            for service in "${detected_services[@]}"; do
                case "$service" in
                    "google_drive") extract_google_drive_data "$device_serial" ;;
                    "samsung_cloud") extract_samsung_cloud_data "$device_serial" ;;
                    "xiaomi_cloud") extract_xiaomi_cloud_data "$device_serial" ;;
                    *) extract_generic_cloud_data "$device_serial" "$service" ;;
                esac
            done
        fi
    else
        log "INFO" "No cloud services detected on device"
    fi

    log "SUCCESS" "Cloud services scan completed. Results saved to $output_dir"
}
