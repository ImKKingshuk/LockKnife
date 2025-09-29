#!/bin/bash

# LockKnife Forensic Analysis Module
# Provides comprehensive forensic analysis capabilities

# Create device snapshot for forensic analysis
create_device_snapshot() {
    local device_serial="$1"
    local dirs_to_backup="${2:-$SNAPSHOT_DIRS}"
    local output_dir="$OUTPUT_DIR/forensics_$(date +%Y%m%d_%H%M%S)"
    local archive_name="device_snapshot_$(date +%Y%m%d_%H%M%S).tar.gz"
    local temp_archive="$TEMP_DIR/$archive_name"

    log "INFO" "Creating device snapshot for forensic analysis..."
    log "INFO" "Directories to include: $dirs_to_backup"

    mkdir -p "$output_dir"
    chmod 700 "$output_dir"

    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for comprehensive device snapshot"
        log "INFO" "Will attempt to capture non-root accessible directories only"
    fi

    if ! execute_with_retry "adb -s $device_serial shell 'command -v tar'" "Tar check" | grep -q "tar"; then
        log "ERROR" "Tar command not found on device"
        log "INFO" "Will use slower directory-by-directory pull method"

        for dir in $dirs_to_backup; do
            log "INFO" "Pulling directory: $dir"
            local dir_name
            dir_name=$(basename "$dir")
            local output_subdir="$output_dir/$dir_name"
            mkdir -p "$output_subdir"

            execute_with_retry "adb -s $device_serial shell 'su -c \"find $dir -type f 2>/dev/null\"'" "Find files" | while read -r file; do
                if [ -n "$file" ]; then
                    local rel_path="${file#"$dir"}"
                    local target_dir
                    target_dir="$output_subdir$(dirname "$rel_path")"

                    mkdir -p "$target_dir"
                    execute_with_retry "adb -s $device_serial pull \"$file\" \"$target_dir/\"" "Pull file $file"
                fi
            done
        done
    else
        log "INFO" "Creating archive on device (this may take some time)..."

        local tar_dirs=""
        for dir in $dirs_to_backup; do
            tar_dirs="$tar_dirs $dir"
        done

        if execute_with_retry "adb -s $device_serial shell 'su -c \"tar -czf /sdcard/$archive_name $tar_dirs 2>/dev/null\"'" "Create archive"; then

            log "INFO" "Pulling device snapshot archive..."
            if execute_with_retry "adb -s $device_serial pull /sdcard/$archive_name $temp_archive" "Pull archive"; then

                log "INFO" "Extracting snapshot archive..."
                tar -xzf "$temp_archive" -C "$output_dir"

                execute_with_retry "adb -s $device_serial shell 'rm /sdcard/$archive_name'" "Remove device archive" || true

                mv "$temp_archive" "$output_dir/"
                log "SUCCESS" "Device snapshot created successfully in $output_dir"
            else
                log "ERROR" "Failed to pull snapshot archive from device"
                return 1
            fi
        else
            log "ERROR" "Failed to create snapshot archive on device"
            return 1
        fi
    fi

    create_forensics_summary "$output_dir"

    return 0
}

# Create forensics summary report
create_forensics_summary() {
    local snapshot_dir="$1"
    local summary_file="$snapshot_dir/forensics_summary.txt"

    log "INFO" "Creating forensics summary report..."

    {
        echo "# LockKnife Forensics Report"
        echo "# Generated: $(date)"
        echo ""
        echo "## Snapshot Contents"
        echo ""

        echo "### Directories Captured"
        find "$snapshot_dir" -maxdepth 1 -type d | sort | grep -v "^$snapshot_dir$" | while read -r dir; do
            echo "- $(basename "$dir")"
        done
        echo ""

        echo "### File Types Summary"
        find "$snapshot_dir" -type f | grep -v "$summary_file" | sort | while read -r file; do
            file "$file" | awk -F': ' '{print $2}' | sort | uniq -c | sort -nr
        done | head -20
        echo ""

        echo "### SQLite Databases"
        find "$snapshot_dir" -name "*.db" -o -name "*.sqlite" | sort | while read -r db; do
            echo "- $(realpath --relative-to="$snapshot_dir" "$db")"

            if [ -f "$db" ]; then
                echo "  Tables:"
                sqlite3 "$db" ".tables" 2>/dev/null | tr ' ' '\n' | while read -r table; do
                    if [ -n "$table" ]; then
                        echo "  - $table"
                    fi
                done
            fi
        done
        echo ""

        echo "### Potential Sensitive Data Locations"
        {
            find "$snapshot_dir" -type f \( -name "*.xml" -o -name "*.json" -o -name "*.properties" -o -name "*.conf" \) -print0 | xargs -0 grep -l 'key\|api\|token\|secret\|password' 2>/dev/null

            find "$snapshot_dir" -type f -name "*.xml" -o -name "*.properties" -o -name "*.conf" -o -name "*.ini" | sort

            find "$snapshot_dir" -path "*/accounts*" -type f | sort
        } | sort | uniq | while read -r file; do
            echo "- $(realpath --relative-to="$snapshot_dir" "$file")"
        done

    } > "${summary_file}.tmp"

    mv "${summary_file}.tmp" "$summary_file"

    log "INFO" "Forensics summary created: $summary_file"
}

# Search forensic data in snapshots
search_forensic_data() {
    local snapshot_dir="$1"
    local search_pattern="$2"
    local output_file="$OUTPUT_DIR/forensic_search_$(date +%Y%m%d_%H%M%S).txt"

    if [ ! -d "$snapshot_dir" ]; then
        log "ERROR" "Snapshot directory not found: $snapshot_dir"
        return 1
    fi

    log "INFO" "Searching for pattern: $search_pattern in $snapshot_dir"

    {
        echo "# LockKnife Forensic Search Results"
        echo "# Pattern: $search_pattern"
        echo "# Generated: $(date)"
        echo ""

        find "$snapshot_dir" -type f -exec grep -l "$search_pattern" {} \; 2>/dev/null | while read -r file; do
            echo "File: $(realpath --relative-to="$snapshot_dir" "$file")"
            echo "----------------------------------------"
            grep -n "$search_pattern" "$file" | head -10
            echo ""
        done

    } > "$output_file"

    log "SUCCESS" "Search results saved to $output_file"
    return 0
}

# Live analysis of device
live_analysis() {
    local device_serial="$1"

    log "INFO" "Performing live device analysis..."

    # Get device information
    local device_info
    device_info=$(execute_shell_cmd "$device_serial" "getprop" "Get device properties")

    # Get running processes
    local processes
    processes=$(execute_shell_cmd "$device_serial" "ps" "Get running processes")

    # Get network connections
    local netstat
    netstat=$(execute_shell_cmd "$device_serial" "netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null" "Get network connections")

    # Get mounted filesystems
    local mounts
    mounts=$(execute_shell_cmd "$device_serial" "mount" "Get mounted filesystems")

    # Get system information
    local system_info
    system_info=$(execute_shell_cmd "$device_serial" "uname -a" "Get system information")

    local output_file="$OUTPUT_DIR/live_analysis_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "# LockKnife Live Device Analysis"
        echo "# Generated: $(date)"
        echo ""

        echo "## System Information"
        echo "$system_info"
        echo ""

        echo "## Device Properties (Sample)"
        echo "$device_info" | grep -E "(ro\.product\.|ro\.build\.|ro\.hardware\.)" | head -20
        echo ""

        echo "## Running Processes (Sample)"
        echo "$processes" | head -20
        echo ""

        echo "## Network Connections"
        echo "$netstat" | head -20
        echo ""

        echo "## Mounted Filesystems"
        echo "$mounts"
        echo ""

        # Check for suspicious processes
        echo "## Potential Security Concerns"
        echo "### Suspicious Process Names"
        echo "$processes" | grep -i -E "(hack|spy|keylog|trojan|malware|virus|rootkit|backdoor)" | while read -r line; do
            echo "- $line"
        done
        echo ""

        echo "### Suspicious Network Connections"
        echo "$netstat" | grep -E ":(4444|6667|6668|31337|12345|54321)\b" | while read -r line; do
            echo "- $line"
        done

    } > "$output_file"

    log "SUCCESS" "Live analysis completed. Results saved to $output_file"
    return 0
}

# Custom data extraction
custom_data_extraction() {
    local device_serial="$1"

    log "INFO" "Custom data extraction..."

    read -r -p "Enter the remote path to extract: " remote_path
    read -r -p "Enter the local output directory name: " output_name

    if [[ -z "$remote_path" || -z "$output_name" ]]; then
        log "ERROR" "Both remote path and output name are required"
        return 1
    fi

    local output_dir="$OUTPUT_DIR/custom_${output_name}_$(date +%Y%m%d_%H%M%S)"

    # Check if path exists and get file info
    local file_info
    file_info=$(execute_shell_cmd "$device_serial" "ls -la '$remote_path' 2>/dev/null" "Check file info")

    if [[ -z "$file_info" ]]; then
        log "ERROR" "Path does not exist or is not accessible: $remote_path"
        return 1
    fi

    mkdir -p "$output_dir"

    # Determine if it's a file or directory
    if echo "$file_info" | grep -q "^-"; then
        # It's a file
        log "INFO" "Extracting file: $remote_path"

        execute_root_cmd "$device_serial" "chmod 644 '$remote_path'" "Set permissions" || true

        if pull_file_from_device "$device_serial" "$remote_path" "$output_dir/$(basename "$remote_path")"; then
            log "SUCCESS" "File extracted successfully"

            # Analyze file if it's a database
            local filename
            filename=$(basename "$remote_path")
            if [[ "$filename" == *.db || "$filename" == *.sqlite ]]; then
                analyze_database_file "$output_dir/$filename" "$output_dir"
            fi
        else
            log "ERROR" "Failed to extract file"
            return 1
        fi
    elif echo "$file_info" | grep -q "^d"; then
        # It's a directory
        log "INFO" "Extracting directory: $remote_path"

        # Create tar archive on device
        local archive_name="custom_extraction_$(date +%s).tar.gz"
        local device_archive="/data/local/tmp/$archive_name"

        if execute_root_cmd "$device_serial" "tar -czf '$device_archive' -C '$remote_path' . 2>/dev/null" "Create archive"; then
            if pull_file_from_device "$device_serial" "$device_archive" "$output_dir/$archive_name"; then
                # Extract archive locally
                tar -xzf "$output_dir/$archive_name" -C "$output_dir"
                rm "$output_dir/$archive_name"

                log "SUCCESS" "Directory extracted successfully"
            else
                log "ERROR" "Failed to pull archive"
                return 1
            fi

            # Clean up device archive
            execute_shell_cmd "$device_serial" "rm '$device_archive'" "Remove device archive" || true
        else
            log "ERROR" "Failed to create archive on device"
            return 1
        fi
    else
        log "ERROR" "Unsupported file type"
        return 1
    fi

    # Create summary
    local summary_file="$output_dir/extraction_summary.txt"
    {
        echo "# Custom Data Extraction Summary"
        echo "# Generated: $(date)"
        echo "# Remote Path: $remote_path"
        echo ""

        echo "## Extracted Content"
        find "$output_dir" -type f | while read -r file; do
            local size
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            echo "- $(basename "$file") ($(($size / 1024)) KB)"
        done

    } > "$summary_file"

    log "SUCCESS" "Custom extraction completed. Results saved to $output_dir"
    return 0
}

# Analyze database file
analyze_database_file() {
    local db_file="$1"
    local output_dir="$2"
    local analysis_file="$output_dir/database_analysis.txt"

    if [[ ! -f "$db_file" ]]; then
        return 1
    fi

    log "INFO" "Analyzing database file: $(basename "$db_file")"

    {
        echo "# Database Analysis: $(basename "$db_file")"
        echo "# Generated: $(date)"
        echo ""

        if command -v sqlite3 &>/dev/null; then
            echo "## Tables"
            sqlite3 "$db_file" ".tables" 2>/dev/null | tr ' ' '\n' | while read -r table; do
                [[ -n "$table" ]] && echo "- $table"
            done
            echo ""

            echo "## Schema Information"
            sqlite3 "$db_file" ".schema" 2>/dev/null | head -50
            echo ""

            echo "## Record Counts"
            sqlite3 "$db_file" ".tables" 2>/dev/null | while read -r table; do
                if [[ -n "$table" ]]; then
                    local count
                    count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM $table;" 2>/dev/null || echo "N/A")
                    echo "- $table: $count records"
                fi
            done
        else
            echo "sqlite3 not available for database analysis"
        fi

    } > "$analysis_file"
}

# Forensic analysis submenu
submenu_forensic_analysis() {
    local device_serial="$1"
    log "INFO" "Forensic Analysis Options:"
    echo "1. Create Full Device Snapshot"
    echo "2. Snapshot Specific Directories"
    echo "3. Search Existing Snapshot"
    echo "4. Extract SQLite Databases"
    echo "5. Analyze App Data"
    read -r -p "Choice: " choice
    case $choice in
        1) create_device_snapshot "$device_serial" ;;
        2)
           read -r -p "Enter directories to snapshot (space-separated): " custom_dirs
           create_device_snapshot "$device_serial" "$custom_dirs"
           ;;
        3)
           local snapshots
           mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -name "forensics_*" -type d | sort -r)
           if [ ${#snapshots[@]} -eq 0 ]; then
               log "ERROR" "No snapshots found. Create a snapshot first."
               return 1
           fi

           echo "Available snapshots:"
           for i in "${!snapshots[@]}"; do
               echo "$((i+1)). $(basename "${snapshots[$i]}")"
           done

           read -r -p "Select snapshot number: " snapshot_num
            read -r -p "Enter search pattern: " search_pattern

           if [[ "$snapshot_num" =~ ^[0-9]+$ && "$snapshot_num" -ge 1 && "$snapshot_num" -le ${#snapshots[@]} ]]; then
               search_forensic_data "${snapshots[$((snapshot_num-1))]}" "$search_pattern"
           else
               log "ERROR" "Invalid selection."
           fi
           ;;
        4)
           local snapshots
           mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -name "forensics_*" -type d | sort -r)
           if [ ${#snapshots[@]} -eq 0 ]; then
               log "ERROR" "No snapshots found. Create a snapshot first."
               return 1
           fi

           echo "Available snapshots:"
           for i in "${!snapshots[@]}"; do
               echo "$((i+1)). $(basename "${snapshots[$i]}")"
           done

           read -r -p "Select snapshot number: " snapshot_num

           if [[ "$snapshot_num" =~ ^[0-9]+$ && "$snapshot_num" -ge 1 && "$snapshot_num" -le ${#snapshots[@]} ]]; then
               local db_dir
               db_dir="$OUTPUT_DIR/databases_$(date +%Y%m%d_%H%M%S)"
               mkdir -p "$db_dir"

               log "INFO" "Extracting SQLite databases to $db_dir"
               find "${snapshots[$((snapshot_num-1))]}" -name "*.db" -o -name "*.sqlite" | while read -r db; do
                   local db_name
                   db_name=$(basename "$db")
                   local db_path
                   db_path=$(dirname "$db" | sed "s|${snapshots[$((snapshot_num-1))]}||")
                   local target_dir="$db_dir$db_path"

                   mkdir -p "$target_dir"
                   cp "$db" "$target_dir/"
                   log "DEBUG" "Extracted: $db_name"
               done

               log "SUCCESS" "Extracted databases to $db_dir"
           else
               log "ERROR" "Invalid selection."
           fi
           ;;
        5)
           local snapshots
           mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -name "forensics_*" -type d | sort -r)
           if [ ${#snapshots[@]} -eq 0 ]; then
               log "ERROR" "No snapshots found. Create a snapshot first."
               return 1
           fi

           echo "Available snapshots:"
           for i in "${!snapshots[@]}"; do
               echo "$((i+1)). $(basename "${snapshots[$i]}")"
           done

           read -r -p "Select snapshot number: " snapshot_num
            read -r -p "Enter package name (or part of it): " package_name

           if [[ "$snapshot_num" =~ ^[0-9]+$ && "$snapshot_num" -ge 1 && "$snapshot_num" -le ${#snapshots[@]} ]]; then
               local snapshot="${snapshots[$((snapshot_num-1))]}"
               local app_analysis_file
               app_analysis_file="$OUTPUT_DIR/app_analysis_$(date +%Y%m%d_%H%M%S).txt"

               log "INFO" "Analyzing app data for package: $package_name"

               {
                   echo "# App Data Analysis for: $package_name"
                   echo "# Generated: $(date)"
                   echo ""

                   echo "## App Directories Found"
                   find "$snapshot" -path "*data*$package_name*" -type d | while read -r dir; do
                       echo "- $dir"
                   done
                   echo ""

                   echo "## Shared Preferences"
                   find "$snapshot" -path "*data*$package_name*/shared_prefs" -type d | while read -r pref_dir; do
                       find "$pref_dir" -name "*.xml" | while read -r pref_file; do
                           echo "File: $pref_file"
                           echo '```'
                           grep -v "^$" "$pref_file" | head -20
                           echo '```'
                           echo ""
                       done
                   done

                   echo "## Databases"
                   find "$snapshot" -path "*data*$package_name*/databases" -type d | while read -r db_dir; do
                       find "$db_dir" -name "*.db" | while read -r db_file; do
                           echo "Database: $db_file"
                           echo "Tables:"
                           sqlite3 "$db_file" ".tables" 2>/dev/null || echo "  (Could not read database schema)"
                           echo ""
                       done
                   done

               } > "$app_analysis_file"

               log "SUCCESS" "App analysis saved to $app_analysis_file"
           else
               log "ERROR" "Invalid selection."
           fi
           ;;
        *) log "ERROR" "Invalid choice." ;;
    esac
}
