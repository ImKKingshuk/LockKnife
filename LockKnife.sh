#!/bin/bash


DEFAULT_WORDLIST="/usr/share/dict/words"
DEFAULT_OUTPUT_DIR="$HOME/lockknife_output"
DEFAULT_DEBUG_MODE=false
DEFAULT_MAX_RETRIES=3
DEFAULT_SECURE_DELETE=true
DEFAULT_PARALLEL_JOBS="50%"
DEFAULT_PIN_LENGTH=4
DEFAULT_SNAPSHOT_DIRS="/data/data /data/system /sdcard"
DEFAULT_PCAP_FILTER="port not 5555"


DEBUG_MODE=$DEFAULT_DEBUG_MODE
TEMP_DIR=$(mktemp -d /tmp/lockknife.XXXXXX)
LOG_FILE="$TEMP_DIR/lockknife_log.txt"
MAX_RETRIES=$DEFAULT_MAX_RETRIES
WORDLIST=$DEFAULT_WORDLIST
OUTPUT_DIR=$DEFAULT_OUTPUT_DIR
SECURE_DELETE=$DEFAULT_SECURE_DELETE
PARALLEL_JOBS=$DEFAULT_PARALLEL_JOBS
PIN_LENGTH=$DEFAULT_PIN_LENGTH
SNAPSHOT_DIRS=$DEFAULT_SNAPSHOT_DIRS
PCAP_FILTER=$DEFAULT_PCAP_FILTER


CONFIG_PATHS=(
    "./lockknife.conf"
    "$HOME/.config/lockknife/lockknife.conf"
    "/etc/lockknife.conf"
)


load_config() {
    local config_loaded=false
    
    for config_path in "${CONFIG_PATHS[@]}"; do
        if [ -f "$config_path" ]; then
            log "INFO" "Loading configuration from $config_path"
            source "$config_path"
            config_loaded=true
            break
        fi
    done
    
    if [ "$config_loaded" = false ]; then
        log "DEBUG" "No configuration file found, using defaults"
    fi
    
   
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        chmod 700 "$OUTPUT_DIR"
        log "DEBUG" "Created output directory: $OUTPUT_DIR"
    fi
}


mkdir -p "$TEMP_DIR"
chmod 700 "$TEMP_DIR"


log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_message="[$timestamp] [$level] $message"
    
  
    if [ "$DEBUG_MODE" = true ]; then
        echo "$log_message" >> "$LOG_FILE"
    fi
    
  
    case "$level" in
        "DEBUG")
            [ "$DEBUG_MODE" = true ] && echo "$log_message"
            ;;
        *)
            echo "$log_message"
            ;;
    esac
}


cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        log "INFO" "Securely removing temporary files..."
        find "$TEMP_DIR" -type f -exec shred -uzn 3 {} \; 2>/dev/null
        rm -rf "$TEMP_DIR"
    fi
}


trap cleanup EXIT INT TERM


create_default_config() {
    local config_path="$1"
    
    if [ -f "$config_path" ]; then
        log "WARNING" "Configuration file already exists at $config_path"
        read -r -p "Overwrite existing config? (y/n): " overwrite
        if [ "$overwrite" != "y" ]; then
            log "INFO" "Keeping existing configuration file"
            return 0
        fi
    fi
    
    log "INFO" "Creating default configuration file at $config_path"
    

    local config_dir
    config_dir=$(dirname "$config_path")
    if [ ! -d "$config_dir" ]; then
        mkdir -p "$config_dir"
    fi
    
    cat > "$config_path" << EOF



DEBUG_MODE=$DEFAULT_DEBUG_MODE         
MAX_RETRIES=$DEFAULT_MAX_RETRIES       
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"       
SECURE_DELETE=$DEFAULT_SECURE_DELETE   


WORDLIST="$DEFAULT_WORDLIST"           
PARALLEL_JOBS="$DEFAULT_PARALLEL_JOBS" 
PIN_LENGTH=$DEFAULT_PIN_LENGTH         


SNAPSHOT_DIRS="$DEFAULT_SNAPSHOT_DIRS" 
PCAP_FILTER="$DEFAULT_PCAP_FILTER"     
EOF
    
    chmod 600 "$config_path"
    log "INFO" "Default configuration file created"
    return 0
}


execute_with_retry() {
    local cmd="$1"
    local description="$2"
    local retry_count=0
    local max_retries=${3:-$MAX_RETRIES}
    local result=0
    
    while [ $retry_count -lt "$max_retries" ]; do
        log "DEBUG" "Executing: $cmd"
        if [ "$DEBUG_MODE" = true ]; then
            eval "$cmd"
        else
            eval "$cmd" 2>/dev/null
        fi
        result=$?
        
        if [ $result -eq 0 ]; then
            [ $retry_count -gt 0 ] && log "INFO" "$description succeeded after $retry_count retries"
            return 0
        else
            retry_count=$((retry_count + 1))
            log "WARNING" "$description failed (attempt $retry_count/$max_retries)"
            sleep 2
        fi
    done
    
    log "ERROR" "$description failed after $max_retries attempts"
    return 1
}


parse_arguments() {
    for arg in "$@"; do
        case "$arg" in
            --debug)
                DEBUG_MODE=true
                log "DEBUG" "Debug mode enabled"
                ;;
            --config=*)
                local config_file="${arg#*=}"
                if [ -f "$config_file" ]; then
                    source "$config_file"
                    log "INFO" "Loaded custom config from $config_file"
                else
                    log "ERROR" "Config file not found: $config_file"
                    exit 1
                fi
                ;;
            --create-config=*)
                local config_path="${arg#*=}"
                create_default_config "$config_path"
                exit 0
                ;;
            --output-dir=*)
                OUTPUT_DIR="${arg#*=}"
                log "DEBUG" "Output directory set to $OUTPUT_DIR"
                ;;
            --wordlist=*)
                WORDLIST="${arg#*=}"
                log "DEBUG" "Wordlist set to $WORDLIST"
                ;;
            --help)
                show_help
                exit 0
                ;;
        esac
    done
}


show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --debug                Enable debug mode with verbose logging"
    echo "  --config=FILE          Use specific configuration file"
    echo "  --create-config=FILE   Create default configuration file at specified path"
    echo "  --output-dir=DIR       Specify custom output directory"
    echo "  --wordlist=FILE        Specify custom wordlist file"
    echo "  --help                 Show the help message"
}




echo "LockKnife : The Ultimate Android Security Research Tool is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations."


print_banner() {
    local banner=(
        "****************************************************"
        "*                     LockKnife                    *"
        "*    The Ultimate Android Security Research Tool   *"
        "*                       v2.0.1                     *"
        "*      --------------------------------------      *"
        "*                              by @ImKKingshuk     *"
        "*      Github - https://github.com/ImKKingshuk     *"
        "****************************************************"
    )
    local width
    width=$(tput cols)
    for line in "${banner[@]}"; do
        printf "%*s\n" $(((${#line} + width) / 2)) "$line"
    done
    echo
}


check_adb() {
    if ! command -v adb &>/dev/null; then
        echo "Error: ADB (Android Debug Bridge) not found. Please install ADB and make sure it's in your PATH."
        echo "You can download ADB from the Android SDK platform-tools. Follow the instructions for your OS:"
        echo "macOS / Linux / Windows: https://developer.android.com/tools/releases/platform-tools"
        exit 1
    fi
}


check_dependencies() {
    local dependencies=("adb" "sqlite3" "curl")
    local missing=()

    echo "[INFO] Checking required dependencies..."
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        echo "[ERROR] Missing dependencies: ${missing[*]}"
        echo "Attempting to install missing dependencies..."
        if command -v apt &>/dev/null; then
            sudo apt update && sudo apt install -y "${missing[@]}"
        elif command -v brew &>/dev/null; then
            brew install "${missing[@]}"
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y "${missing[@]}"
        else
            echo "[ERROR] Unsupported package manager. Install dependencies manually."
            exit 1
        fi
    else
        echo "[INFO] All dependencies are installed."
    fi
}


check_for_updates() {
    local current_version
    current_version=$(cat version.txt 2>/dev/null || echo "unknown")
    local latest_version
    latest_version=$(curl -sSL "https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/version.txt" 2>/dev/null || echo "$current_version")

    if [ "$latest_version" != "$current_version" ]; then
        echo "A new version ($latest_version) is available. Updating Tool... Please Wait..."
        update_tool
    else
        echo "You are using the latest version ($current_version)."
    fi
}


update_tool() {
    local repo_url="https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main"
    local tmp_script="LockKnife_tmp.sh"
    local tmp_version="version_tmp.txt"

    curl -sSL "$repo_url/LockKnife.sh" -o "$tmp_script"
    curl -sSL "$repo_url/version.txt" -o "$tmp_version"

    if [[ -s "$tmp_script" && -s "$tmp_version" ]]; then
        mv "$tmp_script" LockKnife.sh
        mv "$tmp_version" version.txt
        echo "[INFO] Tool has been updated to the latest version."
        exec bash LockKnife.sh
    else
        echo "[ERROR] Update failed. Retaining current version."
        rm -f "$tmp_script" "$tmp_version"
    fi
}


connect_device() {
    local device_serial="$1"
    
    log "INFO" "Attempting to connect to device: $device_serial"
    
    if ! execute_with_retry "adb connect $device_serial" "Device connection"; then
        log "ERROR" "Failed to connect to the device with serial number: $device_serial."
        log "ERROR" "Ensure the device is reachable and ADB debugging is enabled."
        exit 1
    else
        log "INFO" "Successfully connected to device: $device_serial"
    fi
}



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
    
   
    local grid=(7 8 9 4 5 6 1 2 3)
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


check_security() {
    local device_serial="$1"
    local version
    version=$(adb -s "$device_serial" shell getprop ro.build.version.release)
    local patch
    patch=$(adb -s "$device_serial" shell getprop ro.build.version.security_patch)
    local rooted
    rooted=$(adb -s "$device_serial" shell "su -c 'id'" | grep -q "uid=0" && echo "Yes" || echo "No")
    echo "[INFO] Android Version: $version"
    echo "[INFO] Security Patch: $patch"
    echo "[INFO] Rooted: $rooted"
}


frp_bypass() {
    echo "[WARNING] FRP bypass is a sensitive operation and should only be performed on devices you own or have explicit permission to test."
    echo "[INFO] This feature is not implemented in this version of LockKnife."
}


select_device() {
    local devices=()
    local usb_devices
    mapfile -t usb_devices < <(adb devices | grep -w device | awk '{print $1}')
    local tcp_devices
    mapfile -t tcp_devices < <(adb devices | grep -w "device.*:5555" | awk '{print $1}')
    

    devices=("${usb_devices[@]}" "${tcp_devices[@]}")
    

    if [ ${#devices[@]} -eq 0 ]; then
        log "WARNING" "No devices found connected via USB."
        read -r -p "Would you like to connect to a device via IP? (y/n): " connect_choice
        
        if [ "$connect_choice" = "y" ]; then
            read -r -p "Enter the IP address of the device: " device_ip

            if [[ ! "$device_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                log "ERROR" "Invalid IP address format. Please enter a valid IP address."
                return 1
            fi
            
            log "INFO" "Attempting to connect to device at $device_ip:5555..."
            if execute_with_retry "adb connect $device_ip:5555" "Device connection"; then

                local tcp_devices
                mapfile -t tcp_devices < <(adb devices | grep -w connected | awk '{print $1}')
                devices=("${usb_devices[@]}" "${tcp_devices[@]}")
            else
                log "ERROR" "Failed to connect to device at $device_ip:5555. Please check the IP and make sure ADB debugging is enabled."
                return 1
            fi
        else
            log "ERROR" "No devices found. Please connect a device and ensure ADB debugging is enabled."
            exit 1
        fi
    fi
    

    if [ ${#devices[@]} -eq 0 ]; then
        log "ERROR" "No devices found. Please connect a device and ensure ADB debugging is enabled."
        exit 1
    fi
    

    if [ ${#devices[@]} -eq 1 ]; then
        log "INFO" "Using device: ${devices[0]}"
        echo "${devices[0]}"
        return 0
    fi
    

    log "INFO" "Multiple devices found. Please select one:"
    for i in "${!devices[@]}"; do
        local device_info
        device_info=$(adb -s "${devices[$i]}" shell getprop ro.product.model 2>/dev/null || echo "Unknown")
        echo "$((i+1)). ${devices[$i]} ($device_info)"
    done
    

    local valid_selection=false
    local num
    while [ "$valid_selection" = false ]; do
        read -r -p "Device number (1-${#devices[@]}): " num
        if [[ "$num" =~ ^[0-9]+$ && "$num" -ge 1 && "$num" -le ${#devices[@]} ]]; then
            valid_selection=true
        else
            log "ERROR" "Invalid selection. Please enter a number between 1 and ${#devices[@]}."
        fi
    done
    
    echo "${devices[$((num-1))]}"
    return 0
}



secure_pull_file() {
    local device_serial="$1"
    local remote_path="$2"
    local local_path
    local_path="$TEMP_DIR/$(basename "$remote_path")"
    
    log "DEBUG" "Attempting to pull $remote_path to $local_path"
    

    if ! execute_with_retry "adb -s $device_serial shell '[ -f $remote_path ] && echo exists'" "File existence check" | grep -q "exists"; then
        log "ERROR" "File $remote_path does not exist on device."
        return 1
    fi
    

    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $remote_path\"' 2>/dev/null" "File permission change" || true
    

    if ! execute_with_retry "adb -s $device_serial pull $remote_path $local_path" "File transfer"; then
        log "ERROR" "Failed to pull file $remote_path from device."
        return 1
    fi
    

    chmod 600 "$local_path"
    
    echo "$local_path"
    return 0
}



secure_delete_file() {
    local file_path="$1"
    
    if [ ! -f "$file_path" ]; then
        log "DEBUG" "File $file_path does not exist, nothing to delete."
        return 0
    fi
    
    log "DEBUG" "Securely deleting file: $file_path"
    

    if command -v shred &>/dev/null; then
        shred -uzn 3 "$file_path"
    else

        dd if=/dev/urandom of="$file_path" bs=1k count=1 conv=notrunc &>/dev/null
        rm -f "$file_path"
    fi
    
    return 0
}


main_menu() {
    local device_serial="$1"
    echo "LockKnife - Security Research Tool"
    echo "1. Password Recovery"
    echo "2. Data Extraction"
    echo "3. Live Analysis"
    echo "4. Security Assessment"
    echo "5. Custom Data Extraction"
    echo "6. Forensic Analysis"
    echo "7. Network Traffic Analysis"
    read -r -p "Choice: " choice
    case $choice in
        1) submenu_password_recovery "$device_serial" ;;
        2) submenu_data_extraction "$device_serial" ;;
        3) live_analysis "$device_serial" ;;
        4) check_security "$device_serial" ;;
        5) custom_data_extraction "$device_serial" ;;
        6) submenu_forensic_analysis "$device_serial" ;;
        7) submenu_network_analysis "$device_serial" ;;
        *) echo "[ERROR] Invalid choice." ;;
    esac
}


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
    sqlite3 "$sms_db" "SELECT address, date, body FROM sms ORDER BY date DESC LIMIT 10;" | awk -F'|' '{print "From: "$1" | Date: "$2" | Msg: "$3}'
    
    read -r -p "Keep SMS database? (y/n): " keep
    if [ "$keep" != "y" ]; then
        secure_delete_file "$sms_db"
    else
        local output_file
        output_file="sms_database_$(date +%s).db"
        cp "$sms_db" "$output_file"
        chmod 600 "$output_file"
        log "INFO" "SMS database saved as $output_file"
        secure_delete_file "$sms_db"
    fi
    
    return 0
}


recover_call_logs() {
    local device_serial="$1"
    local call_db="$TEMP_DIR/contacts2.db"
    
    log "INFO" "Attempting to pull call log database (root required)..."
    

    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 /data/data/com.android.providers.contacts/databases/contacts2.db\"'" "Setting permissions" || true
    

    if ! execute_with_retry "adb -s $device_serial pull /data/data/com.android.providers.contacts/databases/contacts2.db $call_db" "Call logs transfer"; then
        log "ERROR" "Failed to pull call log database. Root access required."
        return 1
    fi
    
    if [ ! -f "$call_db" ]; then
        log "ERROR" "Call log database file not found after pull attempt. Check transfer."
        return 1
    fi
    
    log "INFO" "Extracting recent call logs..."
    sqlite3 "$call_db" "SELECT number, date, duration, type FROM calls ORDER BY date DESC LIMIT 10;" | awk -F'|' '{print "Number: "$1" | Date: "$2" | Duration: "$3" | Type: "$4}'
    
    read -r -p "Keep call log database? (y/n): " keep
    if [ "$keep" != "y" ]; then
        secure_delete_file "$call_db"
    else
        local output_file
        output_file="call_logs_$(date +%s).db"
        cp "$call_db" "$output_file"
        chmod 600 "$output_file"
        log "INFO" "Call logs database saved as $output_file"
        secure_delete_file "$call_db"
    fi
    
    return 0
}


live_analysis() {
    local device_serial="$1"
    log "INFO" "Live Analysis Options:"
    echo "1. Dump system logs"
    echo "2. List running processes"
    echo "3. List installed apps"
    echo "4. Monitor Keystore Access"
    read -r -p "Choice: " choice
    case $choice in
        1) 
           local log_file
           log_file="$TEMP_DIR/system_logs_$(date +%s).txt"
           if execute_with_retry "adb -s $device_serial logcat -d > $log_file" "Log capture"; then
               local output_file
                output_file="system_logs_$(date +%s).txt"
               cp "$log_file" "$output_file"
               chmod 600 "$output_file"
               log "INFO" "Logs saved to $output_file"
               secure_delete_file "$log_file"
           fi
           ;;
        2) execute_with_retry "adb -s $device_serial shell ps" "Process listing" ;;
        3) execute_with_retry "adb -s $device_serial shell pm list packages" "Package listing" ;;
        *) log "ERROR" "Invalid choice." ;;
    esac
}


custom_data_extraction() {
    local device_serial="$1"
    read -r -p "Enter file path to pull: " file_path
    read -r -p "Is this a SQLite database? (y/n): " is_db
    
    local local_file
    local_file="$TEMP_DIR/$(basename "$file_path")"
    

    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file_path\"'" "Setting permissions" || true
    
    if ! execute_with_retry "adb -s $device_serial pull $file_path $local_file" "File transfer"; then
        log "ERROR" "Failed to pull file."
        return 1
    fi
    
    if [ ! -f "$local_file" ]; then
        log "ERROR" "Failed to pull file."
        return 1
    fi
    
    if [ "$is_db" = "y" ]; then
        read -r -p "Enter SQL query: " sql_query
        sqlite3 "$local_file" "$sql_query"
    else
        log "INFO" "File pulled: $(basename "$file_path")"
    fi
    
    read -r -p "Keep file? (y/n): " keep
    if [ "$keep" != "y" ]; then
        secure_delete_file "$local_file"
    else
        local output_file
        output_file="$(basename "$file_path")_$(date +%s)"
        cp "$local_file" "$output_file"
        chmod 600 "$output_file"
        log "INFO" "File saved as $output_file"
        secure_delete_file "$local_file"
    fi
}



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



create_device_snapshot() {
    local device_serial="$1"
    local dirs_to_backup="${2:-$SNAPSHOT_DIRS}"
    local output_dir
    output_dir="$OUTPUT_DIR/forensics_$(date +%Y%m%d_%H%M%S)"
    local archive_name
    archive_name="device_snapshot_$(date +%Y%m%d_%H%M%S).tar.gz"
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
    
    # Move the temporary file to the final destination
    mv "${summary_file}.tmp" "$summary_file"
    
    log "INFO" "Forensics summary created: $summary_file"
}


search_forensic_data() {
    local snapshot_dir="$1"
    local search_pattern="$2"
    local output_file
    output_file="$OUTPUT_DIR/forensic_search_$(date +%Y%m%d_%H%M%S).txt"
    
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


capture_network_traffic() {
    local device_serial="$1"
    local duration="$2"
    local filter="${3:-$PCAP_FILTER}"
    local output_file
    output_file="$OUTPUT_DIR/network_capture_$(date +%Y%m%d_%H%M%S).pcap"
    
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


execute_lockknife() {

    parse_arguments "$@"
    

    load_config
    

    print_banner
    

    if [ "$DEBUG_MODE" = false ]; then
        check_for_updates
    else
        log "DEBUG" "Skipping update check in debug mode"
    fi
    

    check_dependencies
    

    check_adb
    

    device_serial=$(select_device)
    if [ -z "$device_serial" ]; then
        log "ERROR" "No device selected. Exiting."
        exit 1
    fi
    

    connect_device "$device_serial"
    

    check_root "$device_serial"
    

    main_menu "$device_serial"
    

    log "INFO" "LockKnife execution completed successfully."
}


check_root() {
    local device_serial="$1"
    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "WARNING" "Root not detected. Some features require root access and may not function properly."
    else
        log "INFO" "Root access detected. All features should be available."
    fi
}



extract_whatsapp_data() {
    local device_serial="$1"
    local output_dir
    output_dir="$OUTPUT_DIR/app_whatsapp_$(date +%Y%m%d_%H%M%S)"
    local temp_dir="$TEMP_DIR/whatsapp"
    
    log "INFO" "Extracting WhatsApp data (requires root)..."
    mkdir -p "$temp_dir"
    mkdir -p "$output_dir"
    

    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for WhatsApp data extraction"
        return 1
    fi
    

    local msgstore_path="/data/data/com.whatsapp/databases/msgstore.db"
    local wa_path="/data/data/com.whatsapp/databases/wa.db"
    local axolotl_path="/data/data/com.whatsapp/databases/axolotl.db"
    local chatsettings_path="/data/data/com.whatsapp/databases/chatsettings.db"
    

    # local media_path="/sdcard/WhatsApp/Media"  # Unused, commented out
    

    log "INFO" "Pulling WhatsApp databases..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $msgstore_path\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $wa_path\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $axolotl_path\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $chatsettings_path\"'" "Setting permissions" || true
    
    execute_with_retry "adb -s $device_serial pull $msgstore_path $temp_dir/" "Pull msgstore.db"
    execute_with_retry "adb -s $device_serial pull $wa_path $temp_dir/" "Pull wa.db"
    execute_with_retry "adb -s $device_serial pull $axolotl_path $temp_dir/" "Pull axolotl.db"
    execute_with_retry "adb -s $device_serial pull $chatsettings_path $temp_dir/" "Pull chatsettings.db"
    

    local summary_file="$output_dir/whatsapp_summary.txt"
    {
        echo "# WhatsApp Data Extraction Report"
        echo "# Generated: $(date)"
        echo ""
        

        if [ -f "$temp_dir/msgstore.db" ]; then
            echo "## Message Database Analysis"
            echo ""
            

            echo "### Chat List"
            sqlite3 "$temp_dir/msgstore.db" "SELECT jid, subject, sort_timestamp FROM chat_list ORDER BY sort_timestamp DESC LIMIT 20;" 2>/dev/null | 
            while IFS='|' read -r jid subject timestamp; do
                echo "- JID: $jid"
                echo "  Subject: $subject"
                echo "  Last Activity: $(date -d @$((timestamp/1000)) 2>/dev/null || date -r $((timestamp/1000)) 2>/dev/null || echo "$timestamp")"
                echo ""
            done
            

            echo "### Message Statistics"
            echo "Total messages: $(sqlite3 "$temp_dir/msgstore.db" "SELECT COUNT(*) FROM messages;" 2>/dev/null || echo "Unknown")"
            echo "Media messages: $(sqlite3 "$temp_dir/msgstore.db" "SELECT COUNT(*) FROM messages WHERE media_wa_type > 0;" 2>/dev/null || echo "Unknown")"
            echo ""
            

            cp "$temp_dir/msgstore.db" "$output_dir/"
            chmod 600 "$output_dir/msgstore.db"
        else
            echo "## Message Database Not Found"
            echo ""
        fi
        

        if [ -f "$temp_dir/wa.db" ]; then
            echo "## Contacts Database Analysis"
            echo ""
            

            echo "### Contact List (Sample)"
            sqlite3 "$temp_dir/wa.db" "SELECT jid, display_name, status FROM wa_contacts WHERE display_name IS NOT NULL LIMIT 10;" 2>/dev/null |
            while IFS='|' read -r jid name status; do
                echo "- Name: $name"
                echo "  JID: $jid"
                echo "  Status: $status"
                echo ""
            done
            

            cp "$temp_dir/wa.db" "$output_dir/"
            chmod 600 "$output_dir/wa.db"
        else
            echo "## Contacts Database Not Found"
            echo ""
        fi
        
    } > "$summary_file"
    

    find "$temp_dir" -name "*.db" -exec cp {} "$output_dir/" \;
    find "$output_dir" -name "*.db" -exec chmod 600 {} \;
    
    log "SUCCESS" "WhatsApp data extracted to $output_dir"
    

    secure_delete_file "$temp_dir"/*
    
    return 0
}

extract_telegram_data() {
    local device_serial="$1"
    local output_dir
    output_dir="$OUTPUT_DIR/app_telegram_$(date +%Y%m%d_%H%M%S)"
    local temp_dir="$TEMP_DIR/telegram"
    
    log "INFO" "Extracting Telegram data (requires root)..."
    mkdir -p "$temp_dir"
    mkdir -p "$output_dir"
    

    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for Telegram data extraction"
        return 1
    fi
    

    local telegram_path="/data/data/org.telegram.messenger"
    local cache_path="$telegram_path/cache"
    # local files_path="$telegram_path/files"  # Unused, commented out
    local db_path="$telegram_path/files/Telegram"
    

    log "INFO" "Identifying Telegram databases..."
    local db_files
    db_files=$(execute_with_retry "adb -s $device_serial shell 'su -c \"find $db_path -name \"*.db\"\"'" "Find Telegram databases")
    

    for db_file in $db_files; do
        log "INFO" "Pulling database: $db_file"
        execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $db_file\"'" "Setting permissions" || true
        

        local filename
        filename=$(basename "$db_file")
        execute_with_retry "adb -s $device_serial pull $db_file $temp_dir/$filename" "Pull $filename"
    done
    

    log "INFO" "Pulling MTProto cache files..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"find $cache_path -name \"mtproto*\"\"'" "Find MTProto files" | while read -r file; do
        if [ -n "$file" ]; then
            execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file\"'" "Setting permissions" || true
            local filename
            filename=$(basename "$file")
            execute_with_retry "adb -s $device_serial pull $file $temp_dir/$filename" "Pull $filename"
        fi
    done
    

    local summary_file="$output_dir/telegram_summary.txt"
    {
        echo "# Telegram Data Extraction Report"
        echo "# Generated: $(date)"
        echo ""
        

        echo "## Extracted Files"
        find "$temp_dir" -type f | while read -r file; do
            echo "- $(basename "$file") ($(du -h "$file" | cut -f1))"
        done
        echo ""
        

        if [ -f "$temp_dir/cache.db" ]; then
            echo "## Cache Database Analysis"
            echo ""
            

            echo "### Tables"
            sqlite3 "$temp_dir/cache.db" ".tables" 2>/dev/null || echo "Could not read tables"
            echo ""
            

            cp "$temp_dir/cache.db" "$output_dir/"
            chmod 600 "$output_dir/cache.db"
        fi
        
    } > "$summary_file"
    

    cp -r "$temp_dir"/* "$output_dir/"
    find "$output_dir" -type f -exec chmod 600 {} \;
    
    log "SUCCESS" "Telegram data extracted to $output_dir"
    

    secure_delete_file "$temp_dir"/*
    
    return 0
}

extract_signal_data() {
    local device_serial="$1"
    local output_dir
    output_dir="$OUTPUT_DIR/app_signal_$(date +%Y%m%d_%H%M%S)"
    local temp_dir="$TEMP_DIR/signal"
    
    log "INFO" "Extracting Signal data (requires root)..."
    mkdir -p "$temp_dir"
    mkdir -p "$output_dir"
    

    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for Signal data extraction"
        return 1
    fi
    

    local signal_path="/data/data/org.thoughtcrime.securesms"
    local db_path="$signal_path/databases"
    local shared_prefs="$signal_path/shared_prefs"
    

    log "INFO" "Pulling Signal databases..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $db_path/signal.db\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial pull $db_path/signal.db $temp_dir/" "Pull signal.db"
    

    log "INFO" "Pulling Signal key-value store..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $db_path/signal_key_value.db\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial pull $db_path/signal_key_value.db $temp_dir/" "Pull signal_key_value.db"
    

    log "INFO" "Pulling Signal shared preferences..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"find $shared_prefs -name \"*.xml\"\"'" "Find preferences" | while read -r file; do
        if [ -n "$file" ]; then
            execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file\"'" "Setting permissions" || true
            local filename
            filename=$(basename "$file")
            execute_with_retry "adb -s $device_serial pull $file $temp_dir/$filename" "Pull $filename"
        fi
    done
    

    local summary_file="$output_dir/signal_summary.txt"
    {
        echo "# Signal Data Extraction Report"
        echo "# Generated: $(date)"
        echo ""
        

        echo "## Extracted Files"
        find "$temp_dir" -type f | while read -r file; do
            echo "- $(basename "$file") ($(du -h "$file" | cut -f1))"
        done
        echo ""
        

        if [ -f "$temp_dir/signal.db" ]; then
            echo "## Signal Database Analysis"
            echo ""
            

            echo "### Tables"
            sqlite3 "$temp_dir/signal.db" ".tables" 2>/dev/null || echo "Could not read tables"
            echo ""
            

            echo "### Statistics"
            echo "Recipients: $(sqlite3 "$temp_dir/signal.db" "SELECT COUNT(*) FROM recipient;" 2>/dev/null || echo "Unknown")"
            echo "Messages: $(sqlite3 "$temp_dir/signal.db" "SELECT COUNT(*) FROM sms;" 2>/dev/null || echo "Unknown")"
            echo ""
            

            cp "$temp_dir/signal.db" "$output_dir/"
            chmod 600 "$output_dir/signal.db"
        fi
        

        echo "## Shared Preferences"
        find "$temp_dir" -name "*.xml" | while read -r file; do
            echo "### $(basename "$file")"
            grep -v "^$" "$file" | head -10
            echo "..."
            echo ""
        done
        
    } > "$summary_file"
    

    cp -r "$temp_dir"/* "$output_dir/"
    find "$output_dir" -type f -exec chmod 600 {} \;
    
    log "SUCCESS" "Signal data extracted to $output_dir"
    

    secure_delete_file "$temp_dir"/*
    
    return 0
}

extract_browser_data() {
    local device_serial="$1"
    local browser_type="$2"
    local output_dir
    output_dir="$OUTPUT_DIR/app_${browser_type}_$(date +%Y%m%d_%H%M%S)"
    local temp_dir="$TEMP_DIR/$browser_type"
    
    log "INFO" "Extracting $browser_type browser data (requires root)..."
    mkdir -p "$temp_dir"
    mkdir -p "$output_dir"
    

    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for browser data extraction"
        return 1
    fi
    

    local browser_path=""
    case "$browser_type" in
        chrome)
            browser_path="/data/data/com.android.chrome"
            ;;
        firefox)
            browser_path="/data/data/org.mozilla.firefox"
            ;;
        brave)
            browser_path="/data/data/com.brave.browser"
            ;;
        edge)
            browser_path="/data/data/com.microsoft.emmx"
            ;;
        *)
            log "ERROR" "Unsupported browser type: $browser_type"
            return 1
            ;;
    esac
    

    log "INFO" "Pulling $browser_type databases..."
    local db_path="$browser_path/app_chrome/Default"
    

    if [ "$browser_type" = "chrome" ] || [ "$browser_type" = "brave" ] || [ "$browser_type" = "edge" ]; then

        execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $db_path/History\"'" "Setting permissions" || true
        execute_with_retry "adb -s $device_serial pull $db_path/History $temp_dir/" "Pull History"
        

        execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $db_path/Cookies\"'" "Setting permissions" || true
        execute_with_retry "adb -s $device_serial pull $db_path/Cookies $temp_dir/" "Pull Cookies"
        

        execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $db_path/Login\\ Data\"'" "Setting permissions" || true
        execute_with_retry "adb -s $device_serial pull "$db_path/Login Data" $temp_dir/" "Pull Login Data"
        

        execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $db_path/Web\\ Data\"'" "Setting permissions" || true
        execute_with_retry "adb -s $device_serial pull "$db_path/Web Data" $temp_dir/" "Pull Web Data"
    fi
    

    if [ "$browser_type" = "firefox" ]; then

        execute_with_retry "adb -s $device_serial shell 'su -c \"find $browser_path -name \"*.db\"\"'" "Find Firefox databases" | while read -r file; do
            if [ -n "$file" ]; then
                execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file\"'" "Setting permissions" || true
                local filename
                filename=$(basename "$file")
                execute_with_retry "adb -s $device_serial pull $file $temp_dir/$filename" "Pull $filename"
            fi
        done
    fi
    

    local summary_file="$output_dir/${browser_type}_summary.txt"
    {
        echo "# $browser_type Browser Data Extraction Report"
        echo "# Generated: $(date)"
        echo ""
        

        echo "## Extracted Files"
        find "$temp_dir" -type f | while read -r file; do
            echo "- $(basename "$file") ($(du -h "$file" | cut -f1))"
        done
        echo ""
        

        if [ -f "$temp_dir/History" ]; then
            echo "## Browser History Analysis"
            echo ""
            

            echo "### Recent History (Last 20 Entries)"
            sqlite3 "$temp_dir/History" "SELECT datetime(last_visit_time/1000000-11644473600, 'unixepoch'), url, title FROM urls ORDER BY last_visit_time DESC LIMIT 20;" 2>/dev/null |
            while IFS='|' read -r date url title; do
                echo "- $date"
                echo "  URL: $url"
                echo "  Title: $title"
                echo ""
            done
            

            echo "### Most Visited Sites"
            sqlite3 "$temp_dir/History" "SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 10;" 2>/dev/null |
            while IFS='|' read -r url title count; do
                echo "- $title"
                echo "  URL: $url"
                echo "  Visits: $count"
                echo ""
            done
            

            cp "$temp_dir/History" "$output_dir/"
            chmod 600 "$output_dir/History"
        fi
        

        if [ -f "$temp_dir/Login Data" ]; then
            echo "## Saved Passwords Analysis"
            echo ""
            

            echo "### Saved Login Information"
            sqlite3 "$temp_dir/Login Data" "SELECT origin_url, username_value FROM logins ORDER BY date_created DESC LIMIT 10;" 2>/dev/null |
            while IFS='|' read -r url username; do
                echo "- URL: $url"
                echo "  Username: $username"
                echo "  (Password encrypted)"
                echo ""
            done
            

            cp "$temp_dir/Login Data" "$output_dir/"
            chmod 600 "$output_dir/Login Data"
        fi
        
    } > "$summary_file"
    

    cp -r "$temp_dir"/* "$output_dir/"
    find "$output_dir" -type f -exec chmod 600 {} \;
    
    log "SUCCESS" "$browser_type browser data extracted to $output_dir"
    

    secure_delete_file "$temp_dir"/*
    
    return 0
}


extract_bluetooth_keys() {
    local device_serial="$1"
    local output_dir
    output_dir="$OUTPUT_DIR/bluetooth_keys_$(date +%Y%m%d_%H%M%S)"
    local temp_dir="$TEMP_DIR/bluetooth"
    
    log "INFO" "Extracting Bluetooth pairing keys (requires root)..."
    mkdir -p "$temp_dir"
    mkdir -p "$output_dir"
    

    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for Bluetooth keys extraction"
        return 1
    fi
    

    local bt_path_legacy="/data/misc/bluetoothd"
    local bt_path_modern="/data/misc/bluetooth"
    local bt_path_new="/data/data/com.android.bluetooth/databases"
    

    log "INFO" "Checking legacy Bluetooth files..."
    if execute_with_retry "adb -s $device_serial shell 'su -c \"ls $bt_path_legacy 2>/dev/null\"'" "Check legacy path" | grep -q "\."; then
        log "INFO" "Found legacy Bluetooth files"
        execute_with_retry "adb -s $device_serial shell 'su -c \"find $bt_path_legacy -type f\"'" "Find legacy files" | while read -r file; do
            if [ -n "$file" ]; then
                execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file\"'" "Setting permissions" || true
                local filename
                filename=$(basename "$file")
                execute_with_retry "adb -s $device_serial pull $file $temp_dir/legacy_$filename" "Pull $filename"
            fi
        done
    fi
    

    log "INFO" "Checking modern Bluetooth files..."
    if execute_with_retry "adb -s $device_serial shell 'su -c \"ls $bt_path_modern 2>/dev/null\"'" "Check modern path" | grep -q "\."; then
        log "INFO" "Found modern Bluetooth files"
        

        execute_with_retry "adb -s $device_serial shell 'su -c \"find $bt_path_modern -name \"*.conf\" -o -name \"*.xml\" -o -name \"*.bin\"\"'" "Find config files" | while read -r file; do
            if [ -n "$file" ]; then
                execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file\"'" "Setting permissions" || true
                local filename
                filename=$(basename "$file")
                execute_with_retry "adb -s $device_serial pull $file $temp_dir/$filename" "Pull $filename"
            fi
        done
        

        local bt_files=("config.xml" "bt_config.xml" "bt_config.conf" "bt_stack.conf" "bt_addr" "bt_name")
        for file in "${bt_files[@]}"; do
            if execute_with_retry "adb -s $device_serial shell 'su -c \"test -f $bt_path_modern/$file && echo exists\"'" "Check file" | grep -q "exists"; then
                execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $bt_path_modern/$file\"'" "Setting permissions" || true
                execute_with_retry "adb -s $device_serial pull $bt_path_modern/$file $temp_dir/" "Pull $file"
            fi
        done
    fi
    

    log "INFO" "Checking Bluetooth databases..."
    if execute_with_retry "adb -s $device_serial shell 'su -c \"ls $bt_path_new 2>/dev/null\"'" "Check database path" | grep -q "\."; then
        log "INFO" "Found Bluetooth databases"
        execute_with_retry "adb -s $device_serial shell 'su -c \"find $bt_path_new -name \"*.db\"\"'" "Find databases" | while read -r file; do
            if [ -n "$file" ]; then
                execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file\"'" "Setting permissions" || true
                local filename
                filename=$(basename "$file")
                execute_with_retry "adb -s $device_serial pull $file $temp_dir/$filename" "Pull $filename"
            fi
        done
    fi
    

    local summary_file="$output_dir/bluetooth_keys_summary.txt"
    {
        echo "# Bluetooth Pairing Keys Extraction Report"
        echo "# Generated: $(date)"
        echo ""
        

        echo "## Extracted Files"
        find "$temp_dir" -type f | while read -r file; do
            echo "- $(basename "$file") ($(du -h "$file" | cut -f1))"
        done
        echo ""
        

        echo "## Bluetooth Configuration Analysis"
        find "$temp_dir" -name "*.xml" | while read -r file; do
            echo "### $(basename "$file")"
            grep -E "<(name|address|linkKey|pin|passkey)" "$file" 2>/dev/null | sed 's/<[^>]*>//g' | grep -v "^$" | head -20
            echo ""
        done
        

        find "$temp_dir" -name "*.db" | while read -r db_file; do
            echo "### Database: $(basename "$db_file")"
            echo "Tables:"
            sqlite3 "$db_file" ".tables" 2>/dev/null || echo "  (Could not read database schema)"
            echo ""
            

            sqlite3 "$db_file" "SELECT * FROM sqlite_master WHERE type='table';" 2>/dev/null | grep -i "device\|addr\|pair" | while read -r table_info; do
                local table_name
                table_name=$(echo "$table_info" | awk '{print $2}')
                echo "Table: $table_name"
                sqlite3 "$db_file" "SELECT * FROM $table_name LIMIT 10;" 2>/dev/null || echo "  (Could not read table data)"
                echo ""
            done
        done
        
    } > "$summary_file"
    

    cp -r "$temp_dir"/* "$output_dir/"
    find "$output_dir" -type f -exec chmod 600 {} \;
    
    log "SUCCESS" "Bluetooth pairing keys extracted to $output_dir"
    

    secure_delete_file "$temp_dir"/*
    
    return 0
}


monitor_keystore_access() {
    local device_serial="$1"
    local duration="$2"
    local output_file
    output_file="$OUTPUT_DIR/keystore_access_$(date +%Y%m%d_%H%M%S).log"
    
    log "INFO" "Monitoring Keystore access for $duration seconds..."
    
  
    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "WARNING" "Root access not detected. Limited monitoring capabilities."
    fi
    
   
    log "INFO" "Starting logcat capture for keystore events..."
    execute_with_retry "adb -s $device_serial logcat -c" "Clear logcat"
    
   
    execute_with_retry "adb -s $device_serial logcat -v threadtime *:S KeyStore:V Keystore:V keystore:V KeyChain:V SecurityException:V -d > $output_file &" "Start logcat capture"
    
   
    log "INFO" "Monitoring for $duration seconds..."
    sleep "$duration"
    
  
    execute_with_retry "adb -s $device_serial logcat -v threadtime *:S KeyStore:V Keystore:V keystore:V KeyChain:V SecurityException:V -d >> $output_file" "Capture logcat"
    
   
    if [ -s "$output_file" ]; then
        log "SUCCESS" "Keystore access monitoring completed. Results saved to $output_file"
        
      
        local summary_file="${output_file%.log}_summary.txt"
        {
            echo "# Keystore Access Monitoring Report"
            echo "# Generated: $(date)"
            echo "# Duration: $duration seconds"
            echo ""
            
            echo "## Access Attempts Summary"
            grep -E "KeyStore|Keystore|keystore|KeyChain" "$output_file" | grep -E "get|put|access|unlock|lock" | sort | uniq -c | sort -nr
            echo ""
            
            echo "## Security Exceptions"
            grep "SecurityException" "$output_file" | head -20
            echo ""
            
            echo "## Full Log"
            echo "See: $(basename "$output_file")"
            echo ""
            
        } > "$summary_file"
        
        log "INFO" "Summary created: $summary_file"
    else
        log "WARNING" "No Keystore access events detected during monitoring period"
    fi
    
    return 0
}


analyze_gatekeeper() {
    local device_serial="$1"
    local output_dir
    output_dir="$OUTPUT_DIR/gatekeeper_analysis_$(date +%Y%m%d_%H%M%S)"
    local temp_dir="$TEMP_DIR/gatekeeper"
    
    log "INFO" "Analyzing Gatekeeper HAL for credential recovery (requires root)..."
    mkdir -p "$temp_dir"
    mkdir -p "$output_dir"
    
   
    if ! execute_with_retry "adb -s $device_serial shell 'su -c id' 2>/dev/null | grep -q 'uid=0'" "Root check"; then
        log "ERROR" "Root access required for Gatekeeper analysis"
        return 1
    fi
    
  
    local locksettings_db="/data/system/locksettings.db"
    local gatekeeper_dir="/data/system/gatekeeper"
    local device_policies_xml="/data/system/device_policies.xml"
    local password_history_key="/data/system/password_history_key"
    local password_history="/data/system/password_history"
    
  
    log "INFO" "Pulling locksettings database..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $locksettings_db\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial pull $locksettings_db $temp_dir/" "Pull locksettings.db"
    
   
    log "INFO" "Pulling gatekeeper directory..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"find $gatekeeper_dir -type f 2>/dev/null\"'" "Find gatekeeper files" | while read -r file; do
        if [ -n "$file" ]; then
            execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $file\"'" "Setting permissions" || true
            local rel_path
            rel_path="${file#"$gatekeeper_dir"/}"
            local dir_path
            dir_path="$temp_dir/gatekeeper/$(dirname "$rel_path")"
            mkdir -p "$dir_path"
            execute_with_retry "adb -s $device_serial pull $file $dir_path/" "Pull $file"
        fi
    done
    
 
    log "INFO" "Pulling device policies..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $device_policies_xml\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial pull $device_policies_xml $temp_dir/" "Pull device_policies.xml"
    
  
    log "INFO" "Pulling password history..."
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $password_history_key\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial pull $password_history_key $temp_dir/" "Pull password_history_key"
    execute_with_retry "adb -s $device_serial shell 'su -c \"chmod 644 $password_history\"'" "Setting permissions" || true
    execute_with_retry "adb -s $device_serial pull $password_history $temp_dir/" "Pull password_history"
    
 
    local summary_file="$output_dir/gatekeeper_analysis_summary.txt"
    {
        echo "# Gatekeeper HAL Analysis Report"
        echo "# Generated: $(date)"
        echo ""
        
     
        echo "## Extracted Files"
        find "$temp_dir" -type f | while read -r file; do
            echo "- $(basename "$file") ($(du -h "$file" | cut -f1))"
        done
        echo ""
        
      
        if [ -f "$temp_dir/locksettings.db" ]; then
            echo "## Locksettings Database Analysis"
            echo ""
            
           
            echo "### Lockscreen Settings"
            sqlite3 "$temp_dir/locksettings.db" "SELECT name, value FROM locksettings WHERE name LIKE 'lockscreen%';" 2>/dev/null |
            while IFS='|' read -r name value; do
                echo "- $name: $value"
            done
            echo ""
            
           
            echo "### Password Quality"
            sqlite3 "$temp_dir/locksettings.db" "SELECT name, value FROM locksettings WHERE name='lockscreen.password_type';" 2>/dev/null |
            while IFS='|' read -r name value; do
                echo "- $name: $value"
                case "$value" in
                    "65536") echo "  Type: PIN" ;;
                    "131072") echo "  Type: Pattern" ;;
                    "262144" | "327680" | "393216" | "458752") echo "  Type: Password" ;;
                    *) echo "  Type: Unknown" ;;
                esac
            done
            echo ""
            
         
            echo "### Password Hash"
            sqlite3 "$temp_dir/locksettings.db" "SELECT name, value FROM locksettings WHERE name='lockscreen.password_salt';" 2>/dev/null |
            while IFS='|' read -r name value; do
                echo "- $name: $value"
            done
            
            sqlite3 "$temp_dir/locksettings.db" "SELECT name, value FROM locksettings WHERE name='lockscreen.passwordhistory';" 2>/dev/null |
            while IFS='|' read -r name value; do
                echo "- $name: $value"
            done
            echo ""
            
           
            echo "### Hashcat Export"
            local salt
            salt=$(sqlite3 "$temp_dir/locksettings.db" "SELECT value FROM locksettings WHERE name='lockscreen.password_salt';" 2>/dev/null)
            local hash
            hash=$(sqlite3 "$temp_dir/locksettings.db" "SELECT value FROM locksettings WHERE name='lockscreen.password_hash';" 2>/dev/null)
            
            if [ -n "$salt" ] && [ -n "$hash" ]; then
                echo "$hash:$salt" > "$output_dir/hashcat_export.txt"
                echo "Exported hash:salt to hashcat_export.txt"
                echo "For PIN cracking, use: hashcat -m 5800 hashcat_export.txt -a 3 ?d?d?d?d"
                echo "For pattern cracking, use: hashcat -m 5800 hashcat_export.txt -a 3 ?d?d?d?d?d?d?d?d?d"
                echo "For password cracking, use: hashcat -m 5800 hashcat_export.txt wordlist.txt"
                echo ""
            else
                echo "No hash:salt combination found for hashcat export"
                echo ""
            fi
        else
            echo "## Locksettings Database Not Found"
            echo ""
        fi
        
     
        echo "## Gatekeeper Files Analysis"
        find "$temp_dir/gatekeeper" -type f 2>/dev/null | while read -r file; do
            echo "### $(basename "$file")"
            hexdump -C "$file" | head -10
            echo "..."
            echo ""
        done
        
       
        if [ -f "$temp_dir/device_policies.xml" ]; then
            echo "## Device Policies Analysis"
            grep -E "<(password|pin|pattern|lockscreen)" "$temp_dir/device_policies.xml" | head -20
            echo ""
        fi
        
     
        echo "## Offline Cracking Guidance"
        echo ""
        echo "### Modern Android Password Storage"
        echo "1. Android 6.0+ uses the Gatekeeper HAL for credential verification."
        echo "2. Passwords are stored as salted SHA-1 or SHA-256 hashes with PBKDF2 or scrypt."
        echo "3. For offline cracking:"
        echo "   - Extract the hash and salt from locksettings.db"
        echo "   - Use hashcat with mode 5800 (Android PIN) or appropriate mode"
        echo "   - For PINs: Try all combinations (usually 4-6 digits)"
        echo "   - For patterns: Try common patterns (0-1-2-5-8, etc.)"
        echo "   - For passwords: Use dictionary attacks with common variations"
        echo ""
        echo "### Side-Channel Attacks"
        echo "If offline cracking is not possible, consider:"
        echo "1. Monitoring Gatekeeper responses via logcat"
        echo "2. Timing attacks on the verify() function"
        echo "3. Memory analysis during credential verification"
        echo ""
        
    } > "$summary_file"
    
  
    cp -r "$temp_dir"/* "$output_dir/"
    find "$output_dir" -type f -exec chmod 600 {} \;
    
    log "SUCCESS" "Gatekeeper analysis completed. Results saved to $output_dir"
    
  
    secure_delete_file "$temp_dir"/*
    
    return 0
}


monitor_gatekeeper_responses() {
    local device_serial="$1"
    local duration="$2"
    local output_file
    output_file="$OUTPUT_DIR/gatekeeper_monitor_$(date +%Y%m%d_%H%M%S).log"
    
    log "INFO" "Monitoring Gatekeeper responses for $duration seconds..."
    
 
    execute_with_retry "adb -s $device_serial logcat -c" "Clear logcat"
    
  
    execute_with_retry "adb -s $device_serial logcat -v threadtime *:S Gatekeeper:V gatekeeper:V KeyguardUpdateMonitor:V KeyguardService:V -d > $output_file &" "Start logcat capture"
    
 
    log "INFO" "Monitoring for $duration seconds. Try to unlock your device during this time..."
    sleep "$duration"
    
  
    execute_with_retry "adb -s $device_serial logcat -v threadtime *:S Gatekeeper:V gatekeeper:V KeyguardUpdateMonitor:V KeyguardService:V -d >> $output_file" "Capture logcat"
    

    if [ -s "$output_file" ]; then
        log "SUCCESS" "Gatekeeper monitoring completed. Results saved to $output_file"
        
     
        local summary_file="${output_file%.log}_summary.txt"
        {
            echo "# Gatekeeper Response Monitoring Report"
            echo "# Generated: $(date)"
            echo "# Duration: $duration seconds"
            echo ""
            
            echo "## Authentication Attempts"
            grep -E "authenticate|verify" "$output_file" | sort | uniq -c | sort -nr
            echo ""
            
            echo "## Response Times"
            grep -E "GateKeeper|gatekeeper" "$output_file" | grep -E "time|elapsed|duration" | sort | uniq -c | sort -nr
            echo ""
            
            echo "## Failed Attempts"
            grep -E "fail|error|invalid" "$output_file" | head -20
            echo ""
            
            echo "## Full Log"
            echo "See: $(basename "$output_file")"
            echo ""
            
        } > "$summary_file"
        
        log "INFO" "Summary created: $summary_file"
    else
        log "WARNING" "No Gatekeeper events detected during monitoring period"
    fi
    
    return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    execute_lockknife "$@"
fi