#!/bin/bash

# Ethical Reminder
echo "LockKnife : The Ultimate Android Security Research Tool is developed for research and educational purposes. It should be used responsibly and in compliance with all applicable laws and regulations. The developer of this tool is not responsible for any misuse or illegal activities conducted with this tool.

Password recovery tools should only be used for legitimate purposes and with proper authorization. Using such tools without proper authorization is illegal and a violation of privacy. Ensure proper authorization before using LockKnife for password recovery or data extraction. Always adhere to ethical hacking practices and comply with all applicable laws and regulations."


print_banner() {
    local banner=(
        "****************************************************"
        "*                     LockKnife                    *"
        "*    The Ultimate Android Security Research Tool   *"
        "*                       v1.8.5                     *"
        "*      --------------------------------------      *"
        "*                              by @ImKKingshuk     *"
        "*      Github - https://github.com/ImKKingshuk     *"
        "****************************************************"
    )
    local width=$(tput cols)
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
    local current_version=$(cat version.txt 2>/dev/null || echo "unknown")
    local latest_version=$(curl -sSL "https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/version.txt" 2>/dev/null || echo "$current_version")

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
    
    adb connect "$device_serial" &>/dev/null

    if ! adb devices | grep -w "$device_serial" &>/dev/null; then
        echo "[ERROR] Failed to connect to the device with serial number: $device_serial."
        echo "Ensure the device is reachable and ADB debugging is enabled."
        exit 1
    else
        echo "[INFO] Successfully connected to device: $device_serial."
    fi
}


recover_password() {
    local file_path="$1"
    local password=""

    if [[ ! -f "$file_path" ]]; then
        echo "[ERROR] File $file_path not found or is not accessible. Exiting."
        return 1
    fi

    while IFS= read -r -n1 byte; do
        if [[ -z "$byte" ]]; then
            echo "[WARNING] Encountered invalid byte in file. Skipping."
            continue
        fi
        byte_value=$(printf "%d" "'$byte")
        decrypted_byte=$((byte_value ^ 0x6A))
        password+=$(printf "\\$(printf '%03o' "$decrypted_byte")")
    done < "$file_path"

    echo "[INFO] Recovered password: $password"

    rm -f "$file_path"
}


recover_locksettings_db() {
    local db_file="locksettings.db"
    local device_serial="$1"

    echo "[INFO] Attempting to pull locksettings database..."
    adb -s "$device_serial" shell "su -c 'chmod 644 /data/system/locksettings.db'" &>/dev/null
    adb -s "$device_serial" pull /data/system/locksettings.db &>/dev/null

    if [[ ! -f "$db_file" ]]; then
        echo "[ERROR] Unable to pull locksettings.db. Ensure root permissions are granted."
        return 1
    fi

    echo "[INFO] Locksettings database file pulled successfully. Analyzing..."
    sqlite3 "$db_file" "SELECT name, value FROM locksettings WHERE name LIKE 'lockscreen%' OR name LIKE 'pattern%' OR name LIKE 'password%';" | while read -r row; do
        echo "[INFO] Recovered setting: $row"
    done

    rm -f "$db_file"
}


recover_wifi_passwords() {
    local wifi_file="/data/misc/wifi/WifiConfigStore.xml"
    local device_serial="$1"

    echo "[INFO] Checking for Wi-Fi configuration file on device..."
    if ! adb -s "$device_serial" shell "test -f $wifi_file && echo 'exists'" | grep -q "exists"; then
        echo "[ERROR] Wi-Fi configuration file not found on device. Exiting."
        return 1
    fi

    adb -s "$device_serial" pull "$wifi_file" &>/dev/null
    if [[ ! -f "WifiConfigStore.xml" ]]; then
        echo "[ERROR] Failed to pull Wi-Fi configuration file. Check device permissions."
        return 1
    fi

    echo "[INFO] Wi-Fi configuration file pulled successfully. Analyzing..."
    grep -oP '(?<=<string name="PreSharedKey">).+?(?=</string>)' "WifiConfigStore.xml" | while read -r line; do
        echo "[INFO] Recovered Wi-Fi password: $line"
    done

    rm -f "WifiConfigStore.xml"
}


dictionary_attack() {
    local lock_file="$1"
    local wordlist

    read -p "Enter the full path to your wordlist file: " wordlist

    if [[ ! -f "$wordlist" ]]; then
        echo "[ERROR] The file '$wordlist' does not exist. Please provide a valid wordlist file."
        return 1
    fi

    if [[ ! -f "$lock_file" ]]; then
        echo "[ERROR] Lock file '$lock_file' not found. Exiting."
        return 1
    fi

    echo "[INFO] Starting dictionary attack using '$wordlist'..."
    while read -r word; do
        local hash=$(echo -n "$word" | sha1sum | awk '{print $1}')
        if grep -q "$hash" "$lock_file"; then
            echo "[SUCCESS] Password found: $word"
            return 0
        fi
    done < "$wordlist"

    echo "[INFO] Dictionary attack failed. No matching password found."
    return 1
}


brute_force_attack() {
    local lock_file="$1"
    local pin_length="$2"

    if ! [[ "$pin_length" =~ ^[0-9]+$ ]] || [ "$pin_length" -lt 4 ]; then
        echo "[ERROR] Invalid PIN length. Use a number >= 4."
        return 1
    fi

    local total=$((10 ** pin_length))

    if [ "$pin_length" -gt 6 ]; then
        echo "[WARNING] Brute-forcing PINs longer than 6 digits may take significant time."
        read -p "Continue? (y/n): " choice
        [ "$choice" != "y" ] && return 1
    fi

    local count=0
    echo "[INFO] Starting brute-force attack for $pin_length-digit PINs..."
    for i in $(seq 0 $((total - 1))); do
        local pin=$(printf "%0${pin_length}d" "$i")
        ((count++))
        if [ $((count % 1000)) -eq 0 ]; then
            printf "\rProgress: %d/%d (%.1f%%)" "$count" "$total" "$(bc <<< "scale=1; $count*100/$total")"
        fi
        local hash=$(echo -n "$pin" | sha1sum | awk '{print $1}')
        if grep -q "$hash" "$lock_file"; then
            echo -e "\n[SUCCESS] PIN found: $pin"
            return 0
        fi
    done
    echo -e "\n[INFO] Brute-force attack failed."
    return 1
}


check_security() {
    local device_serial="$1"
    local version=$(adb -s "$device_serial" shell getprop ro.build.version.release)
    local patch=$(adb -s "$device_serial" shell getprop ro.build.version.security_patch)
    local rooted=$(adb -s "$device_serial" shell "su -c 'id'" | grep -q "uid=0" && echo "Yes" || echo "No")
    echo "[INFO] Android Version: $version"
    echo "[INFO] Security Patch: $patch"
    echo "[INFO] Rooted: $rooted"
}


frp_bypass() {
    echo "[WARNING] FRP bypass is a sensitive operation and should only be performed on devices you own or have explicit permission to test."
    echo "[INFO] This feature is not implemented in this version of LockKnife."
}


select_device() {
    local devices=($(adb devices | grep -w device | awk '{print $1}'))
    [ ${#devices[@]} -eq 0 ] && { echo "[ERROR] No devices found."; exit 1; }
    [ ${#devices[@]} -eq 1 ] && { echo "[INFO] Using ${devices[0]}"; echo "${devices[0]}"; return; }
    echo "Select device:"
    for i in "${!devices[@]}"; do echo "$((i+1)). ${devices[i]}"; done
    read -p "Device number: " num
    echo "${devices[$((num-1))]}"
}


main_menu() {
    local device_serial="$1"
    echo "LockKnife - Security Research Tool"
    echo "1. Password Recovery"
    echo "2. Data Extraction"
    echo "3. Live Analysis"
    echo "4. Security Assessment"
    echo "5. Custom Data Extraction"
    read -p "Choice: " choice
    case $choice in
        1) submenu_password_recovery "$device_serial" ;;
        2) submenu_data_extraction "$device_serial" ;;
        3) live_analysis "$device_serial" ;;
        4) check_security "$device_serial" ;;
        5) custom_data_extraction "$device_serial" ;;
        *) echo "[ERROR] Invalid choice." ;;
    esac
}


submenu_password_recovery() {
    local device_serial="$1"
    echo "Password Recovery Options:"
    echo "1. Gesture Lock"
    echo "2. Password Lock"
    echo "3. Wi-Fi Passwords"
    echo "4. Locksettings DB"
    echo "5. Variable-Length PIN Cracking"
    echo "6. Alphanumeric Password Cracking"
    read -p "Choice: " choice
    case $choice in
        1) adb -s "$device_serial" pull /data/system/gesture.key && recover_password "gesture.key" ;;
        2) adb -s "$device_serial" pull /data/system/password.key && recover_password "password.key" ;;
        3) recover_wifi_passwords "$device_serial" ;;
        4) recover_locksettings_db "$device_serial" ;;
        5) read -p "Enter PIN length (e.g., 4, 6, 8): " pin_length
           brute_force_attack "path_to_lock_file" "$pin_length" ;;
        6) read -p "Enter path to wordlist: " wordlist
           dictionary_attack "path_to_lock_file" "$wordlist" ;;
        *) echo "[ERROR] Invalid choice." ;;
    esac
}


submenu_data_extraction() {
    local device_serial="$1"
    echo "Data Extraction Options:"
    echo "1. SMS Messages"
    echo "2. Call Logs"
    echo "3. Wi-Fi Passwords"
    read -p "Choice: " choice
    case $choice in
        1) recover_sms "$device_serial" ;;
        2) recover_call_logs "$device_serial" ;;
        3) recover_wifi_passwords "$device_serial" ;;
        *) echo "[ERROR] Invalid choice." ;;
    esac
}


recover_sms() {
    local device_serial="$1"
    local sms_db="mmssms.db"
    echo "[INFO] Attempting to pull SMS database (root required)..."
    adb -s "$device_serial" shell "su -c 'chmod 644 /data/data/com.android.providers.telephony/databases/mmssms.db'" &>/dev/null
    adb -s "$device_serial" pull "/data/data/com.android.providers.telephony/databases/mmssms.db" "$sms_db" &>/dev/null
    if [ ! -f "$sms_db" ]; then
        echo "[ERROR] Failed to pull SMS database. Root access required."
        return 1
    fi
    echo "[INFO] Extracting recent SMS messages..."
    sqlite3 "$sms_db" "SELECT address, date, body FROM sms ORDER BY date DESC LIMIT 10;" | awk -F'|' '{print "From: "$1" | Date: "$2" | Msg: "$3}'
    read -p "Keep SMS database? (y/n): " keep
    [ "$keep" != "y" ] && rm -f "$sms_db"
}


recover_call_logs() {
    local device_serial="$1"
    local call_db="contacts2.db"
    echo "[INFO] Attempting to pull call log database (root required)..."
    adb -s "$device_serial" shell "su -c 'chmod 644 /data/data/com.android.providers.contacts/databases/contacts2.db'" &>/dev/null
    adb -s "$device_serial" pull "/data/data/com.android.providers.contacts/databases/contacts2.db" "$call_db" &>/dev/null
    if [ ! -f "$call_db" ]; then
        echo "[ERROR] Failed to pull call log database. Root access required."
        return 1
    fi
    echo "[INFO] Extracting recent call logs..."
    sqlite3 "$call_db" "SELECT number, date, duration, type FROM calls ORDER BY date DESC LIMIT 10;" | awk -F'|' '{print "Number: "$1" | Date: "$2" | Duration: "$3" | Type: "$4}'
    read -p "Keep call log database? (y/n): " keep
    [ "$keep" != "y" ] && rm -f "$call_db"
}


live_analysis() {
    local device_serial="$1"
    echo "Live Analysis Options:"
    echo "1. Dump system logs"
    echo "2. List running processes"
    echo "3. List installed apps"
    read -p "Choice: " choice
    case $choice in
        1) adb -s "$device_serial" logcat -d > "system_logs_$(date +%s).txt"
           echo "[INFO] Logs saved to file."
           ;;
        2) adb -s "$device_serial" shell ps ;;
        3) adb -s "$device_serial" shell pm list packages ;;
        *) echo "[ERROR] Invalid choice." ;;
    esac
}


custom_data_extraction() {
    local device_serial="$1"
    read -p "Enter file path to pull: " file_path
    read -p "Is this a SQLite database? (y/n): " is_db
    adb -s "$device_serial" shell "su -c 'chmod 644 $file_path'" &>/dev/null
    adb -s "$device_serial" pull "$file_path" &>/dev/null
    local local_file=$(basename "$file_path")
    if [ ! -f "$local_file" ]; then
        echo "[ERROR] Failed to pull file."
        return 1
    fi
    if [ "$is_db" = "y" ]; then
        read -p "Enter SQL query: " sql_query
        sqlite3 "$local_file" "$sql_query"
    else
        echo "[INFO] File pulled: $local_file"
    fi
    read -p "Keep file? (y/n): " keep
    [ "$keep" != "y" ] && rm -f "$local_file"
}


execute_lockknife() {
    print_banner
    check_for_updates
    check_dependencies
    check_adb
    device_serial=$(select_device)
    connect_device "$device_serial"
    check_root "$device_serial"
    main_menu "$device_serial"
}


check_root() {
    local device_serial="$1"
    adb -s "$device_serial" shell "su -c 'id'" | grep -q "uid=0" || echo "[WARNING] Root not detected. Some features require root."
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    execute_lockknife
fi