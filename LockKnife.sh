#!/bin/bash

function print_banner() {
    echo "******************************************"
    echo "*                LockKnife               *"
    echo "*         Android Password Tool          *"
    echo "*      ----------------------------      *"
    echo "*                        by @ImKKingshuk *"
    echo "* Github- https://github.com/ImKKingshuk *"
    echo "******************************************"
    echo
}

function recover_android_password() {
    local device_serial
    local recovery_option

    read -p "Enter your Android device serial number: " device_serial

    adb connect "$device_serial"

    devices_output=$(adb devices)
    if [[ ! $devices_output =~ $device_serial ]]; then
        echo "Failed to connect to the device with serial number: $device_serial"
        return
    fi

    echo "Select recovery option:"
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
            recover_wifi_passwords ;;
        *)
            echo "Invalid choice. Exiting."
            ;;
    esac
}

function recover_password() {
    local file_path="$1"
    local password=""
    
    while IFS= read -r -n1 byte; do
        byte_value=$(printf "%d" "'$byte")
        decrypted_byte=$((byte_value ^ 0x6A))
        password+=$(printf "\\$(printf '%03o' "$decrypted_byte")")
    done < "$file_path"

    echo "Recovered password: $password"

    rm "$file_path"
}

function recover_wifi_passwords() {
    local wifi_file="/data/misc/wifi/wpa_supplicant.conf"
    local device_serial
    local password=""

    read -p "Enter your Android device serial number: " device_serial

    adb connect "$device_serial"

    devices_output=$(adb devices)
    if [[ ! $devices_output =~ $device_serial ]]; then
        echo "Failed to connect to the device with serial number: $device_serial"
        return
    fi

    adb -s "$device_serial" pull "$wifi_file"
    
    while IFS= read -r line; do
        if [[ $line =~ psk=\"(.*)\" ]]; then
            password="${BASH_REMATCH[1]}"
            echo "Recovered Wi-Fi password: $password"
        fi
    done < "$wifi_file"

    rm "$wifi_file"
}

function execute_lockknife() {
    print_banner

    if ! command -v adb &>/dev/null; then
        echo "Error: ADB (Android Debug Bridge) not found. Please install ADB and make sure it's in your PATH."
        echo "You can download ADB from the Android SDK platform-tools. Follow the instructions for your OS:"
        echo "Windows: https://developer.android.com/studio/#command-tools"
        echo "MacOS: https://developer.android.com/studio/#downloads"
        echo "Linux: https://developer.android.com/studio/#downloads"
        exit 1
    fi

    recover_android_password
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
   
    chmod +x "$0"
 
    execute_lockknife
fi
