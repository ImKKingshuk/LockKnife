#!/bin/bash


function print_banner() {
    echo "******************************************"
    echo "*                LockKnife               *"
    echo "*    Android LockScreen Password Tool    *"
    echo "*      ----------------------------      *"
    echo "*                        by @ImKKingshuk *"
    echo "* Github- https://github.com/ImKKingshuk *"
    echo "******************************************"
    echo
}


function recover_android_password() {
   
    read -p "Enter your Android device serial number: " device_serial

   
   
    adb connect "$device_serial"

 
    devices_output=$(adb devices)
    if [[ ! $devices_output =~ $device_serial ]]; then
        echo "Failed to connect to the device with serial number: $device_serial"
        return
    fi

  
    adb -s "$device_serial" pull /data/system/gesture.key


    password=""
    while IFS= read -r -n1 byte; do
        byte_value=$(printf "%d" "'$byte")
        decrypted_byte=$((byte_value ^ 0x6A))
        password+=$(printf "\\$(printf '%03o' "$decrypted_byte")")
    done < gesture.key

    echo "Recovered password: $password"

  
    rm gesture.key
}


function execute_lockknife() {
    print_banner

  
    if ! command -v adb &>/dev/null; then
        echo "Error: ADB (Android Debug Bridge) not found. Please install ADB and make sure it's in your PATH."
        exit 1
    fi

    recover_android_password
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
   
    chmod +x "$0"
   
    execute_lockknife
fi
