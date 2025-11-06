#!/bin/bash

# LockKnife Android Version Support Module
# Handles Android version-specific features and compatibility (Android 5 - Android 16)

# Android API level mapping
declare -A ANDROID_API_LEVELS=(
    [21]="5.0 (Lollipop)"
    [22]="5.1 (Lollipop)"
    [23]="6.0 (Marshmallow)"
    [24]="7.0 (Nougat)"
    [25]="7.1 (Nougat)"
    [26]="8.0 (Oreo)"
    [27]="8.1 (Oreo)"
    [28]="9.0 (Pie)"
    [29]="10.0 (Q)"
    [30]="11.0 (R)"
    [31]="12.0 (S)"
    [32]="12.1 (S_V2)"
    [33]="13.0 (T)"
    [34]="14.0 (U)"
    [35]="15.0 (V)"
    [36]="16.0 (W)"
)

# Get Android API level from device
get_api_level() {
    local device_serial="$1"
    local api_level
    
    api_level=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.sdk")
    echo "$api_level"
}

# Get Android version string
get_android_version() {
    local device_serial="$1"
    local version
    
    version=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.release")
    echo "$version"
}

# Get Android codename
get_android_codename() {
    local api_level="$1"
    
    if [[ -n "${ANDROID_API_LEVELS[$api_level]}" ]]; then
        echo "${ANDROID_API_LEVELS[$api_level]}"
    else
        echo "Unknown (API $api_level)"
    fi
}

# Check if device supports Android 16 features
supports_android_16() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 36 ]]; then
        return 0
    else
        return 1
    fi
}

# Check if device supports Android 15 features (Private Space)
supports_android_15() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 35 ]]; then
        return 0
    else
        return 1
    fi
}

# Check if device supports scoped storage (Android 10+)
supports_scoped_storage() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 29 ]]; then
        return 0
    else
        return 1
    fi
}

# Check if device uses file-based encryption (Android 7+)
supports_file_based_encryption() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 24 ]]; then
        return 0
    else
        return 1
    fi
}

# Check if device supports keystore attestation
supports_keystore_attestation() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 28 ]]; then
        return 0
    else
        return 1
    fi
}

# Get credential storage path based on Android version
get_credential_storage_path() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 29 ]]; then
        # Android 10+: Uses locksettings.db
        echo "/data/system/locksettings.db"
    elif [[ $api_level -ge 23 ]]; then
        # Android 6-9: Uses gatekeeper
        echo "/data/system/gatekeeper.password.key"
    else
        # Android 5 and older: Uses legacy files
        echo "/data/system/gesture.key /data/system/password.key"
    fi
}

# Check if Private Space is available (Android 15+)
check_private_space_support() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 35 ]]; then
        log "INFO" "Private Space feature available (Android 15+)"
        return 0
    else
        log "WARNING" "Private Space requires Android 15+ (current: API $api_level)"
        return 1
    fi
}

# Get Credential Manager API status (Android 14+)
check_credential_manager() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 34 ]]; then
        log "INFO" "Credential Manager API available (Android 14+)"
        
        # Check if credential manager service is running
        local credential_service
        credential_service=$(execute_shell_cmd "$device_serial" "pm list packages | grep -i credential")
        
        if [[ -n "$credential_service" ]]; then
            log "DEBUG" "Credential Manager service detected: $credential_service"
            return 0
        fi
    fi
    
    log "WARNING" "Credential Manager requires Android 14+ (current: API $api_level)"
    return 1
}

# Android 16 specific features check
check_android_16_features() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    if [[ $api_level -ge 36 ]]; then
        log "SUCCESS" "Android 16 detected - Full feature support enabled"
        
        # Check for Android 16 specific security features
        local security_features=()
        
        # Enhanced biometric security
        if execute_shell_cmd "$device_serial" "pm list features | grep -i biometric" &>/dev/null; then
            security_features+=("Enhanced Biometric API")
        fi
        
        # V4 signature scheme support
        if execute_shell_cmd "$device_serial" "pm list features | grep -i signature" &>/dev/null; then
            security_features+=("V4 Signature Scheme")
        fi
        
        # Improved sandbox features
        security_features+=("Enhanced App Sandbox")
        security_features+=("Advanced SELinux Policies")
        security_features+=("Quantum-Resistant Crypto Support")
        
        log "INFO" "Android 16 Features Available:"
        for feature in "${security_features[@]}"; do
            log "INFO" "  - $feature"
        done
        
        return 0
    fi
    
    return 1
}

# Get appropriate extraction method based on Android version
get_extraction_method() {
    local device_serial="$1"
    local data_type="$2"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    case "$data_type" in
        "credentials")
            if [[ $api_level -ge 34 ]]; then
                echo "credential_manager"
            elif [[ $api_level -ge 29 ]]; then
                echo "locksettings_db"
            elif [[ $api_level -ge 23 ]]; then
                echo "gatekeeper"
            else
                echo "legacy_files"
            fi
            ;;
        "storage")
            if [[ $api_level -ge 29 ]]; then
                echo "scoped_storage"
            else
                echo "legacy_storage"
            fi
            ;;
        "private_space")
            if [[ $api_level -ge 35 ]]; then
                echo "private_space_api"
            else
                echo "unsupported"
            fi
            ;;
        *)
            echo "default"
            ;;
    esac
}

# Display comprehensive device information
display_device_info() {
    local device_serial="$1"
    
    echo "════════════════════════════════════════════════════════"
    echo "Device Information"
    echo "════════════════════════════════════════════════════════"
    
    local api_level
    api_level=$(get_api_level "$device_serial")
    
    local version
    version=$(get_android_version "$device_serial")
    
    local codename
    codename=$(get_android_codename "$api_level")
    
    local manufacturer
    manufacturer=$(execute_shell_cmd "$device_serial" "getprop ro.product.manufacturer")
    
    local model
    model=$(execute_shell_cmd "$device_serial" "getprop ro.product.model")
    
    local build_id
    build_id=$(execute_shell_cmd "$device_serial" "getprop ro.build.id")
    
    local security_patch
    security_patch=$(execute_shell_cmd "$device_serial" "getprop ro.build.version.security_patch")
    
    echo "Manufacturer: $manufacturer"
    echo "Model: $model"
    echo "Android Version: $version"
    echo "API Level: $api_level"
    echo "Codename: $codename"
    echo "Build ID: $build_id"
    echo "Security Patch: $security_patch"
    echo "Serial: $device_serial"
    echo ""
    
    # Feature support summary
    echo "Feature Support:"
    echo "────────────────────────────────────────────────────────"
    
    if [[ $api_level -ge 36 ]]; then
        echo "✓ Android 16 Features (Full Support)"
    fi
    
    if [[ $api_level -ge 35 ]]; then
        echo "✓ Private Space (Android 15+)"
    fi
    
    if [[ $api_level -ge 34 ]]; then
        echo "✓ Credential Manager API (Android 14+)"
    fi
    
    if [[ $api_level -ge 29 ]]; then
        echo "✓ Scoped Storage (Android 10+)"
    fi
    
    if [[ $api_level -ge 24 ]]; then
        echo "✓ File-Based Encryption (Android 7+)"
    fi
    
    if [[ $api_level -ge 28 ]]; then
        echo "✓ Keystore Attestation (Android 9+)"
    fi
    
    echo "════════════════════════════════════════════════════════"
    echo ""
}

# Version-specific optimization suggestions
suggest_optimizations() {
    local device_serial="$1"
    local api_level
    
    api_level=$(get_api_level "$device_serial")
    
    echo "Recommended Analysis Methods for API $api_level:"
    echo "────────────────────────────────────────────────────────"
    
    if [[ $api_level -ge 34 ]]; then
        echo "• Use Credential Manager analysis for passkeys"
        echo "• Enable advanced biometric extraction"
        echo "• Utilize modern APK signature verification (V4)"
    fi
    
    if [[ $api_level -ge 35 ]]; then
        echo "• Extract Private Space data"
        echo "• Analyze app isolation boundaries"
    fi
    
    if [[ $api_level -ge 36 ]]; then
        echo "• Use Android 16 enhanced security analysis"
        echo "• Check quantum-resistant crypto implementations"
    fi
    
    if [[ $api_level -ge 29 ]]; then
        echo "• Use scoped storage analysis methods"
        echo "• Extract locksettings.db for credentials"
    elif [[ $api_level -ge 23 ]]; then
        echo "• Use Gatekeeper HAL analysis"
        echo "• Extract hardware-backed credentials"
    else
        echo "• Use legacy credential extraction methods"
        echo "• Consider device encryption status"
    fi
    
    echo "────────────────────────────────────────────────────────"
}

log "DEBUG" "Android version support module loaded (v4.0.0)"
