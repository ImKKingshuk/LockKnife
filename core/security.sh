#!/bin/bash

# LockKnife Security Utilities Module
# Provides secure file handling, encryption, and security-related functions

# Secure file deletion
secure_delete_file() {
    local file_path="$1"

    if [[ ! -f "$file_path" ]]; then
        log "DEBUG" "File $file_path does not exist, nothing to delete."
        return 0
    fi

    log "DEBUG" "Securely deleting file: $file_path"

    # Get file size before deletion
    local file_size
    file_size=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null || echo "unknown")

    if [[ "$SECURE_DELETE" = "true" ]]; then
        if command -v shred &>/dev/null; then
            shred -uzn 3 "$file_path" 2>/dev/null
        else
            # Fallback secure deletion
            local temp_file
            temp_file=$(mktemp)
            dd if=/dev/urandom of="$temp_file" bs=1M count=1 2>/dev/null
            mv "$temp_file" "$file_path"
            rm -f "$file_path"
        fi
    else
        rm -f "$file_path"
    fi

    log_file_operation "secure delete" "$file_path" "${file_size} bytes"
    return 0
}

# Secure temporary directory creation
create_secure_temp_dir() {
    local temp_dir

    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        log "DEBUG" "Using existing temp directory: $TEMP_DIR"
        echo "$TEMP_DIR"
        return 0
    fi

    temp_dir=$(mktemp -d /tmp/lockknife.XXXXXX 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        temp_dir=$(mktemp -d "$HOME/.lockknife_temp.XXXXXX" 2>/dev/null)
        if [[ $? -ne 0 ]]; then
            log_error "Failed to create temporary directory"
            return 1
        fi
    fi

    # Secure the directory
    chmod 700 "$temp_dir"

    # Set global variable
    TEMP_DIR="$temp_dir"

    log "DEBUG" "Created secure temp directory: $temp_dir"
    echo "$temp_dir"
    return 0
}

# Secure file operations
secure_file_copy() {
    local src="$1"
    local dst="$2"

    if [[ ! -f "$src" ]]; then
        log_error "Source file does not exist: $src"
        return 1
    fi

    # Create destination directory if it doesn't exist
    local dst_dir
    dst_dir=$(dirname "$dst")
    [[ ! -d "$dst_dir" ]] && mkdir -p "$dst_dir"

    # Copy file securely
    if ! cp "$src" "$dst" 2>/dev/null; then
        log_error "Failed to copy file: $src -> $dst"
        return 1
    fi

    # Set secure permissions
    chmod 600 "$dst"

    log_file_operation "secure copy" "$src -> $dst"
    return 0
}

# Calculate file hash
calculate_file_hash() {
    local file_path="$1"
    local algorithm="${2:-sha256}"

    if [[ ! -f "$file_path" ]]; then
        log_error "File does not exist: $file_path"
        return 1
    fi

    local hash_value

    case "$algorithm" in
        "md5")
            hash_value=$(md5sum "$file_path" 2>/dev/null | awk '{print $1}')
            ;;
        "sha1")
            hash_value=$(sha1sum "$file_path" 2>/dev/null | awk '{print $1}')
            ;;
        "sha256")
            hash_value=$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}')
            ;;
        "sha512")
            hash_value=$(sha512sum "$file_path" 2>/dev/null | awk '{print $1}')
            ;;
        *)
            log_error "Unsupported hash algorithm: $algorithm"
            return 1
            ;;
    esac

    if [[ -z "$hash_value" ]]; then
        log_error "Failed to calculate $algorithm hash for $file_path"
        return 1
    fi

    echo "$hash_value"
    return 0
}

# Verify file integrity
verify_file_integrity() {
    local file_path="$1"
    local expected_hash="$2"
    local algorithm="${3:-sha256}"

    if [[ ! -f "$file_path" ]]; then
        log_error "File does not exist: $file_path"
        return 1
    fi

    local actual_hash
    actual_hash=$(calculate_file_hash "$file_path" "$algorithm")

    if [[ "$actual_hash" != "$expected_hash" ]]; then
        log_error "File integrity check failed for $file_path"
        log_error "Expected: $expected_hash"
        log_error "Actual: $actual_hash"
        return 1
    fi

    log "INFO" "File integrity verified: $file_path"
    return 0
}

# Encrypt file
encrypt_file() {
    local input_file="$1"
    local output_file="$2"
    local password="${3:-}"

    if [[ ! -f "$input_file" ]]; then
        log_error "Input file does not exist: $input_file"
        return 1
    fi

    # Use openssl for encryption
    if ! command -v openssl &>/dev/null; then
        log_error "openssl not found. Cannot encrypt file."
        return 1
    fi

    local openssl_cmd="openssl enc -aes-256-cbc -salt"

    if [[ -n "$password" ]]; then
        openssl_cmd+=" -k '$password'"
    else
        # Use interactive password
        openssl_cmd+=" -k"
    fi

    openssl_cmd+=" -in '$input_file' -out '$output_file'"

    if ! eval "$openssl_cmd" 2>/dev/null; then
        log_error "Failed to encrypt file: $input_file"
        return 1
    fi

    # Set secure permissions on encrypted file
    chmod 600 "$output_file"

    log_file_operation "encrypted" "$input_file -> $output_file"
    return 0
}

# Decrypt file
decrypt_file() {
    local input_file="$1"
    local output_file="$2"
    local password="${3:-}"

    if [[ ! -f "$input_file" ]]; then
        log_error "Input file does not exist: $input_file"
        return 1
    fi

    if ! command -v openssl &>/dev/null; then
        log_error "openssl not found. Cannot decrypt file."
        return 1
    fi

    local openssl_cmd="openssl enc -d -aes-256-cbc"

    if [[ -n "$password" ]]; then
        openssl_cmd+=" -k '$password'"
    else
        # Use interactive password
        openssl_cmd+=" -k"
    fi

    openssl_cmd+=" -in '$input_file' -out '$output_file'"

    if ! eval "$openssl_cmd" 2>/dev/null; then
        log_error "Failed to decrypt file: $input_file"
        return 1
    fi

    # Set secure permissions on decrypted file
    chmod 600 "$output_file"

    log_file_operation "decrypted" "$input_file -> $output_file"
    return 0
}

# Generate random password
generate_password() {
    local length="${1:-16}"
    local use_special="${2:-true}"

    if ! command -v openssl &>/dev/null; then
        # Fallback to /dev/urandom
        if [[ "$use_special" = "true" ]]; then
            tr -dc 'A-Za-z0-9!@#$%^&*()_+-=[]{}|;:,.<>?' < /dev/urandom 2>/dev/null | head -c "$length"
        else
            tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c "$length"
        fi
    else
        if [[ "$use_special" = "true" ]]; then
            openssl rand -base64 "$length" 2>/dev/null | tr -d "=+/" | cut -c1-"$length"
        else
            openssl rand -hex "$length" 2>/dev/null | cut -c1-"$length"
        fi
    fi
}

# Secure memory clearing (best effort)
secure_clear_memory() {
    local var_name="$1"

    if [[ -n "$var_name" ]]; then
        # Overwrite with random data
        eval "$var_name=\"$(generate_password 100)\""
        # Clear the variable
        unset "$var_name"
    fi
}

# Check if running in secure environment
check_secure_environment() {
    local issues=()

    # Check if running as root (not recommended for security)
    if [[ $EUID -eq 0 ]]; then
        issues+=("Running as root - not recommended for security")
    fi

    # Check file permissions on sensitive files
    local sensitive_files=("$0" "$CONFIG_FILE" "$LOG_FILE")
    for file in "${sensitive_files[@]}"; do
        if [[ -f "$file" && $(stat -c%a "$file" 2>/dev/null || stat -f%p "$file" 2>/dev/null | tail -c 3) -gt 600 ]]; then
            issues+=("Insecure permissions on $file")
        fi
    done

    # Check if temp directory is secure
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        local temp_perms
        temp_perms=$(stat -c%a "$TEMP_DIR" 2>/dev/null || stat -f%p "$TEMP_DIR" 2>/dev/null | tail -c 3)
        if [[ "$temp_perms" -gt 700 ]]; then
            issues+=("Insecure temp directory permissions")
        fi
    fi

    # Check if output directory is secure
    if [[ -d "$OUTPUT_DIR" ]]; then
        local output_perms
        output_perms=$(stat -c%a "$OUTPUT_DIR" 2>/dev/null || stat -f%p "$OUTPUT_DIR" 2>/dev/null | tail -c 3)
        if [[ "$output_perms" -gt 700 ]]; then
            issues+=("Insecure output directory permissions")
        fi
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        log "WARNING" "Security environment issues detected:"
        for issue in "${issues[@]}"; do
            log "WARNING" "  - $issue"
        done
        return 1
    else
        log "INFO" "Security environment check passed"
        return 0
    fi
}

# Generate security report
generate_security_report() {
    local output_file="$OUTPUT_DIR/security_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "# LockKnife Security Report"
        echo "# Generated: $(date)"
        echo ""

        echo "## Environment Security Check"
        if check_secure_environment >/dev/null 2>&1; then
            echo "✓ Environment security check passed"
        else
            echo "✗ Environment security issues found"
        fi
        echo ""

        echo "## File Security Status"
        echo "Configuration file: $([[ -f "$CONFIG_FILE" ]] && echo "Present" || echo "Not found")"
        echo "Log file location: $LOG_FILE"
        echo "Temp directory: $TEMP_DIR"
        echo "Output directory: $OUTPUT_DIR"
        echo ""

        echo "## Permissions Check"
        if [[ -f "$CONFIG_FILE" ]]; then
            local config_perms
            config_perms=$(stat -c%a "$CONFIG_FILE" 2>/dev/null || stat -f%p "$CONFIG_FILE" 2>/dev/null | tail -c 3)
            echo "Config file permissions: $config_perms ($(perms_to_text "$config_perms"))"
        fi

        if [[ -d "$TEMP_DIR" ]]; then
            local temp_perms
            temp_perms=$(stat -c%a "$TEMP_DIR" 2>/dev/null || stat -f%p "$TEMP_DIR" 2>/dev/null | tail -c 3)
            echo "Temp directory permissions: $temp_perms ($(perms_to_text "$temp_perms"))"
        fi

        if [[ -d "$OUTPUT_DIR" ]]; then
            local output_perms
            output_perms=$(stat -c%a "$OUTPUT_DIR" 2>/dev/null || stat -f%p "$OUTPUT_DIR" 2>/dev/null | tail -c 3)
            echo "Output directory permissions: $output_perms ($(perms_to_text "$output_perms"))"
        fi
        echo ""

        echo "## Security Features Status"
        echo "Secure delete: $SECURE_DELETE"
        echo "Encrypted output: $ENCRYPTED_OUTPUT"
        echo "Anonymous mode: $ANONYMOUS_MODE"
        echo ""

    } > "$output_file"

    log "INFO" "Security report generated: $output_file"
    echo "$output_file"
}

# Convert numeric permissions to text
perms_to_text() {
    local perms="$1"
    local text=""

    # Owner permissions
    [[ $((perms & 4)) -ne 0 ]] && text+="r" || text+="-"
    [[ $((perms & 2)) -ne 0 ]] && text+="w" || text+="-"
    [[ $((perms & 1)) -ne 0 ]] && text+="x" || text+="-"

    # Group permissions
    perms=$((perms >> 3))
    [[ $((perms & 4)) -ne 0 ]] && text+="r" || text+="-"
    [[ $((perms & 2)) -ne 0 ]] && text+="w" || text+="-"
    [[ $((perms & 1)) -ne 0 ]] && text+="x" || text+="-"

    # Other permissions
    perms=$((perms >> 3))
    [[ $((perms & 4)) -ne 0 ]] && text+="r" || text+="-"
    [[ $((perms & 2)) -ne 0 ]] && text+="w" || text+="-"
    [[ $((perms & 1)) -ne 0 ]] && text+="x" || text+="-"

    echo "$text"
}

# Sanitize filename for security
sanitize_filename() {
    local filename="$1"

    # Remove dangerous characters
    filename=$(echo "$filename" | sed 's/[\/:*?"<>|]/_/g')

    # Remove leading/trailing dots and spaces
    filename=$(echo "$filename" | sed 's/^[. ]*//' | sed 's/[. ]*$//')

    # Ensure it's not empty
    [[ -z "$filename" ]] && filename="unnamed_file"

    echo "$filename"
}

# Check file size limits
check_file_size_limit() {
    local file_path="$1"
    local max_size_mb="${2:-100}"  # Default 100MB

    if [[ ! -f "$file_path" ]]; then
        return 1
    fi

    local file_size_mb
    file_size_mb=$(($(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null) / 1024 / 1024))

    if [[ $file_size_mb -gt $max_size_mb ]]; then
        log "WARNING" "File size ($file_size_mb MB) exceeds limit ($max_size_mb MB): $file_path"
        return 1
    fi

    return 0
}

# Create encrypted archive
create_encrypted_archive() {
    local source_dir="$1"
    local archive_path="$2"
    local password="${3:-}"

    if [[ ! -d "$source_dir" ]]; then
        log_error "Source directory does not exist: $source_dir"
        return 1
    fi

    local temp_archive="${archive_path}.tmp"

    # Create tar archive
    if ! tar -czf "$temp_archive" -C "$source_dir" . 2>/dev/null; then
        log_error "Failed to create archive from $source_dir"
        return 1
    fi

    # Encrypt the archive
    if ! encrypt_file "$temp_archive" "$archive_path" "$password"; then
        log_error "Failed to encrypt archive"
        rm -f "$temp_archive"
        return 1
    fi

    # Clean up temp file
    secure_delete_file "$temp_archive"

    log "SUCCESS" "Encrypted archive created: $archive_path"
    return 0
}

# Extract encrypted archive
extract_encrypted_archive() {
    local archive_path="$1"
    local extract_dir="$2"
    local password="${3:-}"

    if [[ ! -f "$archive_path" ]]; then
        log_error "Archive does not exist: $archive_path"
        return 1
    fi

    [[ ! -d "$extract_dir" ]] && mkdir -p "$extract_dir"

    local temp_archive="${archive_path}.tmp"

    # Decrypt the archive
    if ! decrypt_file "$archive_path" "$temp_archive" "$password"; then
        log_error "Failed to decrypt archive"
        return 1
    fi

    # Extract the archive
    if ! tar -xzf "$temp_archive" -C "$extract_dir" 2>/dev/null; then
        log_error "Failed to extract archive"
        secure_delete_file "$temp_archive"
        return 1
    fi

    # Clean up temp file
    secure_delete_file "$temp_archive"

    log "SUCCESS" "Archive extracted to: $extract_dir"
    return 0
}
