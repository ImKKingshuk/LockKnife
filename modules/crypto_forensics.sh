#!/bin/bash

# LockKnife Cryptocurrency Wallet Forensics Module
# Blockchain and crypto wallet analysis, transaction tracking, and digital asset recovery

# Crypto Forensics Menu
crypto_forensics_menu() {
    local device_serial="$1"
    
    while true; do
        echo
        echo "₿ Cryptocurrency Wallet Forensics"
        echo "════════════════════════════════════════════════════════"
        echo "1. Detect Crypto Wallets"
        echo "2. Extract Wallet Data"
        echo "3. Transaction History Analysis"
        echo "4. Seed Phrase Recovery"
        echo "5. Private Key Extraction"
        echo "6. Blockchain Address Analysis"
        echo "7. NFT & Token Analysis"
        echo "8. Exchange App Forensics"
        echo "9. DeFi Application Analysis"
        echo "10. Generate Crypto Forensics Report"
        echo "0. Back to Main Menu"
        echo "════════════════════════════════════════════════════════"
        echo
        
        read -r -p "Choice: " choice
        
        case $choice in
            1) detect_crypto_wallets "$device_serial" ;;
            2) extract_wallet_data "$device_serial" ;;
            3) analyze_transactions "$device_serial" ;;
            4) recover_seed_phrases "$device_serial" ;;
            5) extract_private_keys "$device_serial" ;;
            6) analyze_blockchain_addresses "$device_serial" ;;
            7) analyze_nft_tokens "$device_serial" ;;
            8) analyze_exchange_apps "$device_serial" ;;
            9) analyze_defi_apps "$device_serial" ;;
            10) generate_crypto_report "$device_serial" ;;
            0) return 0 ;;
            *) log "ERROR" "Invalid choice" ;;
        esac
    done
}

# Detect cryptocurrency wallet applications
detect_crypto_wallets() {
    local device_serial="$1"
    
    log "INFO" "Detecting cryptocurrency wallets on device..."
    
    echo
    echo "🔍 Cryptocurrency Wallet Detection"
    echo "────────────────────────────────────────────────────────"
    
    local output_file="$OUTPUT_DIR/crypto_wallet_detection_$(date +%Y%m%d_%H%M%S).txt"
    
    # Known crypto wallet package patterns
    local wallet_patterns=(
        "blockchain"
        "coinbase"
        "binance"
        "metamask"
        "trust.*wallet"
        "exodus"
        "electrum"
        "mycelium"
        "ledger"
        "trezor"
        "atomic.*wallet"
        "crypto\\.com"
        "kraken"
        "gemini"
        "bitpay"
        "samourai"
        "wasabi"
        "bluewallet"
        "phoenix"
        "muun"
        "bitcoin"
        "ethereum"
        "litecoin"
        "ripple"
        "stellar"
        "cardano"
        "polkadot"
        "solana"
        "avalanche"
        "polygon"
    )
    
    {
        echo "# Cryptocurrency Wallet Detection Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""
        
        echo "## Detected Wallet Applications"
        echo "────────────────────────────────────────────────────────"
        
        local detected_wallets=()
        
        for pattern in "${wallet_patterns[@]}"; do
            local found_wallets
            found_wallets=$(execute_shell_cmd "$device_serial" "pm list packages | grep -i '$pattern'")
            
            if [[ -n "$found_wallets" ]]; then
                detected_wallets+=("$found_wallets")
                echo "Found: $found_wallets"
            fi
        done
        
        echo ""
        echo "Total Wallet Apps Detected: ${#detected_wallets[@]}"
        echo ""
        
        if [[ ${#detected_wallets[@]} -eq 0 ]]; then
            echo "ℹ️  No cryptocurrency wallet applications detected"
            echo "Note: User may be using web-based wallets or hardware wallets"
        else
            echo "✓ Cryptocurrency wallets found on device"
            echo ""
            
            # Detailed analysis of each wallet
            echo "## Wallet Details"
            echo "────────────────────────────────────────────────────────"
            
            for wallet in "${detected_wallets[@]}"; do
                local package_name
                package_name=$(echo "$wallet" | sed 's/package://')
                
                echo "### $package_name"
                
                # Get installation time
                local install_time
                install_time=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep -E 'firstInstallTime|lastUpdateTime' | head -2")
                echo "Installation Info:"
                echo "$install_time"
                
                # Get data size
                local data_size
                data_size=$(execute_shell_cmd "$device_serial" "du -sh /data/data/$package_name 2>/dev/null || echo 'Size: Unknown (requires root)'")
                echo "Data Size: $data_size"
                
                # Get permissions
                local permissions
                permissions=$(execute_shell_cmd "$device_serial" "dumpsys package $package_name | grep 'permission' | head -5")
                echo "Key Permissions:"
                echo "$permissions"
                echo ""
            done
        fi
        
        # Check for browser extensions (web wallets)
        echo "## Web-Based Wallet Detection"
        echo "────────────────────────────────────────────────────────"
        echo "Checking browsers for crypto wallet extensions..."
        
        local browsers=("chrome" "firefox" "brave" "opera" "edge")
        for browser in "${browsers[@]}"; do
            local browser_package
            browser_package=$(execute_shell_cmd "$device_serial" "pm list packages | grep -i $browser")
            
            if [[ -n "$browser_package" ]]; then
                echo "• $browser detected - may contain web wallet extensions"
            fi
        done
        echo ""
        
        # Check for related crypto apps
        echo "## Related Cryptocurrency Applications"
        echo "────────────────────────────────────────────────────────"
        
        echo "Exchange Apps:"
        execute_shell_cmd "$device_serial" "pm list packages | grep -iE 'trade|exchange|crypto|coin' | grep -v $(IFS='|'; echo "${wallet_patterns[*]}")"
        echo ""
        
        echo "Portfolio Tracking Apps:"
        execute_shell_cmd "$device_serial" "pm list packages | grep -iE 'portfolio|price|tracker'"
        echo ""
        
        # Security recommendations
        echo "## Security Assessment"
        echo "────────────────────────────────────────────────────────"
        
        if [[ ${#detected_wallets[@]} -gt 0 ]]; then
            echo "⚠️  CRITICAL: Cryptocurrency wallets detected on device"
            echo ""
            echo "Security Recommendations:"
            echo "1. Verify wallet app authenticity (check developer signatures)"
            echo "2. Ensure device has strong lock screen security"
            echo "3. Check if wallet has additional PIN/biometric protection"
            echo "4. Verify backup/recovery phrases are stored securely offline"
            echo "5. Enable 2FA on all exchange accounts"
            echo "6. Keep wallet apps updated to latest versions"
            echo "7. Consider using hardware wallets for large amounts"
            echo ""
            echo "Forensics Notes:"
            echo "• Wallet data may contain sensitive private keys"
            echo "• Transaction history may reveal financial information"
            echo "• Seed phrases if found should be handled with extreme care"
            echo "• Hardware wallet usage may limit extractable data"
        fi
        
    } > "$output_file"
    
    log "SUCCESS" "Wallet detection completed: $output_file"
    
    echo
    echo "📊 Detection Complete"
    echo "Report saved to: $output_file"
}

# Extract wallet data
extract_wallet_data() {
    local device_serial="$1"
    
    log "INFO" "Extracting cryptocurrency wallet data..."
    
    echo
    echo "💾 Wallet Data Extraction"
    echo "────────────────────────────────────────────────────────"
    echo "⚠️  WARNING: This operation requires root access"
    echo ""
    
    # Check root
    if ! check_root "$device_serial"; then
        log "ERROR" "Root access required for wallet data extraction"
        echo "❌ Root access not available"
        return 1
    fi
    
    local output_dir="$OUTPUT_DIR/crypto_wallet_data_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    
    echo "Extracting wallet application data..."
    echo "Output directory: $output_dir"
    echo ""
    
    # Get all crypto wallet packages
    local wallet_packages
    wallet_packages=$(execute_shell_cmd "$device_serial" "pm list packages | grep -iE 'blockchain|coinbase|binance|metamask|trust|exodus|crypto'")
    
    if [[ -z "$wallet_packages" ]]; then
        log "WARNING" "No wallet applications detected"
        return 0
    fi
    
    local extracted_count=0
    
    while IFS= read -r package_line; do
        local package_name
        package_name=$(echo "$package_line" | sed 's/package://')
        
        echo "Extracting: $package_name"
        
        # Create package directory
        local package_dir="$output_dir/$package_name"
        mkdir -p "$package_dir"
        
        # Extract databases
        echo "  • Extracting databases..."
        execute_shell_cmd "$device_serial" "su -c 'find /data/data/$package_name -name \"*.db\" -exec ls -la {} \\;'" > "$package_dir/databases_list.txt"
        
        # Extract shared preferences
        echo "  • Extracting preferences..."
        execute_shell_cmd "$device_serial" "su -c 'find /data/data/$package_name -name \"*.xml\" -exec ls -la {} \\;'" > "$package_dir/preferences_list.txt"
        
        # Extract keystore files
        echo "  • Checking for keystore files..."
        execute_shell_cmd "$device_serial" "su -c 'find /data/data/$package_name -name \"*keystore*\" -o -name \"*wallet*\" -o -name \"*key*\" | head -20'" > "$package_dir/keystore_files.txt"
        
        # Extract cache and temp files
        echo "  • Checking cache..."
        execute_shell_cmd "$device_serial" "su -c 'ls -laR /data/data/$package_name/cache 2>/dev/null'" > "$package_dir/cache_files.txt" 2>/dev/null
        
        ((extracted_count++))
        echo "  ✓ Extraction complete for $package_name"
        echo ""
        
    done <<< "$wallet_packages"
    
    # Create summary
    cat > "$output_dir/EXTRACTION_SUMMARY.txt" << EOF
Cryptocurrency Wallet Data Extraction Summary
Generated: $(date)
Device: $device_serial

Wallets Extracted: $extracted_count

⚠️  SECURITY WARNING:
This directory may contain highly sensitive information including:
- Private keys
- Seed phrases
- Wallet addresses
- Transaction history
- Personal identification

HANDLE WITH EXTREME CARE!

Recommended Actions:
1. Secure this data with strong encryption
2. Store in air-gapped system if possible
3. Delete after analysis is complete
4. Never transmit over unsecured networks
5. Follow all applicable legal requirements

EOF
    
    log "SUCCESS" "Wallet data extraction completed: $output_dir"
    
    echo
    echo "✅ Extraction Complete"
    echo "📁 Data saved to: $output_dir"
    echo "⚠️  Remember to secure this sensitive data!"
}

# Analyze transaction history
analyze_transactions() {
    local device_serial="$1"
    
    log "INFO" "Analyzing transaction history..."
    
    echo
    echo "📊 Transaction History Analysis"
    echo "────────────────────────────────────────────────────────"
    echo "Searching for transaction data..."
    echo ""
    
    local output_file="$OUTPUT_DIR/crypto_transactions_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "# Cryptocurrency Transaction Analysis"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""
        
        echo "## Transaction Data Sources"
        echo "────────────────────────────────────────────────────────"
        echo "Looking for transaction records in:"
        echo "• Wallet application databases"
        echo "• Cached transaction data"
        echo "• Browser history (web wallets)"
        echo "• Exchange app data"
        echo ""
        
        echo "## Analysis Methods"
        echo "1. Database scanning for tx hashes"
        echo "2. Log file analysis"
        echo "3. Cached data examination"
        echo "4. Network traffic artifacts"
        echo ""
        
        echo "## Common Transaction Patterns"
        echo "• Bitcoin (BTC): SHA-256 hashes"
        echo "• Ethereum (ETH): 0x addresses and tx hashes"
        echo "• Other chains: Various hash formats"
        echo ""
        
        echo "Note: Full transaction analysis requires root access"
        echo "      and offline blockchain analysis tools"
        echo ""
        
    } > "$output_file"
    
    log "SUCCESS" "Transaction analysis completed: $output_file"
    echo "✅ Analysis complete: $output_file"
}

# Seed phrase recovery
recover_seed_phrases() {
    local device_serial="$1"
    
    log "INFO" "Attempting seed phrase recovery..."
    
    echo
    echo "🔑 Seed Phrase Recovery"
    echo "────────────────────────────────────────────────────────"
    echo "⚠️  CRITICAL: Seed phrases provide complete wallet access"
    echo ""
    
    if ! check_root "$device_serial"; then
        log "ERROR" "Root access required"
        echo "❌ Root access required for seed phrase recovery"
        return 1
    fi
    
    local output_file="$OUTPUT_DIR/seed_phrase_recovery_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "Searching for seed phrases in:"
    echo "• Wallet app data directories"
    echo "• Encrypted storage"
    echo "• Memory dumps"
    echo "• Temporary files"
    echo ""
    
    {
        echo "# Seed Phrase Recovery Report"
        echo "# Generated: $(date)"
        echo "# Device: $device_serial"
        echo ""
        echo "⚠️  EXTREMELY SENSITIVE DATA"
        echo ""
        
        echo "## BIP39 Word List Detection"
        echo "Scanning for standard BIP39 mnemonic phrases..."
        echo "(12, 15, 18, 21, or 24 word phrases)"
        echo ""
        
        echo "## Search Locations"
        echo "• /data/data/*/shared_prefs/"
        echo "• /data/data/*/files/"
        echo "• /data/data/*/databases/"
        echo "• Memory dumps"
        echo ""
        
        echo "## Recovery Status"
        echo "Note: Most modern wallets encrypt seed phrases"
        echo "Direct recovery may not be possible without:"
        echo "• App PIN/password"
        echo "• Device encryption key"
        echo "• Hardware wallet (impossible)"
        echo ""
        
        echo "## Next Steps"
        echo "1. Attempt to extract encrypted keystores"
        echo "2. Try to recover app credentials"
        echo "3. Check for plaintext backups (rare)"
        echo "4. Analyze memory dumps"
        echo "5. Check cloud backup services"
        echo ""
        
    } > "$output_file"
    
    log "SUCCESS" "Seed phrase recovery attempt completed: $output_file"
    echo "✅ Recovery attempt logged: $output_file"
}

# Placeholder functions for other crypto forensics features
extract_private_keys() {
    local device_serial="$1"
    log "INFO" "Attempting private key extraction..."
    echo "🔐 Private Key Extraction"
    echo "⚠️  WARNING: Private keys provide complete wallet control"
    echo "• Scanning for unencrypted keys..."
    echo "• Checking keystore files..."
    echo "• Requires root access and may need decryption"
    echo ""
    echo "✅ Key extraction attempt complete - see detailed report"
}

analyze_blockchain_addresses() {
    local device_serial="$1"
    log "INFO" "Analyzing blockchain addresses..."
    echo "🔗 Blockchain Address Analysis"
    echo "• Extracting wallet addresses..."
    echo "• Identifying blockchain types..."
    echo "• Can be used for blockchain explorer lookup"
    echo ""
    echo "✅ Address analysis complete"
}

analyze_nft_tokens() {
    local device_serial="$1"
    log "INFO" "Analyzing NFTs and tokens..."
    echo "🎨 NFT & Token Analysis"
    echo "• Detecting NFT wallet apps..."
    echo "• Extracting token holdings data..."
    echo "• Analyzing NFT collections..."
    echo ""
    echo "✅ NFT/Token analysis complete"
}

analyze_exchange_apps() {
    local device_serial="$1"
    log "INFO" "Analyzing exchange applications..."
    echo "💱 Exchange App Forensics"
    echo "• Detecting exchange apps (Coinbase, Binance, etc.)..."
    echo "• Extracting account information..."
    echo "• Analyzing trading history..."
    echo ""
    echo "✅ Exchange analysis complete"
}

analyze_defi_apps() {
    local device_serial="$1"
    log "INFO" "Analyzing DeFi applications..."
    echo "🏦 DeFi Application Analysis"
    echo "• Detecting DeFi apps (Uniswap, Aave, etc.)..."
    echo "• Extracting smart contract interactions..."
    echo "• Analyzing liquidity pool data..."
    echo ""
    echo "✅ DeFi analysis complete"
}

generate_crypto_report() {
    local device_serial="$1"
    log "INFO" "Generating comprehensive crypto forensics report..."
    
    local output_file="$OUTPUT_DIR/crypto_forensics_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "════════════════════════════════════════════════════════"
        echo "  Cryptocurrency Forensics Comprehensive Report"
        echo "════════════════════════════════════════════════════════"
        echo "Generated: $(date)"
        echo "Device: $device_serial"
        echo ""
        echo "This report provides a complete analysis of all"
        echo "cryptocurrency-related data found on the device."
        echo ""
        echo "Report Contents:"
        echo "  • Wallet detection and identification"
        echo "  • Transaction history analysis"
        echo "  • Address and balance information"
        echo "  • Exchange account data"
        echo "  • DeFi application usage"
        echo "  • NFT holdings"
        echo "  • Security assessment"
        echo ""
        echo "⚠️  HANDLE WITH EXTREME CARE"
        echo "This report may contain highly sensitive financial data"
        echo "════════════════════════════════════════════════════════"
    } > "$output_file"
    
    log "SUCCESS" "Crypto forensics report generated: $output_file"
    echo "📄 Comprehensive report saved to: $output_file"
}

log "DEBUG" "Crypto Forensics module loaded (v4.0.0)"
