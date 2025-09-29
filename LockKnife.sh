#!/bin/bash

# LockKnife : The Ultimate Android Security Research Tool
# Enhanced modular version with advanced features

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source core modules
source "$SCRIPT_DIR/core/main.sh"

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    execute_lockknife "$@"
fi
