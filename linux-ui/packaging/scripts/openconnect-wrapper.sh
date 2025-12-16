#!/bin/bash
# Wrapper script for openconnect that reads cookie from temp file
# This is needed because pkexec doesn't forward stdin

COOKIE_FILE="/tmp/.openconnect-cookie-$$"

# Read cookie from the file passed as first argument
if [ -f "$1" ]; then
    COOKIE_FILE="$1"
    shift
fi

# Run openconnect with cookie from file
if [ -f "$COOKIE_FILE" ]; then
    cat "$COOKIE_FILE" | /usr/sbin/openconnect "$@"
    EXIT_CODE=$?
    # Clean up cookie file
    rm -f "$COOKIE_FILE"
    exit $EXIT_CODE
else
    echo "Error: Cookie file not found: $COOKIE_FILE" >&2
    exit 1
fi
