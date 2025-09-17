#!/bin/bash

# get-current-configs.sh - Discover and report current Apache/Lucee upgrade configurations
# This script identifies all upgrade-related modifications on the current system
# for use by uninstall.sh and other management scripts.

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "${SCRIPT_DIR}/ENVIRONMENT.sh"
. "${SCRIPT_DIR}/shared-functions.sh"

# Default output format and file
OUTPUT_FORMAT="text"
OUTPUT_FILE=""
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
	case $1 in
		--format|-f)
			OUTPUT_FORMAT="$2"
			shift 2
			;;
		--output|-o)
			OUTPUT_FILE="$2"
			shift 2
			;;
		--verbose|-v)
			VERBOSE=true
			shift
			;;
		--help|-h)
			cat <<EOF
Usage: $0 [OPTIONS]

Discover and report current Apache/Lucee upgrade configurations.

OPTIONS:
    --format, -f FORMAT    Output format: json, text, or paths-only (default: text)
    --output, -o FILE      Write output to file instead of stdout
    --verbose, -v          Enable verbose output
    --help, -h             Show this help message

FORMATS:
    json        Structured JSON output for programmatic use
    text        Human-readable text report (default)
    paths-only  Simple list of file paths only

EXAMPLES:
    $0                                    # Basic text report to stdout
    $0 --format json --output config.json # JSON report to file
    $0 --format paths-only                # Just file paths for scripting

This script is used to understand the current state before uninstalling
or modifying the Lucee upgrade-in-progress system.
EOF
			exit 0
			;;
		*)
			echo "Unknown option: $1"
			echo "Use --help for usage information."
			exit 1
			;;
	esac
done

# Validate output format
case "$OUTPUT_FORMAT" in
	json|text|paths-only)
		;;
	*)
		echo "Error: Invalid output format '$OUTPUT_FORMAT'"
		echo "Valid formats: json, text, paths-only"
		exit 1
		;;
esac

# Function to log verbose messages
log_verbose() {
	if [ "$VERBOSE" = true ]; then
		echo "[VERBOSE] $*" >&2
	fi
}

# Main discovery process
main() {
	log_verbose "Starting Apache configuration discovery..."
	log_verbose "Environment: Debian=$IS_DEBIAN, cPanel=$IS_CPANEL"
	log_verbose "Lucee Root: $LUCEE_ROOT"
	log_verbose "Upgrade Dir: $UPG_DIR"
	
	# Show progress by default unless output is going to stdout and format is not text
	local show_progress="true"
	if [ -z "$OUTPUT_FILE" ] && [ "$OUTPUT_FORMAT" != "text" ]; then
		show_progress="false"
	fi
	
	# Perform the discovery
	local discovery_output
	discovery_output=$(discover_apache_configs "$OUTPUT_FORMAT" "$show_progress")
	
	if [ -n "$OUTPUT_FILE" ]; then
		log_verbose "Writing output to: $OUTPUT_FILE"
		echo "$discovery_output" > "$OUTPUT_FILE"
		echo "Configuration discovery complete. Output written to: $OUTPUT_FILE"
	else
		echo "$discovery_output"
	fi
	
	# Additional verbose information
	if [ "$VERBOSE" = true ] && [ "$OUTPUT_FORMAT" = "text" ]; then
		echo "" >&2
		echo "[VERBOSE] Additional system information:" >&2
		
		# Check for primary Apache config
		local primary_config
		if primary_config=$(find_primary_apache_config); then
			echo "[VERBOSE] Primary Apache config: $primary_config" >&2
			if has_lucee_proxy_config "$primary_config"; then
				echo "[VERBOSE] Primary config contains Lucee proxy configuration" >&2
			else
				echo "[VERBOSE] Primary config does not contain Lucee proxy configuration" >&2
			fi
		else
			echo "[VERBOSE] Could not locate primary Apache configuration file" >&2
		fi
		
		# Check upgrade flag status
		if [ -f "/var/lucee-upgrade-in-progress" ]; then
			echo "[VERBOSE] Upgrade flag file exists: /var/lucee-upgrade-in-progress" >&2
		else
			echo "[VERBOSE] Upgrade flag file not found: /var/lucee-upgrade-in-progress" >&2
		fi
	fi
}

# Run main function
main
