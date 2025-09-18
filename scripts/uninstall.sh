#!/bin/bash

# uninstall.sh - Remove Lucee upgrade-in-progress system and restore original configurations
# This script discovers and removes all upgrade-related modifications from the system

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "${SCRIPT_DIR}/ENVIRONMENT.sh"
. "${SCRIPT_DIR}/shared-functions.sh"

# Set backup timestamp for this run to keep all backups in the same directory
BACKUP_TS="$(date +%Y-%m-%d-%H%M%S)"

# Default options
PREVIEW_MODE=true
PREVIEW_PREFIX="[PREVIEW] "
VERBOSE=false
BACKUP_BEFORE_REMOVE=true
FORCE=false
INTERACTIVE=true

# Track number of items actually removed/modified
TOTAL_ITEMS_PROCESSED=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
	case $1 in
		--execute|-x)
			PREVIEW_MODE=false
			PREVIEW_PREFIX=""
			shift
			;;
		--verbose|-v)
			VERBOSE=true
			shift
			;;
		--no-backup)
			BACKUP_BEFORE_REMOVE=false
			shift
			;;
		--force|-f)
			FORCE=true
			INTERACTIVE=false
			PREVIEW_MODE=false
			PREVIEW_PREFIX=""
			shift
			;;
		--yes|-y)
			INTERACTIVE=false
			shift
			;;
		--help|-h)
			cat <<EOF
Usage: $0 [OPTIONS]

Remove Lucee upgrade-in-progress system and restore original configurations.

OPTIONS:
    --execute, -x      Execute changes immediately (default is preview mode)
    --verbose, -v      Enable verbose output
    --no-backup        Skip creating backups before removal
    --force, -f        Force removal without prompts (implies --execute)
    --yes, -y          Answer yes to all prompts (implies --execute)
    --help, -h         Show this help message

DESCRIPTION:
    This script discovers all upgrade-related configurations and removes them:
    - VirtualHost files with upgrade Include directives
    - Per-site include files
    - Upgrade HTML files (upgrade-in-progress.html)
    - Modified .htaccess files
    - Proxy configuration files
    - Legacy upgrade files
    - Upgrade flag files

    By default, shows a preview of pending changes and prompts for confirmation.
    Use --execute to skip preview. Backups are created before removal unless --no-backup is used.

EXAMPLES:
    $0                 # Preview changes, then prompt for confirmation
    $0 --execute       # Execute changes immediately with prompts
    $0 --force         # Execute changes without prompts
    $0 --verbose --yes # Execute with detailed output, no prompts

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

# Function to log verbose messages
log_verbose() {
	if [ "$VERBOSE" = true ]; then
		echo "[VERBOSE] $*" >&2
	fi
}

# Function to log actions
log_action() {
	echo "[ACTION] $*"
}

execute_or_simulate() {
	local action="$1"
	shift

	if [ "$PREVIEW_MODE" = true ]; then
		if [ "$action" = "remove_include_directive" ]; then
			local file="$1"
			local pattern="$2"
			local matching_lines
			matching_lines=$(grep "$pattern" "$file" 2>/dev/null || true)
			if [ -n "$matching_lines" ]; then
				echo "Would remove from $file:"
				echo "$matching_lines" | sed 's/^/  /'
				TOTAL_ITEMS_PROCESSED=$((TOTAL_ITEMS_PROCESSED + 1))
			else
				echo "No matching lines found in $file for pattern: $pattern"
			fi
		else
			echo "Would execute: $action $*"
		fi
	else
		log_action "$action $*"
		case "$action" in
			backup_file)
				backup_file "$1"
				;;
			remove_file)
				rm -f "$1"
				;;
			remove_dir)
				rm -rf "$1"
				;;
			restore_file)
				cp --no-preserve=all "$1" "$2"
				;;
			rename_file)
				mv "$1" "$2"
				;;
			remove_include_directive)
				local file="$1"
				local pattern="$2"
				sed_i_nopreserve "\|$pattern|d" "$file"
				;;
			apache_reload)
				apache_reload || exit 1
				;;
		esac
	fi
	case "$action" in
		remove_file|remove_dir|restore_file|rename_file)
			TOTAL_ITEMS_PROCESSED=$((TOTAL_ITEMS_PROCESSED + 1))
			;;
	esac
}

# Function to prompt user for confirmation
confirm_action() {
	local message="$1"
	
	if [ "$INTERACTIVE" = false ]; then
		return 0
	fi
	
	echo -n "$message (y/N): "
	read -r response
	echo ""  # Add newline after response
	case "$response" in
		[yY]|[yY][eE][sS])
			return 0
			;;
		*)
			return 1
			;;
	esac
}

# Helper function to restore ErrorDocument 404 in a specific .htaccess file
restore_htaccess_errordocument() {
	local htaccess_file="$1"
	
	if [ ! -f "$htaccess_file" ]; then
		return 1
	fi
	
	log_verbose "Checking .htaccess file for commented ErrorDocument: $htaccess_file"
	
	# Check if there's a commented-out ErrorDocument with our note pattern
	local htaccess_commented
	htaccess_commented=$(grep -A1 "NOTE: ErrorDocument 404.*configure-apache.sh" "$htaccess_file" 2>/dev/null | grep -E "^[[:space:]]*#[[:space:]]*ErrorDocument[[:space:]]+404[[:space:]]+" | head -1)
	
	if [ -n "$htaccess_commented" ]; then
		local htaccess_original
		htaccess_original=$(echo "$htaccess_commented" | sed -E 's/^[[:space:]]*#[[:space:]]*//')
		
		log_verbose "Found commented ErrorDocument 404 in .htaccess: $htaccess_original"
		
		if [ "$PREVIEW_MODE" = true ]; then
			echo "Would restore ErrorDocument 404 in $htaccess_file:"
			echo "  $htaccess_original"
			TOTAL_ITEMS_PROCESSED=$((TOTAL_ITEMS_PROCESSED + 1))
		else
			# Backup if requested
			if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
				backup_file "$htaccess_file"
			fi
			
			# Remove the note line
			sed -i "/NOTE: ErrorDocument 404.*configure-apache.sh/d" "$htaccess_file"
			
			# Uncomment the ErrorDocument line
			sed -i 's/^\([[:space:]]*\)#[[:space:]]*\(ErrorDocument[[:space:]]\+404.*\)/\1\2/' "$htaccess_file"
			
			# Normalize whitespace to clean up any extra blank lines
			normalize_conf_whitespace "$htaccess_file"
			
			log_action "Restored original ErrorDocument 404 to: $htaccess_file"
		fi
		return 0
	fi
	
	return 1
}

# Function to restore original ErrorDocument 404 directives by uncommenting them
restore_original_errordocument_404() {
	local vhost_file="$1"
	
	log_verbose "Searching for commented ErrorDocument 404 in: $vhost_file"
	
	# Check if there's a commented-out ErrorDocument with our note pattern
	local commented_errordoc
	commented_errordoc=$(grep -A1 "NOTE: ErrorDocument 404.*configure-apache.sh" "$vhost_file" 2>/dev/null | grep -E "^[[:space:]]*#[[:space:]]*ErrorDocument[[:space:]]+404[[:space:]]+" | head -1)
	
	if [ -n "$commented_errordoc" ]; then
		# Found a commented directive with our note pattern
		local original_errordoc
		original_errordoc=$(echo "$commented_errordoc" | sed -E 's/^[[:space:]]*#[[:space:]]*//')
		
		log_verbose "Found commented ErrorDocument 404 with note: $original_errordoc"
		
		if [ "$PREVIEW_MODE" = true ]; then
			echo "Would uncomment ErrorDocument 404 in $vhost_file:"
			echo "  $original_errordoc"
			echo "Would remove note comment from $vhost_file"
		else
			# Remove the note line
			sed -i "/NOTE: ErrorDocument 404.*configure-apache.sh/d" "$vhost_file"
			
			# Uncomment the ErrorDocument line
			sed -i 's/^\([[:space:]]*\)#[[:space:]]*\(ErrorDocument[[:space:]]\+404.*\)/\1\2/' "$vhost_file"
			
			# Normalize whitespace to clean up any extra blank lines
			normalize_conf_whitespace "$vhost_file"
			
			log_action "Restored original ErrorDocument 404 to: $vhost_file"
		fi
		return 0
	fi
	
	# Also check for .htaccess files in the site's document root
	# In cPanel environments, multiple VirtualHost blocks may be in one file
	# Check all DocumentRoot entries for corresponding .htaccess files
	
	# Find all DocumentRoot directives in the file
	local all_docroots
	all_docroots=$(grep -E "^[[:space:]]*DocumentRoot[[:space:]]+" "$vhost_file" 2>/dev/null | sed -E 's/^[[:space:]]*DocumentRoot[[:space:]]+//' | tr -d '"')
	
	if [ -n "$all_docroots" ]; then
		echo "${PREVIEW_PREFIX}Checking .htaccess files in document roots for ErrorDocument restoration..."
		while IFS= read -r docroot; do
			if [ -z "$docroot" ]; then
				continue
			fi
			
			local htaccess_file="${docroot}/.htaccess"
			if [ -f "$htaccess_file" ]; then
				if grep -q "NOTE: ErrorDocument 404.*configure-apache.sh" "$htaccess_file" 2>/dev/null; then
					echo "  ${PREVIEW_PREFIX}Found .htaccess with commented ErrorDocument: $htaccess_file"
					restore_htaccess_errordocument "$htaccess_file"
				fi
			fi
		done <<< "$all_docroots"
	fi
}

# Function to remove Include directives from VirtualHost files
remove_include_directives() {
	local vhost_file="$1"
	
	if [ ! -f "$vhost_file" ]; then
		return 0
	fi
	
	log_verbose "Checking for upgrade Include directives in: $vhost_file"
	
	# Backup if requested and not in preview mode
	if [ "$BACKUP_BEFORE_REMOVE" = true ] && [ "$PREVIEW_MODE" = false ]; then
		execute_or_simulate "backup_file" "$vhost_file"
	fi
	
	# Remove Include directives that reference upgrade-in-progress files
	local patterns=(
		"Include.*${HTTPD_LUCEE_ROOT}"
	)
	
	local modified=false
	for pattern in "${patterns[@]}"; do
		if grep -q "$pattern" "$vhost_file" 2>/dev/null; then
			execute_or_simulate "remove_include_directive" "$vhost_file" "$pattern"
			modified=true
		fi
	done
	
	if [ "$modified" = true ]; then
		if [ "$PREVIEW_MODE" = false ]; then
			log_action "Removed upgrade Include directives from: $vhost_file"
			
			# Normalize whitespace to clean up extra blank lines after actual changes
			normalize_conf_whitespace "$vhost_file"
		fi
		
		# Try to restore original ErrorDocument 404 directives by uncommenting
		# Do this in both preview and execution modes
		echo "${PREVIEW_PREFIX}Checking for commented ErrorDocument 404 directives to restore..."
		restore_original_errordocument_404 "$vhost_file"
	fi
}

# Function to process all uninstall operations
process_uninstall_operations() {
	local vhost_files="$1"
	local proxy_configs="$2"
	local upgrade_configs="$3"
	local upgrade_html_files="$4"
	local site_includes="$5"
	local modified_htaccess="$6"

	# Restore lucee-proxy.conf functionality FIRST
	if [ "$IS_DEBIAN" = true ]; then
		# For Debian/Ubuntu, ensure lucee-proxy.conf is enabled
		local lucee_proxy_conf="${CONF_AVAILABLE_DIR}/lucee-proxy.conf"
		if [ -f "$lucee_proxy_conf" ]; then
			echo "${PREVIEW_PREFIX}Ensuring lucee-proxy.conf is enabled..."
			if [ "$PREVIEW_MODE" = true ]; then
				echo "Would execute: a2enconf lucee-proxy"
			else
				if command -v a2enconf >/dev/null 2>&1; then
					a2enconf lucee-proxy >/dev/null 2>&1 || true
					log_action "Enabled lucee-proxy.conf"
				fi
			fi
		fi
	else
		# For RedHat/CentOS, restore .disabled file if it exists
		local lucee_proxy_disabled="${CONF_DIR}/lucee-proxy.conf.disabled"
		local lucee_proxy_conf="${CONF_DIR}/lucee-proxy.conf"
		
		# Check for cPanel simulation mode - look for the cpanel-specific disabled file
		local cpanel_sim_disabled="/etc/httpd/conf.d/lucee-proxy.conf.disabled-for-cpanel-sim"
		local cpanel_sim_target="/etc/httpd/conf.d/lucee-proxy.conf"
		
		if [ -f "$cpanel_sim_disabled" ]; then
			echo "${PREVIEW_PREFIX}Restoring cPanel simulation disabled lucee-proxy.conf..."
			execute_or_simulate "rename_file" "$cpanel_sim_disabled" "$cpanel_sim_target"
		elif [ -f "$lucee_proxy_disabled" ]; then
			echo "${PREVIEW_PREFIX}Restoring disabled lucee-proxy.conf..."
			execute_or_simulate "rename_file" "$lucee_proxy_disabled" "$lucee_proxy_conf"
		fi
	fi

	# Remove VirtualHost Include directives and restore commented ErrorDocument directives
	if [ -n "$vhost_files" ]; then
		echo "${PREVIEW_PREFIX}Processing VirtualHost files..."
		while IFS= read -r vhost_file; do
			if [ -n "$vhost_file" ]; then
				# Check if file has Include directives
				if grep -q "Include.*upgrade-in-progress.*lucee-detect-upgrade\.conf" "$vhost_file" 2>/dev/null; then
					echo "  ${PREVIEW_PREFIX}Removing Include directives from: $vhost_file"
					remove_include_directives "$vhost_file"
				fi
				
			fi
		done <<< "$vhost_files"
		echo ""
	fi
	

	# Remove proxy configuration files (except lucee-proxy.conf)
	if [ -n "$proxy_configs" ]; then
		echo "${PREVIEW_PREFIX}Removing upgrade-specific proxy configuration files..."
		while IFS= read -r proxy_file; do
			if [ -n "$proxy_file" ] && [ -f "$proxy_file" ]; then
				# Skip lucee-proxy.conf - it should remain for continued Lucee functionality
				if [[ "$proxy_file" == *"lucee-proxy.conf" ]]; then
					log_verbose "Preserving lucee-proxy.conf: $proxy_file"
					continue
				fi
				
				echo "  ${PREVIEW_PREFIX}Removing proxy file: $proxy_file"
				
				# Disable and remove Apache configuration (Debian/Ubuntu)
				if [ "$IS_DEBIAN" = true ]; then
					local conf_name
					conf_name=$(basename "$proxy_file" .conf)
					if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
						execute_or_simulate "backup_file" "$proxy_file"
					fi
					if [ "$PREVIEW_MODE" = true ]; then
						echo "Would execute: disable_and_remove_conf $conf_name"
					else
						disable_and_remove_conf "$conf_name"
					fi
				else
					# Non-Debian systems: just remove the file
					if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
						execute_or_simulate "backup_file" "$proxy_file"
					fi
					execute_or_simulate "remove_file" "$proxy_file"
				fi
			fi
		done <<< "$proxy_configs"
		echo ""
	fi
	
	# Remove upgrade configuration files
	if [ -n "$upgrade_configs" ]; then
		echo "${PREVIEW_PREFIX}Removing upgrade configuration files..."
		while IFS= read -r upgrade_file; do
			if [ -n "$upgrade_file" ] && [ -f "$upgrade_file" ]; then
				# Disable and remove Apache configuration (Debian/Ubuntu)
				if [ "$IS_DEBIAN" = true ]; then
					local conf_name
					conf_name=$(basename "$upgrade_file" .conf)
					if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
						execute_or_simulate "backup_file" "$upgrade_file"
					fi
					if [ "$PREVIEW_MODE" = true ]; then
						echo "Would execute: disable_and_remove_conf $conf_name"
					else
						disable_and_remove_conf "$conf_name"
					fi
				else
					# Non-Debian systems: just remove the file
					if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
						execute_or_simulate "backup_file" "$upgrade_file"
					fi
					execute_or_simulate "remove_file" "$upgrade_file"
				fi
			fi
		done <<< "$upgrade_configs"
		echo ""
	fi
	
	# Process directly discovered modified .htaccess files first
	if [ -n "$modified_htaccess" ]; then
		echo "${PREVIEW_PREFIX}Processing directly discovered modified .htaccess files..."
		local htaccess_direct_count=0
		
		while IFS= read -r htaccess_file; do
			if [ -n "$htaccess_file" ] && [ -f "$htaccess_file" ] && grep -q "NOTE: ErrorDocument 404.*configure-apache.sh" "$htaccess_file" 2>/dev/null; then
				echo "  ${PREVIEW_PREFIX}Found .htaccess with commented ErrorDocument: $htaccess_file"
				if restore_htaccess_errordocument "$htaccess_file"; then
					htaccess_direct_count=$((htaccess_direct_count + 1))
				fi
			fi
		done <<< "$modified_htaccess"
		
		if [ "$htaccess_direct_count" -gt 0 ]; then
			echo "${PREVIEW_PREFIX}Restored $htaccess_direct_count directly discovered .htaccess files"
		else
			echo "${PREVIEW_PREFIX}No directly discovered .htaccess files needed restoration"
		fi
		echo ""
	fi
	
	# Remove upgrade HTML files
	if [ -n "$upgrade_html_files" ]; then
		echo "${PREVIEW_PREFIX}Removing upgrade HTML files..."
		while IFS= read -r html_file; do
			if [ -n "$html_file" ] && [ -f "$html_file" ]; then
				if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
					execute_or_simulate "backup_file" "$html_file"
				fi
				execute_or_simulate "remove_file" "$html_file"
			fi
		done <<< "$upgrade_html_files"
		echo ""
	fi
	
	# Remove per-site include files
	if [ -n "$site_includes" ]; then
		echo "${PREVIEW_PREFIX}Removing per-site include files..."
		while IFS= read -r include_file; do
			if [ -n "$include_file" ] && [ -f "$include_file" ]; then
				if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
					execute_or_simulate "backup_file" "$include_file"
				fi
				execute_or_simulate "remove_file" "$include_file"
			fi
		done <<< "$site_includes"
		echo ""
	fi
	
	# Remove upgrade flag file
	if [ -f "/var/lucee-upgrade-in-progress" ]; then
		echo "${PREVIEW_PREFIX}Removing upgrade flag file..."
		if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
			execute_or_simulate "backup_file" "/var/lucee-upgrade-in-progress"
		fi
		execute_or_simulate "remove_file" "/var/lucee-upgrade-in-progress"
		echo ""
	fi
	
	# Remove Apache lucee-upgrade-in-progress directory
	if [ -d "${HTTPD_ROOT}/lucee-upgrade-in-progress" ]; then
		echo "${PREVIEW_PREFIX}Removing Apache lucee-upgrade-in-progress directory..."
		execute_or_simulate "remove_dir" "${HTTPD_ROOT}/lucee-upgrade-in-progress"
		echo ""
	fi
	
	# Reload Apache configuration
	if [ "$PREVIEW_MODE" = false ]; then
		echo "${PREVIEW_PREFIX}Reloading Apache configuration..."
		execute_or_simulate "apache_reload"
		echo ""
	fi
	
	echo "${PREVIEW_PREFIX}Uninstall complete. $TOTAL_ITEMS_PROCESSED items processed."
	
	if [ "$BACKUP_BEFORE_REMOVE" = true ]; then
		echo ""
		echo "${PREVIEW_PREFIX}Backups created in: ${UPG_DIR}/backups/${BACKUP_TS}"
	fi
}

# Function to find VirtualHost files with commented ErrorDocument directives
find_vhosts_with_commented_errordocs() {
	local output_files=""
	local apache_dirs=("/etc/httpd" "/etc/apache2" "/usr/local/apache/conf")
	
	# Add any additional directories from ENVIRONMENT.sh
	[ -n "$CONF_DIR" ] && apache_dirs+=("$CONF_DIR")
	
	for apache_dir in "${apache_dirs[@]}"; do
		[ -d "$apache_dir" ] || continue
		
		# Check main conf directory and conf.d
		for search_dir in "$apache_dir" "$apache_dir/conf.d" "$apache_dir/sites-available"; do
			[ -d "$search_dir" ] || continue
			
			while IFS= read -r -d '' vhost_file; do
				# Skip our own config files using the helper function
				if is_lucee_config_file "$vhost_file"; then
					continue
				fi
				
				# Check if file contains the commented ErrorDocument pattern
				if grep -q "NOTE: ErrorDocument 404 disabled/commented by" "$vhost_file" 2>/dev/null; then
					output_files="${output_files}${vhost_file}\n"
				fi
			done < <(find "$search_dir" -maxdepth 1 -type f -name "*.conf" -print0 2>/dev/null)
		done
	done
	
	# Return the list of files
	echo -e "$output_files" | sort | uniq
}

# Main uninstall function
main() {
	echo "Lucee Upgrade-in-Progress System Uninstaller"
	echo "=============================================="
	echo ""
	
	log_verbose "Environment: Debian=$IS_DEBIAN, cPanel=$IS_CPANEL"
	log_verbose "Lucee Root: $LUCEE_ROOT"
	log_verbose "Upgrade Dir: $UPG_DIR"
	
	# Check for lucee-upgrade-in-progress directory in HTTPD_ROOT
	local has_upgrade_dir=false
	if [ -d "${HTTPD_ROOT}/lucee-upgrade-in-progress" ]; then
		has_upgrade_dir=true
		log_verbose "Found lucee-upgrade-in-progress directory in ${HTTPD_ROOT}"
	fi
	
	
	# Discover current configurations
	echo "Discovering current upgrade configurations..."
	local discovery_output
	discovery_output=$(discover_apache_configs "json" "false")
	
	# Also find VirtualHost files with commented ErrorDocument directives
	local commented_vhosts
	commented_vhosts=$(find_vhosts_with_commented_errordocs)
	
	if [ -z "$discovery_output" ] && [ -z "$commented_vhosts" ] && [ "$has_upgrade_dir" = false ]; then
		echo "No upgrade configurations found."
		exit 0
	fi
	
	# Parse JSON output to get file lists
	local vhost_files proxy_configs upgrade_configs upgrade_html_files site_includes
	
	# Extract file arrays from JSON (handle multi-line arrays with proper whitespace matching)
	vhost_files=$(echo "$discovery_output" | sed -n '/[[:space:]]*"vhost_files": \[/,/[[:space:]]*\]/p' | grep -o '"/[^"]*"' | sed 's/"//g' | grep -v '^$')
	proxy_configs=$(echo "$discovery_output" | sed -n '/[[:space:]]*"proxy_configs": \[/,/[[:space:]]*\]/p' | grep -o '"/[^"]*"' | sed 's/"//g' | grep -v '^$')
	upgrade_configs=$(echo "$discovery_output" | sed -n '/[[:space:]]*"upgrade_configs": \[/,/[[:space:]]*\]/p' | grep -o '"/[^"]*"' | sed 's/"//g' | grep -v '^$')
	modified_htaccess=$(echo "$discovery_output" | sed -n '/[[:space:]]*"modified_htaccess": \[/,/[[:space:]]*\]/p' | grep -o '"/[^"]*"' | sed 's/"//g' | grep -v '^$')
	upgrade_html_files=$(echo "$discovery_output" | sed -n '/[[:space:]]*"upgrade_html_files": \[/,/[[:space:]]*\]/p' | grep -o '"/[^"]*"' | sed 's/"//g' | grep -v '^$')
	site_includes=$(echo "$discovery_output" | sed -n '/[[:space:]]*"site_includes": \[/,/[[:space:]]*\]/p' | grep -o '"/[^"]*"' | sed 's/"//g' | grep -v '^$')
	
	# Debug output to show what's being detected
	log_verbose "Found vhost_files: $(echo "$vhost_files" | wc -l) files"
	if [ -n "$vhost_files" ]; then
		log_verbose "VHost files: $vhost_files"
	fi
	log_verbose "Found proxy_configs: $(echo "$proxy_configs" | wc -l) files"
	if [ -n "$proxy_configs" ]; then
		log_verbose "Proxy configs: $proxy_configs"
	fi
	log_verbose "Found modified_htaccess: $(echo "$modified_htaccess" | wc -l) files"
	if [ -n "$modified_htaccess" ]; then
		log_verbose "Modified .htaccess files: $modified_htaccess"
	fi
	log_verbose "Found upgrade_configs: $(echo "$upgrade_configs" | wc -l) files"
	log_verbose "Found upgrade_html_files: $(echo "$upgrade_html_files" | wc -l) files"
	log_verbose "Found site_includes: $(echo "$site_includes" | wc -l) files"
	
	# Process VirtualHost files with commented ErrorDocument directives separately
	if [ -n "$commented_vhosts" ]; then
		echo "${PREVIEW_PREFIX}Processing VirtualHost files with commented ErrorDocument directives..."
		while IFS= read -r vhost_file; do
			if [ -n "$vhost_file" ]; then
				echo "  ${PREVIEW_PREFIX}Restoring commented ErrorDocument in: $vhost_file"
				restore_original_errordocument_404 "$vhost_file"
			fi
		done <<< "$commented_vhosts"
		echo ""
	fi
	
	# Add any VirtualHost files with commented ErrorDocument directives to the main list
	if [ -n "$commented_vhosts" ]; then
		if [ -n "$vhost_files" ]; then
			# Combine both lists and remove duplicates
			vhost_files=$(printf "%s\n%s" "$vhost_files" "$commented_vhosts" | sort | uniq | grep -v '^$')
		else
			vhost_files="$commented_vhosts"
		fi
	fi
	
	# If in preview mode, show preview and prompt for confirmation
	if [ "$PREVIEW_MODE" = true ]; then
		echo "PREVIEW OF PENDING CHANGES:"
		echo "============================"
		echo ""
		
		# Run through all operations in preview mode
		process_uninstall_operations "$vhost_files" "$proxy_configs" "$upgrade_configs" "$upgrade_html_files" "$site_includes" "$modified_htaccess"
		
		if [ "$FORCE" = false ]; then
			echo ""
			if confirm_action "Execute these changes now?"; then
				PREVIEW_MODE=false
				PREVIEW_PREFIX=""
				echo ""
				echo "EXECUTING CHANGES:"
				echo "=================="
				echo ""
				TOTAL_ITEMS_PROCESSED=0
				process_uninstall_operations "$vhost_files" "$proxy_configs" "$upgrade_configs" "$upgrade_html_files" "$site_includes" "$modified_htaccess"
			else
				echo "Uninstall cancelled."
				exit 0
			fi
		fi
	else
		# Direct execution mode
		if [ "$FORCE" = false ]; then
			if ! confirm_action "Proceed with uninstall?"; then
				echo "Uninstall cancelled."
				exit 0
			fi
			echo ""
		fi
		process_uninstall_operations "$vhost_files" "$proxy_configs" "$upgrade_configs" "$upgrade_html_files" "$site_includes" "$modified_htaccess"
	fi
}

# Run main function
main "$@"
