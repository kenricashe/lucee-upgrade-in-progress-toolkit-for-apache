#!/bin/bash

# Detect Apache configuration directories and main config file
if [ -d /etc/apache2/conf ]; then
	APACHE_CONF_DIR="/etc/apache2/conf"
	if [ -f "${APACHE_CONF_DIR}/httpd.conf" ]; then
		APACHE_CONF_FILE="${APACHE_CONF_DIR}/httpd.conf"
	elif [ -f "${APACHE_CONF_DIR}/apache2.conf" ]; then
		APACHE_CONF_FILE="${APACHE_CONF_DIR}/apache2.conf"
	else
		APACHE_CONF_FILE=""
	fi
elif [ -d /etc/httpd/conf ]; then
	APACHE_CONF_DIR="/etc/httpd/conf"
	APACHE_CONF_FILE="${APACHE_CONF_DIR}/httpd.conf"
elif [ -d /usr/local/apache2/conf ]; then
	APACHE_CONF_DIR="/usr/local/apache2/conf"
	APACHE_CONF_FILE="${APACHE_CONF_DIR}/httpd.conf"
else
	APACHE_CONF_DIR=""
	APACHE_CONF_FILE=""
fi

# Ensure the site exclusions file exists with sensible defaults.
ensure_default_exclusions_file() {
	if [ ! -f "$EXCLUSIONS_FILE" ] || [ ! -s "$EXCLUSIONS_FILE" ]; then
		mkdir -p "$(dirname "$EXCLUSIONS_FILE")" 2>/dev/null || true
		tee "$EXCLUSIONS_FILE" >/dev/null <<'EOF'
# Lucee site search exclusions
#
# Domain patterns:
#   exact domains: example.com
#   wildcard domains: *.example.com
#   subdomain wildcards:
#     bounce.*
#     www.bounce.*
# Path exclusions:
#   path: /var/www/html/some-static-site

# Commonly excluded subdomains (cPanel, etc)
localhost
cpanel.*
whm.*
webmail.*
webdisk.*
mail.*
default.*
_wildcard_.*

# cPanel and control panel vhosts
proxy-subdomains-vhost

# Path exclusions (examples)
# path: /var/www/html/default
EOF
	fi
}

# Helper functions for handling newlines in different file creation scenarios

# Backup helper: mirror source path under ${BACKUP_ROOT}/${BACKUP_TS}
# Usage: backup_file /path/to/file
backup_file() {
	local src="$1"
	[ -f "$src" ] || return 0
	
	# Set backup variables if not already set
	: ${BACKUP_ROOT:="${UPG_DIR}/backups"}
	: ${BACKUP_TS:="$(date +%Y-%m-%d-%H%M%S)"}
	
	# Skip backing up files that are already in backup directories to prevent recursion
	# Also skip if the source path would create a backup inside itself
	if [[ "$src" == *"/backups/"* ]] || [[ "$src" == "$BACKUP_ROOT"* ]]; then
		return 0
	fi
	
	local dest="${BACKUP_ROOT}/${BACKUP_TS}${src}"
	
	# Skip if backup already exists for this timestamp
	[ -f "$dest" ] && return 0
	
	local dest_dir
	dest_dir=$(dirname "$dest")
	mkdir -p "$dest_dir"
	cp -f "$src" "$dest"
	
	# Return success if backup was created
	[ -f "$dest" ]
}

backup_folder() {
	local src="$1"
	[ -d "$src" ] || return 0
	
	# Set backup variables if not already set
	: ${BACKUP_ROOT:="${UPG_DIR}/backups"}
	: ${BACKUP_TS:="$(date +%Y-%m-%d-%H%M%S)"}
	
	# Skip backing up directories that are already in backup directories to prevent recursion
	# Also skip if the source path would create a backup inside itself
	if [[ "$src" == *"/backups/"* ]] || [[ "$src" == "$BACKUP_ROOT"* ]]; then
		return 0
	fi
	
	local dest_dir
	dest_dir="${BACKUP_ROOT}/${BACKUP_TS}${src}"
	mkdir -p "$dest_dir"
	
	# Copy contents of source directory to destination
	cp -rf "$src/"* "$dest_dir/" 2>/dev/null || true
	
	# Return success if backup was created
	[ -d "$dest_dir" ]
}

# Helper function to strip all trailing newlines from a string
# Returns the cleaned string via echo
strip_trailing_newlines() {
	local content="$1"
	
	# Remove all trailing newlines
	while [ -n "$content" ] && [ "${content: -1}" = $'\n' ]; do
		content="${content%$'\n'}"
	done
	
	echo "$content"
}

# Write content to a file with exactly one newline at EOF
write_with_single_newline() {
	local content="$1"
	local file="$2"
	
	# Strip trailing newlines and add exactly one
	content=$(strip_trailing_newlines "$content")
	printf "%s\n" "$content" > "$file"
}

# Append content to a file with exactly one newline
append_with_single_newline() {
	local content="$1"
	local file="$2"
	
	# Strip trailing newlines and add exactly one
	content=$(strip_trailing_newlines "$content")
	printf "%s\n" "$content" >> "$file"
}

# Function to normalize whitespace in any configuration file
normalize_conf_whitespace() {
	local conf_file="$1"
	[ -f "$conf_file" ] || return 1
	
	# SAFETY CHECK: Make a backup first
	backup_file "$conf_file"
	
	local tmp
	tmp=$(mktemp)
	
	# Use cat to ensure we don't lose content
	cat "$conf_file" > "$tmp"
	
	# Trim trailing whitespace and normalize consecutive blank lines
	sed -i 's/[ \t]*$//' "$tmp"
	
	# Replace 2+ consecutive blank lines with 1 blank line
	awk '
	BEGIN { blank=0 }
	/^$/ { 
		blank++
		# Only print the first blank line in a sequence
		if (blank == 1) print
		next 
	}
	{
		blank = 0
		print
	}
	' "$tmp" > "${tmp}.norm"
	mv "${tmp}.norm" "$tmp"
	
	# Ensure exactly one newline at EOF (safer approach)
	if [ -s "$tmp" ] && [ "$(tail -c 1 "$tmp" | wc -l)" -eq 0 ]; then
		# No newline at end, add one
		printf "\n" >> "$tmp"
	fi
	
	# If tmp is empty, don't proceed with the change
	if [ ! -s "$tmp" ]; then
		echo "ERROR: Empty output when processing $conf_file - ABORTING CHANGE"
		# Just clean up the temp file and return error
		rm -f "$tmp"
		return 1
	fi

	# Only copy/overwrite if file doesn't exist or content changed
	if [ ! -f "$conf_file" ] || ! cmp -s "$conf_file" "$tmp"; then
		cp -f --no-preserve=all "$tmp" "$conf_file"
	fi
	rm -f "$tmp"
}

# Function to disable and remove an Apache configuration file
disable_and_remove_conf() {
	local conf_name="$1"
	local conf_path="/etc/apache2/conf-available/${conf_name}.conf"
	disable_conf "$conf_name"
	rm -f "$conf_path"
}

# Function to enable an Apache configuration file
enable_conf() {
	local conf_name="$1"
	local conf_path="/etc/apache2/conf-available/${conf_name}.conf"
	
	if [ ! -f "$conf_path" ]; then
		echo "ERROR: ${conf_name}.conf does not exist at $conf_path"
		return 1
	fi
	
	echo "Enabling ${conf_name}.conf..."
	if a2enconf "$conf_name" >/dev/null 2>&1; then
		echo "  - Successfully enabled ${conf_name}.conf"
		return 0
	else
		echo "  - Failed to enable ${conf_name}.conf"
		return 1
	fi
}

disable_conf() {
	local conf_name="$1"
	echo "Disabling ${conf_name}.conf..."
	if a2disconf "$conf_name" >/dev/null 2>&1; then
		echo "  - Successfully disabled ${conf_name}.conf"
		return 0
	else
		echo "  - ${conf_name}.conf was already disabled or not found"
		return 1
	fi
}

# ============================================================================
# Apache Configuration Discovery Functions
# ============================================================================

# Helper function to check if a file is a Lucee-specific config file
# Returns 0 (true) if the file should be skipped, 1 (false) otherwise
is_lucee_config_file() {
	local file="$1"
	
	# Skip our own config files
	[[ "$file" == *"lucee-proxy"* ]] && return 0
	[[ "$file" == *"upgrade-in-progress"* ]] && return 0
	
	# Not a Lucee config file
	return 1
}

# Discover all Apache configuration files that contain Lucee upgrade-related content
# Returns: JSON-formatted data about discovered configurations
discover_apache_configs() {
	local output_format="${1:-json}"  # json, text, or paths-only
	local show_progress="${2:-false}"  # true to show progress messages
	local temp_file
	temp_file=$(mktemp)
	
	# Initialize discovery results
	local -A discovered_configs
	local -a vhost_files
	local -a proxy_configs
	local -a upgrade_configs
	local -a modified_htaccess
	local -a upgrade_html_files
	local -a site_includes
	local -a modified_primary_configs
	
	# Determine Apache configuration directories based on distribution
	local apache_dirs=()
	if [ "$IS_DEBIAN" = true ]; then
		apache_dirs=("/etc/apache2")
	elif [ "$IS_CPANEL" = true ]; then
		apache_dirs=("/etc/apache2")
	else
		apache_dirs=("/etc/httpd" "/etc/apache2")
	fi
	
	# Add any additional directories from ENVIRONMENT.sh
	[ -n "$CONF_DIR" ] && apache_dirs+=("$CONF_DIR")
	
	# Initialize associative arrays to avoid duplicates
	local -A seen_proxy
	local -A seen_upgrade
	
	# Search for configuration files
	for apache_dir in "${apache_dirs[@]}"; do
		[ -d "$apache_dir" ] || continue
		
		if [ "$show_progress" = "true" ]; then
			echo "Scanning Apache directory: $apache_dir" >&2
		fi
		
		# Find VirtualHost files with upgrade-related Include directives
		# Check primary config file first (critical for cPanel)
		local primary_config
		if primary_config=$(find_primary_apache_config); then
			if grep -q "Include.*upgrade-in-progress.*lucee-detect-upgrade\.conf" "$primary_config" 2>/dev/null; then
				vhost_files+=("$primary_config")
			fi
		fi
		
		# Check distribution-specific directories
		if [ "$IS_DEBIAN" = true ]; then
			# Debian
			vhost_dir="$apache_dir/sites-available"
			if [ -d "$vhost_dir" ]; then
				while IFS= read -r -d '' vhost_file; do
					if grep -q "Include.*upgrade-in-progress.*lucee-detect-upgrade\.conf" "$vhost_file" 2>/dev/null; then
						vhost_files+=("$vhost_file")
					fi
				done < <(find "$vhost_dir" -maxdepth 1 -type f -name "*.conf" -print0 2>/dev/null)
			fi
		else
			# RHEL/Rocky: VirtualHost files are often in conf.d
			if [ -d "$apache_dir/conf.d" ]; then
				while IFS= read -r -d '' vhost_file; do
					# Skip our own config files using the helper function
					if is_lucee_config_file "$vhost_file"; then
						continue
					fi
					
					if grep -q "Include.*upgrade-in-progress.*lucee-detect-upgrade\.conf" "$vhost_file" 2>/dev/null; then
						vhost_files+=("$vhost_file")
					fi
				done < <(find "$apache_dir/conf.d" -maxdepth 1 -type f -name "*.conf" -print0 2>/dev/null)
			fi
		fi
		
		# Follow ALL Include directives comprehensively (exclude obvious non-vhost paths)
		if [ -n "$primary_config" ] && [ -f "$primary_config" ]; then
			local -A processed_includes
			
			# Function to check if path should be excluded from vhost search
			is_non_vhost_path() {
				local path="$1"
				# Exclude obvious non-vhost paths
				[[ "$path" == */modules.d/* ]] && return 0
				[[ "$path" == */mods-*/* ]] && return 0
				[[ "$path" == */conf.modules.d/* ]] && return 0
				[[ "$path" == */security/* ]] && return 0
				[[ "$path" == */auth/* ]] && return 0
				[[ "$path" == */userdata/* ]] && return 0
				[[ "$path" == */php*/* ]] && return 0
				[[ "$path" == */python*/* ]] && return 0
				[[ "$path" == */perl*/* ]] && return 0
				[[ "$path" == */logs/* ]] && return 0
				[[ "$path" == */log/* ]] && return 0
				[[ "$path" == */status/* ]] && return 0
				[[ "$path" == *"lucee-proxy"* ]] && return 0
				[[ "$path" == *"upgrade-in-progress"* ]] && return 0
				# cPanel hook files
				[[ "$path" == */pre_main_global.conf ]] && return 0
				[[ "$path" == */pre_main_2.conf ]] && return 0
				[[ "$path" == *cloudflare* ]] && return 0
				[[ "$path" == */account_suspensions.conf ]] && return 0
				[[ "$path" == */errordocument.conf ]] && return 0
				[[ "$path" == */pre_virtualhost_global.conf ]] && return 0
				[[ "$path" == */pre_virtualhost_2.conf ]] && return 0
				[[ "$path" == */post_virtualhost_global.conf ]] && return 0
				[[ "$path" == */post_virtualhost_2.conf ]] && return 0
				# Apache module configs
				[[ "$path" == */00-suphp.conf ]] && return 0
				[[ "$path" == */*mod_evasive.conf ]] && return 0
				[[ "$path" == */autoindex.conf ]] && return 0
				[[ "$path" == */cgid.conf ]] && return 0
				[[ "$path" == */cperror.conf ]] && return 0
				[[ "$path" == */http2.conf ]] && return 0
				[[ "$path" == */lucee-mod_cfml.conf ]] && return 0
				[[ "$path" == */lucee-proxy.conf ]] && return 0
				[[ "$path" == */modsec2.conf ]] && return 0
				[[ "$path" == */php_add_handler_fix.conf ]] && return 0
				[[ "$path" == */php.conf ]] && return 0
				# SSL/TLS configs
				[[ "$path" == */ssl.conf ]] && return 0
				[[ "$path" == */ssl-params.conf ]] && return 0
				[[ "$path" == */default-ssl.conf ]] && return 0
				# Load balancer/proxy configs
				[[ "$path" == */proxy.conf ]] && return 0
				[[ "$path" == */proxy_balancer.conf ]] && return 0
				[[ "$path" == */remoteip.conf ]] && return 0
				# Security configs
				[[ "$path" == */security.conf ]] && return 0
				[[ "$path" == */headers.conf ]] && return 0
				[[ "$path" == */deflate.conf ]] && return 0
				# cPanel specific
				[[ "$path" == */bandwidth.conf ]] && return 0
				[[ "$path" == */cpanel_php_config.conf ]] && return 0
				[[ "$path" == */ea-php*.conf ]] && return 0
				[[ "$path" == */mailman.conf ]] && return 0
				[[ "$path" == */roundcube.conf ]] && return 0
				[[ "$path" == */squirrelmail.conf ]] && return 0
				# Debian/Ubuntu specific
				[[ "$path" == */charset.conf ]] && return 0
				[[ "$path" == */localized-error-pages.conf ]] && return 0
				[[ "$path" == */other-vhosts-access-log.conf ]] && return 0
				[[ "$path" == */serve-cgi-bin.conf ]] && return 0
				# General Apache
				[[ "$path" == */mime.conf ]] && return 0
				[[ "$path" == */dir.conf ]] && return 0
				[[ "$path" == */alias.conf ]] && return 0
				[[ "$path" == */negotiation.conf ]] && return 0
				return 1
			}
			
			while IFS= read -r include_line; do
				# Extract path from Include/IncludeOptional directives
				local include_path
				include_path=$(echo "$include_line" | sed -E 's/^[[:space:]]*(Include|IncludeOptional)[[:space:]]+//i' | tr -d '"')
				
				# Skip if already processed
				# +x parameter expansion prevents unbound variable errors when set -u is enabled in calling script
				[ -n "${processed_includes["$include_path"]+x}" ] && continue
				processed_includes["$include_path"]=1
				
				# If it's a directory pattern (ends with /*), check that directory
				if [[ "$include_path" == *"/*" ]]; then
					local include_dir="${include_path%/*}"
					# Skip non-vhost directories
					is_non_vhost_path "$include_dir" && continue
					
					if [ -d "$include_dir" ]; then
						while IFS= read -r -d '' include_file; do
							# Skip non-vhost files
							is_non_vhost_path "$include_file" && continue
							
							if grep -q "Include.*upgrade-in-progress.*lucee-detect-upgrade\.conf" "$include_file" 2>/dev/null; then
								vhost_files+=("$include_file")
							fi
						done < <(find "$include_dir" -maxdepth 1 -type f -name "*.conf" -print0 2>/dev/null)
					fi
				# If it's a specific file, check it directly
				elif [ -f "$include_path" ]; then
					# Skip non-vhost files
					is_non_vhost_path "$include_path" && continue
					
					if grep -q "Include.*upgrade-in-progress.*lucee-detect-upgrade\.conf" "$include_path" 2>/dev/null; then
						vhost_files+=("$include_path")
					fi
				fi
			done < <(grep -i '^[[:space:]]*Include' "$primary_config" 2>/dev/null)
		fi
		
		# Find lucee-proxy.conf files (avoid duplicates with associative array)
		while IFS= read -r -d '' proxy_file; do
			if [ -z "${seen_proxy["$proxy_file"]+x}" ]; then
				proxy_configs+=("$proxy_file")
				seen_proxy["$proxy_file"]=1
			fi
		done < <(find "$apache_dir" -type f -name "*lucee-proxy*" -print0 2>/dev/null)
		
		# Find upgrade-in-progress configuration files (exclude userdata - those are per-site includes)
		while IFS= read -r -d '' upgrade_file; do
			# Skip userdata files - they'll be categorized as per-site includes
			if [[ "$upgrade_file" != */userdata/* ]] && [ -z "${seen_upgrade["$upgrade_file"]+x}" ]; then
				upgrade_configs+=("$upgrade_file")
				seen_upgrade["$upgrade_file"]=1
			fi
		done < <(find "$apache_dir" -type f -name "*upgrade-in-progress*" -print0 2>/dev/null)
	done
	
	# Helper function to collect all document roots from Apache configs
	# (Can't just reference sites-configured.txt because sites may have been removed from that file.)
	collect_document_roots() {
		local -A seen_docroots
		local -a result_docroots
		
		# Check all Apache directories for VirtualHost files
		for apache_dir in "${apache_dirs[@]}"; do
			[ -d "$apache_dir" ] || continue
			
			# Check Debian-style sites directories
			sites_dir="$apache_dir/sites-available"
			if [ -d "$sites_dir" ]; then
				for vhost_file in "$sites_dir"/*.conf; do
					[ -f "$vhost_file" ] || continue
					local docroot
					docroot=$(grep -i '^[[:space:]]*DocumentRoot' "$vhost_file" | head -1 | awk '{print $2}' | tr -d '"')
					if [ -n "$docroot" ] && [ -z "${seen_docroots[$docroot]+x}" ]; then
						result_docroots+=("$docroot")
						seen_docroots["$docroot"]=1
					fi
				done
			fi
			
			# Check RHEL/Rocky-style conf.d files
			if [ -d "$apache_dir/conf.d" ]; then
				for vhost_file in "$apache_dir/conf.d"/*.conf; do
					[ -f "$vhost_file" ] || continue
					# Skip our own config files
					[[ "$vhost_file" == *"lucee-proxy"* ]] && continue
					[[ "$vhost_file" == *"upgrade-in-progress"* ]] && continue
					
					local docroot
					docroot=$(grep -i '^[[:space:]]*DocumentRoot' "$vhost_file" | head -1 | awk '{print $2}' | tr -d '"')
					if [ -n "$docroot" ] && [ -z "${seen_docroots[$docroot]+x}" ]; then
						result_docroots+=("$docroot")
						seen_docroots["$docroot"]=1
					fi
				done
			fi
			
			# Check main Apache config file
			if [ -f "$APACHE_CONF_FILE" ]; then
				while IFS= read -r line; do
					if [[ "$line" =~ ^[[:space:]]*DocumentRoot[[:space:]]+ ]]; then
						local docroot
						docroot=$(echo "$line" | awk '{print $2}' | tr -d '"')
						if [ -n "$docroot" ] && [ -z "${seen_docroots[$docroot]+x}" ]; then
							result_docroots+=("$docroot")
							seen_docroots["$docroot"]=1
						fi
					fi
				done < "$APACHE_CONF_FILE"
			fi
		done
		
		# Return the array
		echo "${result_docroots[@]}"
	}
	
	# Search for modified .htaccess files (containing commented ErrorDocument 404)
	if [ "$show_progress" = "true" ]; then
		echo "Checking .htaccess files in DocumentRoots..." >&2
	fi
	
	# Avoid duplicates from vhosts sharing docroot e.g. for ports 80 and 443
	local -A seen_htaccess
	
	# Get all document roots
	local -a all_docroots
	all_docroots=($(collect_document_roots))
	
	# Check each docroot for .htaccess files
	for docroot in "${all_docroots[@]}"; do
		if [ -n "$docroot" ] && [ -f "${docroot}/.htaccess" ] && [ -z "${seen_htaccess["${docroot}/.htaccess"]+x}" ]; then
			if grep -q "# NOTE: ErrorDocument 404 moved\|# ErrorDocument.*404.*\.cfm" "${docroot}/.htaccess" 2>/dev/null; then
				modified_htaccess+=("${docroot}/.htaccess")
				seen_htaccess["${docroot}/.htaccess"]=1
			fi
		fi
	done
	
	# Search for upgrade-in-progress.html files in DocumentRoots
	if [ "$show_progress" = "true" ]; then
		echo "Searching for upgrade HTML files..." >&2
	fi
	
	# Search in DocumentRoots from VirtualHost files (all distributions)
	# Look for both new and legacy HTML file names
	local html_names=("lucee-upgrade-in-progress.html" "upgrade-in-progress.html")
	# Avoid duplicates from vhosts sharing docroot e.g. for ports 80 and 443
	local -A seen_html
	
	# We already have all document roots from the helper function
	# No need to scan Apache configs again
	for docroot in "${all_docroots[@]}"; do
		if [ -n "$docroot" ]; then
			# Check for each HTML file name
			for html_name in "${html_names[@]}"; do
				if [ -f "${docroot}/${html_name}" ] && [ -z "${seen_html["${docroot}/${html_name}"]+x}" ]; then
					upgrade_html_files+=("${docroot}/${html_name}")
					seen_html["${docroot}/${html_name}"]=1
				fi
			done
		fi
	done
	
	# Search for per-site include directories and files (avoid duplicates)
	local include_dirs=()
	local -A seen_dirs
	local -A seen_site_includes
	
	# Check for files in HTTPD_LUCEE_ROOT
	if [ -n "$HTTPD_LUCEE_ROOT" ]; then
		# Main upgrade config files
		if [ -f "${HTTPD_LUCEE_ROOT}/lucee-upgrade-in-progress.conf" ]; then
			site_includes+=("${HTTPD_LUCEE_ROOT}/lucee-upgrade-in-progress.conf")
			seen_site_includes["${HTTPD_LUCEE_ROOT}/lucee-upgrade-in-progress.conf"]=1
		fi
		
		if [ -f "${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf" ]; then
			site_includes+=("${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf")
			seen_site_includes["${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf"]=1
		fi
		
		if [ -f "${HTTPD_LUCEE_ROOT}/ip-allow.conf" ]; then
			site_includes+=("${HTTPD_LUCEE_ROOT}/ip-allow.conf")
			seen_site_includes["${HTTPD_LUCEE_ROOT}/ip-allow.conf"]=1
		fi
		
		# Per-site include directory
		if [ -d "${HTTPD_LUCEE_ROOT}/site-includes-for-404" ]; then
			include_dirs+=("${HTTPD_LUCEE_ROOT}/site-includes-for-404")
			seen_dirs["${HTTPD_LUCEE_ROOT}/site-includes-for-404"]=1
		fi
		
		# Check for SITE_INCLUDES_404_DIR if different from hardcoded path
		if [ -n "$SITE_INCLUDES_404_DIR" ] && [ "$SITE_INCLUDES_404_DIR" != "${HTTPD_LUCEE_ROOT}/site-includes-for-404" ] && [ -d "$SITE_INCLUDES_404_DIR" ]; then
			include_dirs+=("$SITE_INCLUDES_404_DIR")
			seen_dirs["$SITE_INCLUDES_404_DIR"]=1
		fi
	fi
	
	for include_dir in "${include_dirs[@]}"; do
		if [ "$show_progress" = "true" ]; then
			echo "Checking per-site includes: $include_dir" >&2
		fi
		while IFS= read -r -d '' include_file; do
			if [ -z "${seen_site_includes["$include_file"]+x}" ]; then
				site_includes+=("$include_file")
				seen_site_includes["$include_file"]=1
			fi
		done < <(find "$include_dir" -type f -name "*.conf" -print0 2>/dev/null)
	done
	
	# Also find cPanel userdata files (these are per-site includes)
	for apache_dir in "${apache_dirs[@]}"; do
		[ -d "$apache_dir" ] || continue
		if [ -d "$apache_dir/conf.d/userdata" ]; then
			# Find old upgrade-in-progress files
			while IFS= read -r -d '' userdata_file; do
				if [ -z "${seen_site_includes["$userdata_file"]+x}" ]; then
					site_includes+=("$userdata_file")
					seen_site_includes["$userdata_file"]=1
				fi
			done < <(find "$apache_dir/conf.d/userdata" -name "*upgrade-in-progress*" -type f -print0 2>/dev/null)
			
			# Find new lucee.conf files created by configure-apache.sh
			while IFS= read -r -d '' lucee_conf; do
				if [ -z "${seen_site_includes["$lucee_conf"]+x}" ]; then
					site_includes+=("$lucee_conf")
					seen_site_includes["$lucee_conf"]=1
				fi
			done < <(find "$apache_dir/conf.d/userdata" -name "lucee.conf" -type f -print0 2>/dev/null)
		fi
	done
	
	# Check cPanel userdata SSL and STD paths if they exist
	if [ "$IS_CPANEL" = true ]; then
		for userdata_path in "$CPANEL_USERDATA_SSL_PATH" "$CPANEL_USERDATA_STD_PATH"; do
			if [ -n "$userdata_path" ] && [ -d "$userdata_path" ]; then
				while IFS= read -r -d '' lucee_conf; do
					if [ -z "${seen_site_includes["$lucee_conf"]+x}" ]; then
						site_includes+=("$lucee_conf")
						seen_site_includes["$lucee_conf"]=1
					fi
				done < <(find "$userdata_path" -name "lucee.conf" -type f -print0 2>/dev/null)
			fi
		done
	fi
	
	# Check primary Apache configuration files for modifications
	if [ "$show_progress" = "true" ]; then
		echo "Checking primary Apache configuration files..." >&2
	fi
	
	local primary_config
	if primary_config=$(find_primary_apache_config); then
		if has_lucee_proxy_config "$primary_config"; then
			modified_primary_configs+=("$primary_config")
		fi
	fi
	
	# Sort all arrays alphabetically
	if [ ${#vhost_files[@]} -gt 0 ]; then
		IFS=$'\n' vhost_files=($(sort <<<"${vhost_files[*]}"))
	fi
	if [ ${#proxy_configs[@]} -gt 0 ]; then
		IFS=$'\n' proxy_configs=($(sort <<<"${proxy_configs[*]}"))
	fi
	if [ ${#upgrade_configs[@]} -gt 0 ]; then
		IFS=$'\n' upgrade_configs=($(sort <<<"${upgrade_configs[*]}"))
	fi
	if [ ${#modified_htaccess[@]} -gt 0 ]; then
		IFS=$'\n' modified_htaccess=($(sort <<<"${modified_htaccess[*]}"))
	fi
	if [ ${#upgrade_html_files[@]} -gt 0 ]; then
		IFS=$'\n' upgrade_html_files=($(sort <<<"${upgrade_html_files[*]}"))
	fi
	if [ ${#site_includes[@]} -gt 0 ]; then
		IFS=$'\n' site_includes=($(sort <<<"${site_includes[*]}"))
	fi
	if [ ${#modified_primary_configs[@]} -gt 0 ]; then
		IFS=$'\n' modified_primary_configs=($(sort <<<"${modified_primary_configs[*]}"))
	fi
	
	# Generate output based on format
	case "$output_format" in
		"json")
			cat > "$temp_file" <<EOF
{
	"discovery_timestamp": "$(date -Iseconds)",
	"environment": {
		"is_debian": $IS_DEBIAN,
		"is_cpanel": $IS_CPANEL,
		"lucee_root": "$LUCEE_ROOT",
		"upgrade_dir": "$UPG_DIR"
	},
	"vhost_files": [
$(printf '		"%s"' "${vhost_files[@]}" | sed 's/$/,/' | sed '$s/,$//')
	],
	"proxy_configs": [
$(printf '		"%s"' "${proxy_configs[@]}" | sed 's/$/,/' | sed '$s/,$//')
	],
	"upgrade_configs": [
$(printf '		"%s"' "${upgrade_configs[@]}" | sed 's/$/,/' | sed '$s/,$//')
	],
	"modified_htaccess": [
$(printf '		"%s"' "${modified_htaccess[@]}" | sed 's/$/,/' | sed '$s/,$//')
	],
	"upgrade_html_files": [
$(printf '		"%s"' "${upgrade_html_files[@]}" | sed 's/$/,/' | sed '$s/,$//')
	],
	"site_includes": [
$(printf '\t\t"%s"' "${site_includes[@]}" | sed 's/$/,/' | sed '$s/,$//')
	],
	"modified_primary_configs": [
$(printf '\t\t"%s"' "${modified_primary_configs[@]}" | sed 's/$/,/' | sed '$s/,$//')
	]
}
EOF
			;;
		"text")
			{
				echo ""
				echo "======================================="
				echo "Apache Configuration Discovery Report"
				echo "Generated: $(date)"
				echo "======================================="
				echo ""
				echo "Environment:"
				echo "  Debian: $IS_DEBIAN"
				echo "  cPanel: $IS_CPANEL"
				echo "  Lucee Root: $LUCEE_ROOT"
				echo "  Upgrade Dir: $UPG_DIR"
				echo ""
				echo "Modified primary Apache configs (${#modified_primary_configs[@]}):"
				printf "  %s\n" "${modified_primary_configs[@]}"
				echo ""
				echo "VirtualHost files with upgrade modifications (${#vhost_files[@]}):"
				printf "  %s\n" "${vhost_files[@]}"
				echo ""
				echo "Lucee proxy configuration files (${#proxy_configs[@]}):"
				printf "  %s\n" "${proxy_configs[@]}"
				echo ""
				echo "Upgrade-in-progress configuration files (${#upgrade_configs[@]}):"
				printf "  %s\n" "${upgrade_configs[@]}"
				echo ""
				echo "Modified .htaccess files (${#modified_htaccess[@]}):"
				printf "  %s\n" "${modified_htaccess[@]}"
				echo ""
				echo "Upgrade HTML files (${#upgrade_html_files[@]}):"
				printf "  %s\n" "${upgrade_html_files[@]}"
				echo ""
				echo "Per-site include files (${#site_includes[@]}):"
				printf "  %s\n" "${site_includes[@]}"
			} > "$temp_file"
			;;
		"paths-only")
			{
				printf "%s\n" "${vhost_files[@]}"
				printf "%s\n" "${proxy_configs[@]}"
				printf "%s\n" "${upgrade_configs[@]}"
				printf "%s\n" "${modified_htaccess[@]}"
				printf "%s\n" "${upgrade_html_files[@]}"
				printf "%s\n" "${site_includes[@]}"
				printf "%s\n" "${modified_primary_configs[@]}"
			} > "$temp_file"
			;;
	esac
	
	cat "$temp_file"
	rm -f "$temp_file"
}

# Get detailed information about a specific VirtualHost configuration
# Usage: get_vhost_details /path/to/vhost.conf
get_vhost_details() {
	local vhost_file="$1"
	[ -f "$vhost_file" ] || return 1
	
	local temp_file
	temp_file=$(mktemp)
	
	# Extract key information from VirtualHost
	local server_name
	local server_alias
	local document_root
	local port
	local has_upgrade_blocks=false
	local has_includes=false
	
	server_name=$(grep -i '^[[:space:]]*ServerName' "$vhost_file" | head -1 | awk '{print $2}' | tr -d '"')
	server_alias=$(grep -i '^[[:space:]]*ServerAlias' "$vhost_file" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i}' | sed 's/ $//')
	document_root=$(grep -i '^[[:space:]]*DocumentRoot' "$vhost_file" | head -1 | awk '{print $2}' | tr -d '"')
	port=$(grep -oE ':[0-9]+>' "$vhost_file" | head -1 | tr -d ':>')
	
	if grep -q "LUCEE_UPGRADE_IN_PROGRESS" "$vhost_file" 2>/dev/null; then
		has_upgrade_blocks=true
	fi
	
	if grep -q "Include.*upgrade-in-progress" "$vhost_file" 2>/dev/null; then
		has_includes=true
	fi
	
	cat > "$temp_file" <<EOF
{
	"file_path": "$vhost_file",
	"server_name": "$server_name",
	"server_alias": "$server_alias",
	"document_root": "$document_root",
	"port": "${port:-80}",
	"has_upgrade_blocks": $has_upgrade_blocks,
	"has_upgrade_includes": $has_includes,
	"file_size": $(stat -c%s "$vhost_file" 2>/dev/null || echo 0),
	"last_modified": "$(stat -c%Y "$vhost_file" 2>/dev/null || echo 0)"
}
EOF
	
	cat "$temp_file"
	rm -f "$temp_file"
}

# Find the primary Apache configuration file for the current system
# Returns the path to httpd.conf, apache2.conf, etc.
find_primary_apache_config() {
	local primary_config=""
	
	if [ "$IS_DEBIAN" = true ]; then
		primary_config="/etc/apache2/apache2.conf"
	elif [ "$IS_CPANEL" = true ]; then
		# cPanel typically uses httpd.conf
		if [ -f "/etc/apache2/conf/httpd.conf" ]; then
			primary_config="/etc/apache2/conf/httpd.conf"
		elif [ -f "/usr/local/apache/conf/httpd.conf" ]; then
			primary_config="/usr/local/apache/conf/httpd.conf"
		elif [ -f "/etc/httpd/conf/httpd.conf" ]; then
			primary_config="/etc/httpd/conf/httpd.conf"
		fi
	else
		# RHEL/CentOS
		primary_config="/etc/httpd/conf/httpd.conf"
	fi
	
	# Verify the file exists
	if [ -f "$primary_config" ]; then
		echo "$primary_config"
		return 0
	else
		return 1
	fi
}

# Check if a file contains Lucee proxy configuration
# Usage: has_lucee_proxy_config /path/to/config/file
has_lucee_proxy_config() {
	local config_file="$1"
	[ -f "$config_file" ] || return 1
	
	# Look for comment marker indicating Lucee proxy config was moved
	if grep -qi '^[[:space:]]*#[[:space:]]*Lucee proxy configuration moved to' "$config_file" 2>/dev/null; then
		return 0
	else
		return 1
	fi
}

# Excecute sed -i using tmp file then cp -f --no-preserve=all and rm tmp
sed_i_nopreserve() {
	local pattern="$1"
	local file="$2"
	local tmp=$(mktemp)
	cat "$file" > "$tmp"
	sed -i "$pattern" "$tmp"
	cp -f --no-preserve=all "$tmp" "$file"
	rm -f "$tmp"
}
