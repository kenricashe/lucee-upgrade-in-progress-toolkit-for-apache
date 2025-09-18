#!/bin/bash

# Source environment variables and functions
SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "${SCRIPT_DIR}/ENVIRONMENT.sh"
. "${SCRIPT_DIR}/shared-functions.sh"

# preflight: check that required Apache modules are enabled
# mod_proxy, mod_setenvif, mod_headers, mod_rewrite
# Group by module; detect per environment; emit a single error per missing module

report_missing_module() {
	echo "Error: Required Apache module '$1' is not enabled. Please enable it and try again."
}

# Module check helper (return 0 if enabled, 1 if missing)
check_module() {
	DISPLAY_NAME="$1"   # e.g., mod_proxy
	DEBIAN_NAME="$2"    # e.g., proxy

	if [ "$IS_DEBIAN" = true ]; then
		# Prefer a2query when available
		if command -v a2query >/dev/null 2>&1; then
			if a2query -m "$DEBIAN_NAME" 2>/dev/null | grep -qi "enabled"; then
				return 0
			else
				return 1
			fi
		else
			# Fallback to control command module list
			if command -v apache2ctl >/dev/null 2>&1; then
				CTL=apache2ctl
			elif command -v apachectl >/dev/null 2>&1; then
				CTL=apachectl
			else
				return 1
			fi
			if "$CTL" -M 2>/dev/null | grep -q "${DEBIAN_NAME}_module"; then
				return 0
			else
				return 1
			fi
		fi
	elif [ -n "$CONF_DIR" ]; then
		# Fedora, Red Hat, AlmaLinux, Rocky Linux, etc.
		# Prefer httpd -M; fall back to apachectl -t -D DUMP_MODULES; try apachectl -M last.
		if command -v httpd >/dev/null 2>&1; then
			if httpd -M 2>/dev/null | grep -q "${DEBIAN_NAME}_module"; then
				return 0
			else
				return 1
			fi
		elif command -v apachectl >/dev/null 2>&1; then
			# Use syntax-dump which works even if apachectl does not support -M
			if apachectl -t -D DUMP_MODULES 2>/dev/null | grep -q "${DEBIAN_NAME}_module"; then
				return 0
			else
				# Try legacy -M as a last resort
				if apachectl -M 2>/dev/null | grep -q "${DEBIAN_NAME}_module"; then
					return 0
				fi
				return 1
			fi
		else
			return 1
		fi
	fi

	# Unsupported / not detected
	return 1
}

# Run checks, collect and report
HAS_ERRORS=false

if ! check_module "mod_proxy" "proxy"; then
	report_missing_module "mod_proxy"
	HAS_ERRORS=true
fi

if ! check_module "mod_setenvif" "setenvif"; then
	report_missing_module "mod_setenvif"
	HAS_ERRORS=true
fi

if ! check_module "mod_headers" "headers"; then
	report_missing_module "mod_headers"
	HAS_ERRORS=true
fi

# mod_rewrite is required for conditional proxying during upgrade for allowlisted IPs
if ! check_module "mod_rewrite" "rewrite"; then
	report_missing_module "mod_rewrite"
	HAS_ERRORS=true
fi

if [ "$HAS_ERRORS" = true ]; then
	exit 1
fi

error_if_include_not_found() {
	local file="$1"
	if [ ! -f "$file" ]; then
		echo "Error: Required include not found: $file"
		echo "Run deploy.sh, then retry."
		exit 1
	fi
}

error_if_include_not_found "${UPG_DIR}/lucee-detect-upgrade.conf"
error_if_include_not_found "${UPG_DIR}/lucee-upgrade-in-progress.html"

# cPanel mode: Check for /etc/apache2/conf/httpd.conf and use it exclusively
if [ "$IS_CPANEL" = true ]; then
	CPANEL_HTTP_CONF="/etc/apache2/conf/httpd.conf"
	if [ ! -f "$CPANEL_HTTP_CONF" ]; then
		echo "Warning: cPanel mode detected but $CPANEL_HTTP_CONF not found."
		echo "This file should contain VirtualHost configurations for cPanel sites."
		echo "Run 'cpanel-simulate.sh on' to set up proper cPanel simulation environment."
		exit 0
	fi
	
	# Check if the file contains any VirtualHost blocks
	if ! grep -q "<VirtualHost" "$CPANEL_HTTP_CONF"; then
		echo "Warning: $CPANEL_HTTP_CONF exists but contains no VirtualHost configurations."
		echo "No sites to configure for upgrade mode."
		exit 0
	fi
	
	# Always regenerate sites file in cPanel mode to ensure it reflects current cPanel configuration
	echo "cPanel mode: Extracting site information from $CPANEL_HTTP_CONF"
	if "${UPG_DIR}/get-lucee-sites.sh"; then
		echo "Successfully extracted site information for cPanel mode"
	else
		echo "Error: Failed to extract site information from cPanel configuration"
		exit 1
	fi
fi

if [ ! -f "$SITES_FILE" ]; then
	echo "Lucee sites data file not found."
	echo ""
	echo "Press Enter to get data ..."
	read -r _
	"${UPG_DIR}/get-lucee-sites.sh"
	# Re-check for generated file
	if [ ! -f "$SITES_FILE" ]; then
		echo "Error: Failed to generate sites data file. Aborting now."
		exit 1
	fi
	clear
fi

# Set backup timestamp for this run to keep all backups in the same directory
BACKUP_TS="$(date +%Y-%m-%d-%H%M%S)"

# Default options
PREVIEW_MODE=true
PREVIEW_PREFIX="Pending: "

# Use [.] instead of \. to avoid awk treating "\." as an escape in string constants
LUCEE404_REGEX='^[[:space:]]*ErrorDocument[[:space:]]+404[[:space:]]+/[^[:space:]]*[.](cfm|cfml|cfc|cfs)([^[:alnum:]_]|$)'
# Any ErrorDocument 404 (any target), for precedence checks and comment-all behavior
ANY404_REGEX='^[[:space:]]*ErrorDocument[[:space:]]+404[[:space:]]+'

# cPanel userdata paths (IS_CPANEL provided by ENVIRONMENT.sh)
if [ "$IS_CPANEL" = true ]; then
	# For cPanel, always use /etc/apache2 regardless of CONF_DIR
	CPANEL_USERDATA_SSL_PATH="/etc/apache2/conf.d/userdata/ssl/2_4"
	CPANEL_USERDATA_STD_PATH="/etc/apache2/conf.d/userdata/std/2_4"
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
	case $1 in
		--execute|-x)
			PREVIEW_MODE=false
			shift
			;;
		--help|-h)
			cat <<EOF
Usage: $0 [OPTIONS]

Configure Apache for Lucee upgrade-in-progress system.

OPTIONS:
    --execute, -x      Execute changes immediately (default is preview mode)
    --help, -h         Show this help message

DESCRIPTION:
    This script configures Apache to handle upgrade-in-progress mode:
    - Creates global configuration files
    - Adds Include directives to VirtualHost files
    - Creates per-site upgrade HTML files
    - Generates proxy configuration for allowed IPs
    - Comments out ErrorDocument 404 directives in .htaccess files

    By default, shows a preview of pending changes and prompts for confirmation.
    Use --execute to skip preview.

EXAMPLES:
    $0                 # Preview changes, then single confirmation
    $0 --execute       # Execute changes immediately (no preview)

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

# Function to execute or simulate commands
execute_or_simulate() {
	local action="$1"
	shift

	if [ "$action" = "backup_file" ] && [ ! -f "$1" ]; then
		return 0
	fi

	if [ "$PREVIEW_MODE" = true ]; then
		printf "Pending: " >&2
	fi

	case "$action" in
		create_dir)
			echo "Create Directory (if not exists): $1" >&2
			;;
		create_file)
			echo "Create File: $1" >&2
			;;
		copy_file)
			echo "Copy: $1 -> $2" >&2
			;;
		rename_file)
			echo "Rename: $1 -> $2" >&2
			;;
		delete_file)
			echo "Delete: $1" >&2
			;;
		backup_file)
			echo "Backup: $1" >&2
			;;
		enable_conf)
			echo "Enable: $1" >&2
			;;
		disable_conf)
			echo "Disable: $1" >&2
			;;
		build_ip_all_conf_from_txt)
			echo "Create File: ${HTTPD_LUCEE_ROOT}/ip-allow.conf" >&2
			;;
		apache_reload)
			echo "Apache Reload" >&2
			;;
		*)
			echo "$action $*" >&2
			;;
	esac
	if [ "$PREVIEW_MODE" = false ]; then
		# create and modify are handled by calling functions
		case "$action" in
			create_dir)
				mkdir -p "$1"
				;;
			create_file)
				;;
			copy_file)
				cp -f --no-preserve=all "$1" "$2"
				;;
			rename_file)
				mv -f "$1" "$2"
				;;
			delete_file)
				rm -f "$1"
				;;
			backup_file)
				backup_file "$1"
				;;
			enable_conf)
				enable_conf "$1"
				;;
			disable_conf)
				disable_conf "$1"
				;;
			build_ip_all_conf_from_txt)
				build_ip_all_conf_from_txt
				;;
			apache_reload)
				# apache_reload handles output of config test on error
				apache_reload || exit 1
				;;
		esac
	fi
}

# Extract the single ErrorDocument 404 line from a block (strip leading '#' and whitespace)
extract_404_line_from_block() {
	local block="$1"
	if [ -z "$block" ]; then
		return 1
	fi
	echo "$block" | awk -v IGNORECASE=1 '
		/^[\t ]*#?[\t ]*ErrorDocument[\t ]+404[\t ]+/ { line=$0 }
		END {
			if (!length(line)) exit 1
			gsub(/^\s*#\s*/, "", line)
			gsub(/^\s*/, "", line)
			print line
		}
	'
}

# Generate per-site include file with conditional ErrorDocument block
generate_site_404_include() {
	local domain="$1"
	local port="$2"
	local error_block="$3"
	
	# Create site includes directory if it doesn't exist (and either not in preview mode or it's for port 443)
	if [ ! -d "${SITE_INCLUDES_404_DIR}" ] && [ "$PREVIEW_MODE" = false ]; then
		echo -n "  "
		execute_or_simulate "create_dir" "${SITE_INCLUDES_404_DIR}"
	fi
	
	# Generate include file path
	local include_file="${SITE_INCLUDES_404_DIR}/${domain}-${port}.conf"
	
	# Create the include file with header in new location
	echo -n "  "
	execute_or_simulate "create_file" "$include_file"

	if [ "$PREVIEW_MODE" = false ]; then
		cat > "$include_file" << EOF
# Auto-generated per-site include for ${domain}:${port}
# Generated by $0 on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# This file contains conditional ErrorDocument 404 handling for upgrade mode

<IfDefine !LUCEE_UPGRADE_IN_PROGRESS>
EOF

		# Add ErrorDocument 404 line if it exists
		local error_line
		error_line=$(extract_404_line_from_block "$error_block" || true)
		if [ -n "$error_line" ]; then
			append_with_single_newline $'\t'"$error_line" "$include_file"
		fi
		
		# Add closing sections
		cat >> "$include_file" << EOF
</IfDefine>

<IfDefine LUCEE_UPGRADE_IN_PROGRESS>
	# Set flag to indicate this site has a Lucee 404 handler
	Define LUCEE_SITE_HAS_CF_404
	
	# For allowed IPs, provide the original ErrorDocument 404 handler
	<IfModule mod_setenvif.c>
		<If "%{ENV:LUCEE_UPGRADE_BYPASS} == '1'">
EOF

		# Add the original ErrorDocument for allowed IPs if it exists
		if [ -n "$error_line" ]; then
			append_with_single_newline $'\t\t\t'"$error_line" "$include_file"
		fi
		
		cat >> "$include_file" << EOF
		</If>
	</IfModule>
</IfDefine>
EOF
	fi # end non-preview block
}

# Add per-site include line to vhost if not already present
add_include_404_to_vhost() {

	local vhost_file="$1"
	local domain_match="$2"
	local port_filter="$3"
	local include_file="${SITE_INCLUDES_404_DIR}/${domain_match}-${port_filter}.conf"
	local include_line="Include ${include_file}"
	
	[ "$PREVIEW_MODE" = true ] && return 0
	
	[ -f "$vhost_file" ] || return 1
	
	# Check if this specific include is already present
	if grep -qF "Include ${include_file}" "$vhost_file"; then
		return 0
	fi
	
	# Add the include line before </VirtualHost> in the matching vhost
	local tmp
	tmp=$(mktemp)
	awk -v dom="$domain_match" -v port="$port_filter" -v inc_line="$include_line" '
		BEGIN { inblk=0; match_this=0; blk_port=""; block_inserted=0 }
		/<VirtualHost[> \t]/ { 
			inblk=1; match_this=0; blk_port=""; block_inserted=0; 
			if (match($0, /<VirtualHost[^>]*:([0-9]+)/, m)) { blk_port=m[1] } 
		}
		inblk && tolower($0) ~ /^[\t ]*server(name|alias)[\t ]+/ {
			if (dom == "") { 
				match_this=1 
			}
			else {
				low=tolower($0)
				if (match(low, /^[\t ]*server(name|alias)[\t ]+([^#\t ]+)/, m)) {
					domain_name = m[2]
					if (domain_name == tolower(dom)) { 
						match_this=1;
					}
				}
			}
		}
		{
			if ($0 ~ /<\/VirtualHost>/) {
				if (inblk && block_inserted==0 && (dom=="" || match_this) && (port=="" || blk_port==port)) {
					print "\t" inc_line
					print ""
					block_inserted=1
				}
				inblk=0; match_this=0
			}
			print $0
		}
	' "$vhost_file" > "$tmp"
	if [ $? -eq 0 ]; then
		normalize_conf_whitespace "$tmp"
		cp -f --no-preserve=all "$tmp" "$vhost_file"
		rm -f "$tmp"
		return 0
	else
		rm -f "$tmp"
		return 1
	fi
}

# Comment out ALL ErrorDocument 404 lines (any target) with an explanatory note
comment_all_404_lines() {
	local file="$1"
	[ -f "$file" ] || return 0
	
	echo "  ${PREVIEW_PREFIX}Comment out all ErrorDocument 404 lines in $file"
	
	[ "$PREVIEW_MODE" = true ] && return 0
	
	local tmp=$(mktemp)
	local base=$(basename "$file")
	if [ "$base" = ".htaccess" ]; then
		awk -v IGNORECASE=1 -v pat="$ANY404_REGEX" -v note="# NOTE: ErrorDocument 404 moved by /opt/lucee/sys/upgrade-in-progress/configure-apache.sh into Apache vhost/userdata and disabled during upgrades. See per-site Include directives." '
			{ lines[++n]=$0 }
			END {
				for (i=1;i<=n;i++) {
					if (lines[i] ~ pat) {
						print note
						if (lines[i] ~ /^[\t ]*#/) { print lines[i] }
						else { print "# " lines[i] }
					}
					else { print lines[i] }
				}
			}
		' "$file" > "$tmp"
	else
		awk -v IGNORECASE=1 -v pat="$ANY404_REGEX" -v note="# NOTE: ErrorDocument 404 disabled/commented by /opt/lucee/sys/upgrade-in-progress/configure-apache.sh (now managed via VirtualHost Include)" '
			{ lines[++n]=$0 }
			END {
				for (i=1;i<=n;i++) {
					if (lines[i] ~ pat) {
						print note
						if (lines[i] ~ /^[\t ]*#/) { print lines[i] }
						else { print "# " lines[i] }
					}
					else { print lines[i] }
				}
			}
		' "$file" > "$tmp"
	fi
	# Write back in place to preserve existing mode/ownership
	cp -f --no-preserve=all "$tmp" "$file"
	rm -f "$tmp"
}

# Ensure the lucee-detect-upgrade.conf Include line exists inside the targeted vhost (by domain and optional port).
ensure_include_detect_upgrade_in_vhost() {
	local vhost_file="$1"
	local domain_match="$2"
	local port_filter="$3"
	local tmp
	
	local include_line="Include ${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf"
	
	[ -f "$vhost_file" ] || return 1
	
	echo "  ${PREVIEW_PREFIX}Ensuring lucee-detect-upgrade.conf is included in $vhost_file" >&2
	
	# Check if the include already exists in the file
	if grep -q "${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf" "$vhost_file"; then
		echo "  ${PREVIEW_PREFIX}Include directive already exists in $vhost_file" >&2
		return 0
	fi
	
	[ "$PREVIEW_MODE" = true ] && return 0

	tmp=$(mktemp)
	awk -v dom="$domain_match" -v port="$port_filter" -v inc_line="$include_line" -v inc_path="$HTTPD_LUCEE_ROOT/lucee-detect-upgrade.conf" '
		BEGIN { inblk=0; match_this=0; blk_port=""; inserted=0; had_inc=0 }
		{ line=$0; lines[++n]=$0 }
		/<VirtualHost[> \t]/ { inblk=1; match_this=0; blk_port=""; had_inc=0; if (match($0, /<VirtualHost[^>]*:([0-9]+)/, m)) { blk_port=m[1] } }
		inblk && tolower($0) ~ /^[\t ]*server(name|alias)[\t ]+/ {
			if (dom == "") { match_this=1 }
			else {
				low=$0
				if (tolower(low) ~ /(^|[\t ])[\t ]*server(name|alias)[\t ]+([^#]*)/) {
					names=tolower(substr(low, RSTART+RLENGTH- length(substr(low, RSTART+RLENGTH))+1))
					split(names, a, /[\t ]+/)
					for (j in a) { if (a[j]==tolower(dom)) { match_this=1; break } }
				}
			}
		}
		# Detect an existing Include for this exact path inside the current vhost block
		inblk && match($0, /^[\t ]*Include(Optional)?[\t ]+([^ \t#]+)([\t #]|$)/, m) {
			if (m[2] == inc_path) { had_inc=1 }
		}
		{
			if ($0 ~ /<\/VirtualHost>/) {
				if (inblk && inserted==0 && (dom=="" || match_this) && (port=="" || blk_port==port) && had_inc==0) {
					print "\t" inc_line
					print ""
					inserted=1
				}
				inblk=0; match_this=0; had_inc=0
			}
			print $0
		}
	' "$vhost_file" > "$tmp"
	if [ $? -eq 0 ]; then
		normalize_conf_whitespace "$tmp"
		cp -f --no-preserve=all "$tmp" "$vhost_file"
		rm -f "$tmp"
		return 0
	else
		rm -f "$tmp"
		return 1
	fi
}

# Configure site includes for sites with CF 404 handlers
configure_site_includes() {
	local domain="$1"
	local port="$2"
	local conf_file="$3"
	local docroot="$4"
	local error_404_block="$5"
	local from_htaccess="$6"
	
	# Only generate per-site include file if we have a CF 404 block
	if [ -n "$error_404_block" ]; then
		# Generate the include file with the 404 block
		generate_site_404_include "$domain" "$port" "$error_404_block"
		
		# Comment out original 404s
		comment_all_404_lines "$conf_file"
		
		if [ "$from_htaccess" = "true" ]; then
			if ! grep -qi 'NOTE: ErrorDocument 404 moved' "$docroot/.htaccess"; then
				[ -f "$docroot/.htaccess" ] && echo -n "  "
				execute_or_simulate "backup_file" "$docroot/.htaccess"
				comment_all_404_lines "$docroot/.htaccess"
			else
				echo "  ${PREVIEW_PREFIX}Skipping .htaccess comment (already processed): $docroot/.htaccess"
			fi
		fi
		
		# Add per-site include to vhost
		add_include_404_to_vhost "$conf_file" "$domain" "$port"
	fi
}

# Check if a per-site include already exists for the given domain and port
has_site_include_file_for_404() {
	local domain="$1"
	local port="$2"
	local include_file="${SITE_INCLUDES_404_DIR}/${domain}-${port}.conf"
	[ -f "$include_file" ]
}

# Extract the last matching ErrorDocument 404 *.cf* even if it is commented (e.g., from prior runs)
# Strips leading '# ' from the extracted lines and excludes our NOTE lines
# Does not modify file, only returns the block.
extract_404_block_allow_commented() {
	local file="$1"
	[ -f "$file" ] || return 1
	awk -v IGNORECASE=1 -v pat="$LUCEE404_REGEX" '
		{ lines[++n]=$0 }
		# match active or commented ErrorDocument 404 *.cf*
		$0 ~ /^[\t ]*#?[\t ]*ErrorDocument[\t ]+404[\t ]+/ && $0 ~ pat { ln=n }
		END {
			if (!ln) exit 1
			start=ln-1
			while (start>=1 && (lines[start] ~ /^[\t ]*#/ || lines[start] ~ /^[\t ]*$/)) start--
			for (i=start+1; i<ln; i++) {
				if (lines[i] ~ /NOTE: ErrorDocument 404/) continue
				# strip leading comment markers
				sub(/^[\t ]*#[\t ]?/, "", lines[i])
				print lines[i]
			}
			line=lines[ln]
			sub(/^[\t ]*#[\t ]?/, "", line)
			print line
		}
	' "$file"
}

# Return 0 if the last ErrorDocument 404 in file targets .cf*, else return 1
last_404_is_cf() {
	local file="$1"
	[ -f "$file" ] || return 1
	awk -v IGNORECASE=1 '
		/^[\t ]*#/ { next }
		# capture last ErrorDocument 404 target (rest of line after the code)
		match($0, /^[\t ]*ErrorDocument[\t ]+404[\t ]+(.*)$/, m) { last=m[1] }
		END {
			if (!length(last)) exit 1
			# consider it CF only if it ends with .cfm/.cfml/.cfc/.cfs (optionally followed by non-word chars)
			if (last ~ /\.(cfm|cfml|cfc|cfs)([^[:alnum:]_]|$)/) exit 0; else exit 1
		}
	' "$file"
}

# Extract the first matching ErrorDocument 404 *.cf* line and its contiguous preceding comments
# Prints the block to stdout; returns non-zero if not found
extract_404_block() {
	local file="$1"
	[ -f "$file" ] || return 1
	awk -v IGNORECASE=1 -v pat="$LUCEE404_REGEX" '
		{ lines[++n]=$0 }
		$0 ~ pat { ln=n }
		END {
			if (!ln) exit 1
			start=ln-1
			while (start>=1 && (lines[start] ~ /^[\t ]*#/ || lines[start] ~ /^[\t ]*$/)) start--
			for (i=start+1; i<ln; i++) print lines[i]
			print lines[ln]
		}
	' "$file"
}

find_active_lucee_proxy_conf_path() {
	local path=""
	if [ "$IS_DEBIAN" = true ]; then
		path="/etc/apache2/conf-available/lucee-proxy.conf"
	elif [ -n "$CONF_DIR" ]; then
		path="${CONF_DIR}/lucee-proxy.conf"
	fi
	if [ -n "$path" ] && [ -f "$path" ]; then
		echo "$path"
		return 0
	fi
	echo ""
	return 1
}

generate_allowed_ip_proxy_include() {

	# Generates internal mapping plus rewrite-gated access for allowlisted IPs
	#
	# '/.lucee-upgrade-proxy/' is an internal URI used only as a bridge between mod_rewrite and mod_proxy.
	#
	# Apache forbids ProxyPass/ProxyPassMatch inside conditional blocks, 
	# so we always define a ProxyPassMatch for that internal path,
	# then rewrite allowed client requests to it when LUCEE_UPGRADE_BYPASS=1.
	#
	# This allows allowlisted IPs to reach Lucee normally while non-allowed
	#
	# IPs are served lucee-upgrade-in-progress.html.
	#
	# For AJP backends, we extract and propagate 'secret=...' to keep upgrade-mode proxying secure.
	
	local filename="lucee-proxy-for-allowed-ip.conf"

	if [ "$PREVIEW_MODE" = true ]; then
		execute_or_simulate "create_file" "${HTTPD_LUCEE_ROOT}/${filename}"
		return 0
	fi

	local src=$(find_active_lucee_proxy_conf_path)
	if [ -z "$src" ]; then
		echo "Error: Could not find active lucee-proxy.conf on this system."
		return 1
	fi

	local content=$(cat "$src")
	if [ -z "$content" ]; then
		echo "Error: $src is empty."
		return 1
	fi

	local dest="${HTTPD_LUCEE_ROOT}/${filename}"
	local tmp=$(mktemp)

	# Derive backend target from the active lucee-proxy.conf
	# Prefer balancer://, then ajp://, then http(s)://; fallback to http://127.0.0.1:8888
	local backend_url=""
	local backend_type=""
	local ppm_line=""
	# balancer
	if echo "$content" | grep -Eiq "^[[:space:]]*ProxyPassMatch[[:space:]].*balancer://"; then
		backend_url=$(echo "$content" | awk '/^[\t ]*ProxyPassMatch[\t ]/ { for (i=1; i<=NF; i++) if ($i ~ /^balancer:\/\//) { print $i; exit } }')
		ppm_line=$(echo "$content" | awk '/^[\t ]*ProxyPassMatch[\t ]/ { for (i=1; i<=NF; i++) if ($i ~ /^balancer:\/\//) { print $0; exit } }')
		if [ -n "$backend_url" ]; then
			backend_type="balancer"
		fi
	fi
	# ajp
	if [ -z "$backend_url" ] && echo "$content" | grep -Eiq "^[[:space:]]*ProxyPassMatch[[:space:]].*ajp://"; then
		backend_url=$(echo "$content" | awk '/^[\t ]*ProxyPassMatch[\t ]/ { for (i=1; i<=NF; i++) if ($i ~ /^ajp:\/\//) { print $i; exit } }')
		ppm_line=$(echo "$content" | awk '/^[\t ]*ProxyPassMatch[\t ]/ { for (i=1; i<=NF; i++) if ($i ~ /^ajp:\/\//) { print $0; exit } }')
		if [ -n "$backend_url" ]; then
			backend_type="ajp"
		fi
	fi
	# http/https
	if [ -z "$backend_url" ] && echo "$content" | grep -Eiq "^[[:space:]]*ProxyPassMatch[[:space:]].*https?://"; then
		backend_url=$(echo "$content" | awk '/^[\t ]*ProxyPassMatch[\t ]/ { for (i=1; i<=NF; i++) if ($i ~ /^https?:\/\//) { print $i; exit } }')
		ppm_line=$(echo "$content" | awk '/^[\t ]*ProxyPassMatch[\t ]/ { for (i=1; i<=NF; i++) if ($i ~ /^https?:\/\//) { print $0; exit } }')
		if [ -n "$backend_url" ]; then
			backend_type="http"
		fi
	fi
	# fallback
	if [ -z "$backend_url" ]; then
		backend_url="http://127.0.0.1:8888"
		backend_type="http"
	fi

	# Normalize: strip any trailing '/$1$2' (with optional trailing '/') carried over from ProxyPassMatch
	backend_url=$(echo "$backend_url" | sed -E 's#/\$1\$2/?$##')

	# Extract options that follow the backend URL in the selected ProxyPassMatch line
	# Preserve all flags and key=value pairs (e.g., nocanon, keepalive=On, secret=...)
	local ppm_opts=""
	if [ -n "$ppm_line" ]; then
		ppm_opts=$(echo "$ppm_line" | awk '
			BEGIN { idx=0 }
			{
				for (i=1; i<=NF; i++) {
					if ($i ~ /^(balancer|ajp|https?):\/\//) { idx=i; break }
				}
				if (idx>0 && idx<NF) {
					for (k=idx+1; k<=NF; k++) {
						printf " %s", $k
					}
				}
			}
		')
	fi

	# Warn if AJP secret is missing on the selected ProxyPassMatch line
	if [ "$backend_type" = "ajp" ] && ! echo "$ppm_opts" | grep -Eq '(^|[[:space:]])secret='; then
		echo "Warning: AJP backend detected but no 'secret=' option found on ProxyPassMatch line in $src."
	fi

	{
		echo "# Auto-generated by ${UPG_DIR}/configure-apache.sh"
		echo "# Source: $src"
		echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "# Conditional proxy for allowlisted IPs only"
		echo ""
		echo "# Preserve Host header for mod_cfml virtual host context mapping"
		echo "ProxyPreserveHost On"
		echo ""
		echo "# Internal upgrade proxy mapping (only reachable via RewriteRule)"
		# Use printf to correctly emit literal $1 and $2 backrefs without stray escapes
		printf 'ProxyPassMatch ^/\\.lucee-upgrade-proxy/(.+\\.(?:cfm|cfml|cfc|cfs))(.*)$ %s/$1$2%s\n' "${backend_url}" "${ppm_opts}"
		printf 'ProxyPassReverse /.lucee-upgrade-proxy/ %s/\n' "${backend_url}"
		echo "<IfModule mod_rewrite.c>"
		# Use printf (single-quoted) to avoid shell expansion of $1/$2 backrefs
		printf '\tRewriteEngine On\n'
		printf '\t# Allow Lucee access only for IPs flagged via LUCEE_UPGRADE_BYPASS\n'
		printf '\tRewriteCond %%{ENV:LUCEE_UPGRADE_BYPASS} =1\n'
		printf '\t# Pass original Host header to help mod_cfml maintain virtual host context\n'
		printf '\tRewriteRule ^/(.+\\.(?:cfm|cfml|cfc|cfs))(.*)$ /.lucee-upgrade-proxy/$1$2 [PT,QSA,L,E=ORIGINAL_HOST:%%{HTTP_HOST}]\n'
		echo "</IfModule>"
	} > "$tmp"

	if [ -f "$dest" ]; then
		if cmp -s "$tmp" "$dest"; then
			rm -f "$tmp"
			return 0
		fi
		execute_or_simulate "backup_file" "$dest"
	fi
	execute_or_simulate "create_file" "${HTTPD_LUCEE_ROOT}/${filename}"
	cp -f --no-preserve=all "$tmp" "$dest"
	rm -f "$tmp"
	return 0
}

# Detect manually delineated Lucee proxy block in Apache config
# Returns 0 if found, 1 if not found
find_manual_proxy_block() {
	local config_file="$1"
	[ -f "$config_file" ] || return 1
	awk '
		/^[[:space:]]*#[[:space:]]*begin[[:space:]]+[Ll]ucee[[:space:]]+proxy/ { start=NR; next }
		/^[[:space:]]*#[[:space:]]*end[[:space:]]+[Ll]ucee[[:space:]]+proxy/ { 
			if (start) { 
				for (i=start+1; i<NR; i++) print lines[i]
				exit 0 
			}
		}
		{ lines[NR]=$0 }
		END { exit 1 }
	' "$config_file"
}

# Extract Lucee proxy block using regex patterns (fallback method)
# Based on install_mod_proxy.sh patterns
find_regex_proxy_block() {
	local config_file="$1"
	[ -f "$config_file" ] || return 1
	
	# Extract IfModule mod_proxy.c blocks and check for ProxyPassMatch with cf
	local in_block=0
	local block_content=""
	
	while IFS= read -r line; do
		case "$line" in
			*"<IfModule"*"mod_proxy.c>"*)
				in_block=1
				block_content="$line"
				;;
			*"</IfModule>"*)
				if [ "$in_block" = "1" ]; then
					block_content="$block_content"$'\n'"$line"
					# Check if this block contains ProxyPassMatch with cf
					if echo "$block_content" | grep -q "ProxyPassMatch.*cf"; then
						# Output the block as-is with header comment
						echo "# Lucee proxy configuration (migrated from global Apache config)"
						echo "$block_content"
						return 0
					fi
					in_block=0
					block_content=""
				fi
				;;
			*)
				if [ "$in_block" = "1" ]; then
					block_content="$block_content"$'\n'"$line"
				fi
				;;
		esac
	done < "$config_file"
	
	return 1
}

# Find and extract Lucee proxy configuration from global Apache config
# Returns the proxy block content or empty if not found
find_lucee_proxy_block() {
	local config_file="$1"
	[ -f "$config_file" ] || return 1
	
	# Try manual delineation first
	local proxy_block
	proxy_block=$(find_manual_proxy_block "$config_file" 2>/dev/null)
	if [ $? -eq 0 ] && [ -n "$proxy_block" ]; then
		echo "$proxy_block"
		return 0
	fi
	
	# Fallback to regex detection
	proxy_block=$(find_regex_proxy_block "$config_file" 2>/dev/null)
	if [ $? -eq 0 ] && [ -n "$proxy_block" ]; then
		echo "$proxy_block"
		return 0
	fi
	
	return 1
}

# Replace Lucee proxy block with comment indicating migration
# Returns 0 on success, 1 on failure
replace_proxy_with_comment() {
	local config_file="$1"
	local proxy_conf_path="$2"
	[ -f "$config_file" ] || return 1

	[ "$PREVIEW_MODE" = true ] && return 0
	
	local tmp
	tmp=$(mktemp)
	
	# Try manual delineation replacement first
	if awk -v conf="$proxy_conf_path" '
		/^[[:space:]]*#[[:space:]]*begin[[:space:]]+[Ll]ucee[[:space:]]+proxy/ { 
			print "# Lucee proxy configuration moved to " conf
			comment_mode=1; next 
		}
		/^[[:space:]]*#[[:space:]]*end[[:space:]]+[Ll]ucee[[:space:]]+proxy/ { 
			if (comment_mode) { comment_mode=0; next }
		}
		comment_mode { print "# " $0; next }
		{ print }
	' "$config_file" > "$tmp"; then
		normalize_conf_whitespace "$tmp"
		if ! cmp -s "$config_file" "$tmp"; then
			cp -f --no-preserve=all "$tmp" "$config_file"
			rm -f "$tmp"
			return 0
		fi
	fi
	
	# Fallback to regex-based replacement - completely rewritten to handle newlines properly
	awk -v conf="$proxy_conf_path" '
		BEGIN { 
			in_proxy=0; 
			replaced=0; 
			proxy_content=""; 
		}
		
		/<IfModule[[:space:]]+mod_proxy\.c>/ {
			if (!replaced) {
				in_proxy=1;
				proxy_start=NR;
				proxy_content=$0;
				next;
			}
		}
		
		in_proxy && /<\/IfModule>/ {
			proxy_content = proxy_content "\n" $0;
			
			# Check if this is a Lucee proxy block
			if (proxy_content ~ /ProxyPassMatch.*cf/) {
				print "# Lucee proxy configuration moved to " conf;
				
				# Split the content into lines and comment each line
				split(proxy_content, lines, "\n");
				for (i = 1; i in lines; i++) {
					if (lines[i] != "") {
						print "# " lines[i];
					}
				}
				replaced=1;
			}
			else {
				# Not a Lucee block, print it as-is
				print proxy_content;
			}
			
			in_proxy=0;
			proxy_content="";
			next;
		}
		
		in_proxy { 
			proxy_content = proxy_content "\n" $0; 
			next; 
		}
		
		{ print; }
	' "$config_file" > "$tmp"
	
	if [ $? -eq 0 ]; then
		normalize_conf_whitespace "$tmp"
		cp -f --no-preserve=all "$tmp" "$config_file"
		rm -f "$tmp"
		return 0
	else
		rm -f "$tmp"
		return 1
	fi
}

# Migrate existing Lucee proxy config from global Apache to lucee-proxy.conf
# Returns 0 on success, 1 on failure, 2 if no migration needed
migrate_lucee_proxy_config() {
	local global_config_dir="$1"
	local proxy_conf_path="$2"
	
	# Skip if lucee-proxy.conf already exists
	if [ -f "$proxy_conf_path" ]; then
		echo "lucee-proxy.conf already exists; skipping migration"
		return 2
	fi
	
	# Search for Lucee proxy config in global Apache files
	local proxy_block=""
	local source_file=""
	
	# Check common global config files
	for config_file in \
		"$(dirname "$global_config_dir")"/httpd.conf \
		"$(dirname "$global_config_dir")"/conf/httpd.conf \
		"$(dirname "$global_config_dir")"/apache2.conf \
		"$global_config_dir"/includes/*.conf \
		"$global_config_dir"/*.conf
	do
		[ -f "$config_file" ] || continue
		proxy_block=$(find_lucee_proxy_block "$config_file" 2>/dev/null)
		if [ $? -eq 0 ] && [ -n "$proxy_block" ]; then
			source_file="$config_file"
			break
		fi
	done
	
	if [ -z "$proxy_block" ] || [ -z "$source_file" ]; then
		echo "Error: Unable to automatically identify Lucee proxy configuration."
		echo ""
		echo "Please manually delineate your Apache global configuration like this:"
		echo ""
		echo "# begin Lucee proxy"
		echo "[your existing proxy configuration here]"
		echo "# end Lucee proxy"
		echo ""
		echo "Then run this script again."
		exit 1
	fi
	
	echo "Found Lucee proxy configuration in: $source_file"
	echo "${PREVIEW_PREFIX}Migrating to: $proxy_conf_path"
	
	# Backup source file
	execute_or_simulate "backup_file" "$source_file"
	
	[ "$PREVIEW_MODE" = true ] && return 0
	
	# Write proxy block to lucee-proxy.conf
	echo "$proxy_block" > "$proxy_conf_path"
	
	# Normalize whitespace in the generated file
	normalize_conf_whitespace "$proxy_conf_path"
	
	# Replace original block with comment indicating migration
	if replace_proxy_with_comment "$source_file" "$proxy_conf_path"; then
		echo "Successfully migrated Lucee proxy configuration"
		return 0
	else
		echo "Error: Failed to replace proxy block with migration comment"
		return 1
	fi
}

# Ensure global Apache confs exist and are set to normal-state defaults
# Normal state: lucee-proxy enabled; upgrade flag disabled
ensure_global_confs() {

	local opt_file="${UPG_DIR}/lucee-upgrade-in-progress.conf"
	local luip_conf

	echo ""
	execute_or_simulate "create_dir" "${HTTPD_LUCEE_ROOT}"

	if [ "$PREVIEW_MODE" = false ]; then
		create_ip_allow_txt_if_not_exist
	fi
	if [ ! -f "${HTTPD_LUCEE_ROOT}/ip-allow.conf" ]; then
		execute_or_simulate "build_ip_all_conf_from_txt"
	fi

	# Copy lucee-detect-upgrade.conf from UPG_DIR to HTTPD_LUCEE_ROOT and adjust the
	# HTTPD_ROOT path which can be changed by tests/cpanel-simulate.sh.
	if [ "$PREVIEW_MODE" = true ]; then
		echo "Would create ${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf" >&2
	else
		echo "Create ${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf" >&2
		local tmp=$(mktemp)
		local ESC_HTTPD_ROOT="${HTTPD_ROOT//&/\\&}"
		sed "s|/etc/apache2|${ESC_HTTPD_ROOT}|g" "${UPG_DIR}/lucee-detect-upgrade.conf" > "$tmp"
		cp -f --no-preserve=all "$tmp" "${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf"
		rm -f "$tmp"
	fi

	echo ""
	echo "Checking Lucee proxy configuration ..."

	# Debian, Ubuntu, Pop!_OS, etc
	if [ "$IS_DEBIAN" = true ]; then

		# Debian/Ubuntu - check if proxy migration is needed
		local proxy_available=false
		local conf_avail="/etc/apache2/conf-available"
		if [ ! -f "${conf_avail}/lucee-proxy.conf" ]; then
			migrate_lucee_proxy_config "$conf_avail" "${conf_avail}/lucee-proxy.conf"
		fi
		luip_conf="${conf_avail}/lucee-upgrade-in-progress.conf"
		if [ ! -f "$luip_conf" ]; then
			execute_or_simulate "copy_file" "$opt_file" "$luip_conf"
		fi
		# Proxy migration already handled in early check
		# Ensure upgrade flag is disabled by default
		execute_or_simulate "disable_conf" "lucee-upgrade-in-progress"
		# Ensure lucee-proxy.conf is enabled if present in conf-available
		if [ -f "${conf_avail}/lucee-proxy.conf" ]; then
			proxy_available=true
			execute_or_simulate "enable_conf" "lucee-proxy"
		fi
		# Warn if no Lucee proxying detected in global config
		local proxy_enabled=false
		if [ -f "/etc/apache2/conf-enabled/lucee-proxy.conf" ]; then
			proxy_enabled=true
		fi
		if [ "$proxy_enabled" = true ] || [ "$PREVIEW_MODE" = true ]; then
			echo "${PREVIEW_PREFIX}lucee-proxy.conf enabled"
		elif [ "$proxy_available" = true ]; then
			echo "lucee-proxy.conf available but not enabled"
		else
			echo "Warning: Lucee proxy configuration not detected in global Apache config (Debian/Ubuntu). Normal operation expects mod_proxy enabled."
		fi

	# has conf.d (Fedora, Red Hat, AlmaLinux, Rocky Linux, etc)
	elif [ -n "$CONF_DIR" ]; then

		local proxy_conf="${CONF_DIR}/lucee-proxy.conf"
		
		# First check if we need migration (before any renames happen to avoid potential race condition)
		local need_migration=false
		if [ ! -f "$proxy_conf" ] && [ ! -f "${proxy_conf}.disabled" ]; then
			need_migration=true
		fi
		
		# Handle disabled file if it exists
		if [ -f "${proxy_conf}.disabled" ]; then
			if [ -f "$proxy_conf" ]; then
				execute_or_simulate "delete_file" "${proxy_conf}.disabled"
			else
				execute_or_simulate "rename_file" "${proxy_conf}.disabled" "$proxy_conf"
			fi
		fi
		
		if [ "$need_migration" = true ]; then
			migrate_lucee_proxy_config "$CONF_DIR" "${proxy_conf}"
		fi

		luip_conf="${CONF_DIR}/lucee-upgrade-in-progress.conf"
		if [ -f "$luip_conf" ] && [ -f "${luip_conf}.disabled" ]; then
			execute_or_simulate "delete_file" "${luip_conf}"
		fi
		if [ ! -f "${luip_conf}.disabled" ]; then
			if [ -f "$luip_conf" ]; then
				execute_or_simulate "rename_file" "$luip_conf" "${luip_conf}.disabled"
			else
				execute_or_simulate "copy_file" "$opt_file" "${luip_conf}.disabled"
			fi
		fi
	fi

	generate_allowed_ip_proxy_include || exit 1

}

copy_upgrade_html() {
	local docroot=$1
	[ -f "${docroot}/lucee-upgrade-in-progress.html" ] && echo -n "  "
	execute_or_simulate "backup_file" "${docroot}/lucee-upgrade-in-progress.html"
	echo -n "  "
	execute_or_simulate "copy_file" "${UPG_DIR}/lucee-upgrade-in-progress.html" "${docroot}/lucee-upgrade-in-progress.html"
	
	if [ "$PREVIEW_MODE" = false ]; then
		local owner_group
		owner_group=$(stat -c "%U:%G" "$docroot" 2>/dev/null)
		if [ -n "$owner_group" ]; then
			chown $owner_group "${docroot}/lucee-upgrade-in-progress.html" 2>/dev/null || true
			echo "  Set ownership of ${docroot}/lucee-upgrade-in-progress.html to $owner_group"
		fi
		chmod "664" "${docroot}/lucee-upgrade-in-progress.html" 2>/dev/null || true
		echo "  Set permissions of ${docroot}/lucee-upgrade-in-progress.html to 664"
	fi
}

# Extract 404 block with fallback logic (htaccess -> commented htaccess -> vhost)
extract_404_block_with_fallback() {
	local docroot="$1"
	local vhost_file="$2"
	local port_desc="$3"  # e.g., "SSL" or "HTTP"
	local output_var_name="$4"     # Variable name to store the 404 block
	local output_source_var="$5"   # Variable name to store source flag (htaccess/vhost)
	
	local block=""
	local from_htaccess="false"
	
	# Try .htaccess first (more specific)
	if [ -f "$docroot/.htaccess" ] && last_404_is_cf "$docroot/.htaccess"; then
		block=$(extract_404_block "$docroot/.htaccess" || true)
		if [ -n "$block" ]; then
			from_htaccess="true"
		fi
	fi
	
	# If .htaccess was already commented by a prior run, recover the 404 from it
	if [ -z "$block" ] && [ -f "$docroot/.htaccess" ] && grep -qi 'NOTE: ErrorDocument 404 moved' "$docroot/.htaccess"; then
		block=$(extract_404_block_allow_commented "$docroot/.htaccess" || true)
		if [ -n "$block" ]; then
			from_htaccess="true"
		fi
	fi
	
	# If no .htaccess 404, fallback to local vhost 404
	if [ -z "$block" ] && [ -n "$vhost_file" ]; then
		if last_404_is_cf "$vhost_file"; then
			block=$(extract_404_block "$vhost_file" || true)
		fi
	fi
	
	# Output the values for the caller to capture (use delimiter to handle multi-line blocks)
	echo "BLOCK_START"
	echo "$block"
	echo "BLOCK_END"
	echo "$from_htaccess"
}

# Process vhost for per-site includes (check existing, extract 404, configure)
process_vhost_for_includes() {
	local domain="$1"
	local port="$2"
	local vhost_file="$3"
	local docroot="$4"
	local port_desc="$5"      # e.g., "SSL" or "HTTP"
	local reuse_block="$6"    # Optional: existing 404 block to reuse
	
	if [ ! -f "$vhost_file" ]; then
		return 0
	fi
	
	# output to stderr to avoid polluting stdout, otherwise user messages
	# would also be output to stdout along with the return value, causing
	# formatting issues when messages appear on the same line
	echo -n "  " >&2
	execute_or_simulate "backup_file" "$vhost_file"
	
	# Check if per-site 404 include already exists
	if has_site_include_file_for_404 "$domain" "$port"; then
		echo "  ${PREVIEW_PREFIX}Per-site include already exists for ${domain}:${port}; ensuring vhost includes it" >&2
		add_include_404_to_vhost "$vhost_file" "$domain" "$port"
	else
		local block=""
		local from_htaccess="false"
		
		# If we have a block to reuse, use it
		if [ -n "$reuse_block" ]; then
			echo "  ${PREVIEW_PREFIX}Reusing 404 from SSL vhost for $port_desc per-site include" >&2
			block="$reuse_block"
		else
			# Extract 404 block with fallback logic
			local result
			result=$(extract_404_block_with_fallback "$docroot" "$vhost_file" "$port_desc" "block" "from_htaccess")
			block=$(echo "$result" | sed -n '/^BLOCK_START$/,/^BLOCK_END$/{/^BLOCK_START$/d; /^BLOCK_END$/d; p;}')
			from_htaccess=$(echo "$result" | tail -n 1)
			
			# Display appropriate message based on what was found
			if [ -n "$block" ]; then
				if [ "$from_htaccess" = "true" ]; then
					echo "  ${PREVIEW_PREFIX}Using 404 from .htaccess for $port_desc per-site include" >&2
				else
					echo "  ${PREVIEW_PREFIX}Using local 404 from $port_desc vhost for per-site include" >&2
				fi
			fi
		fi
		
		# Generate per-site include file if we have a 404 block
		configure_site_includes "$domain" "$port" "$vhost_file" "$docroot" "$block" "$from_htaccess"
	fi
	
	# Ensure detection include is present
	ensure_include_detect_upgrade_in_vhost "$vhost_file" "$domain" "$port"
	
}

# Normalize .htaccess by commenting out 404s if per-site includes exist
normalize_htaccess_404s() {
	local domain="$1"
	local docroot="$2"
	
	# Final normalization: if per-site includes exist and .htaccess still has any 404s, comment them out
	if [ -f "$docroot/.htaccess" ] && grep -qiE "$ANY404_REGEX" "$docroot/.htaccess"; then
		if has_site_include_file_for_404 "$domain" "443" || has_site_include_file_for_404 "$domain" "80"; then
			echo "  ${PREVIEW_PREFIX}Commenting out 404 ErrorDocument in $docroot/.htaccess and adding note"
			[ -f "$docroot/.htaccess" ] && echo -n "  "
			execute_or_simulate "backup_file" "$docroot/.htaccess"
			if [ "$PREVIEW_MODE" = false ]; then
				comment_all_404_lines "$docroot/.htaccess"
			fi
		fi
	fi
}

# Function to configure Debian sites
configure_site_debian() {
	local domain="$1"
	local docroot="$2"
	
	echo ""
	echo "${PREVIEW_PREFIX}Processing site $domain with DocumentRoot: $docroot"
	
	copy_upgrade_html "$docroot"
	
	# Find the SSL site configuration file in sites-available directly
	local ssl_conf_file="/etc/apache2/sites-available/${domain}-ssl.conf"
	if [ ! -f "$ssl_conf_file" ]; then
		# Try to find by ServerName
		ssl_conf_file=$(grep -l "ServerName $domain" /etc/apache2/sites-available/*-ssl.conf 2>/dev/null | head -1)
	fi
	
	if [ -f "$ssl_conf_file" ]; then
		process_vhost_for_includes "$domain" "443" "$ssl_conf_file" "$docroot" "SSL"
	else
		echo "  ${PREVIEW_PREFIX}No SSL VirtualHost found for $domain"
	fi

	# Also update the HTTP (port 80) VirtualHost if present
	# Find the HTTP site configuration file in sites-available
	local http_conf_file="/etc/apache2/sites-available/${domain}.conf"
	if [ ! -f "$http_conf_file" ]; then
		# Try to find by ServerName, excluding -ssl.conf
		http_conf_file=$(grep -l "ServerName $domain" /etc/apache2/sites-available/*.conf 2>/dev/null | grep -v -- '-ssl\.conf' | head -1)
	fi

	if [ -n "$http_conf_file" ]; then
		process_vhost_for_includes "$domain" "80" "$http_conf_file" "$docroot" "HTTP"	
		# Best-effort warning if HTTP VirtualHost may not redirect to HTTPS
		if ! grep -Eiq '(Redirect(\s+(permanent|temp|301|302))?\s+/?\s+https?://|RewriteRule\s+.*https://)' "$http_conf_file"; then
			echo "  ${PREVIEW_PREFIX}Warning: HTTP vhost for $domain may not redirect to HTTPS. Ensure a proper 80->443 redirect is configured to avoid exposure over HTTP."
		fi
	else
{{ ... }}
		echo "  ${PREVIEW_PREFIX}Info: No HTTP configuration file found for $domain"
	fi

	# Final normalization: if per-site includes exist and .htaccess still has any 404s, comment them out
	normalize_htaccess_404s "$domain" "$docroot"
}

# Function to configure cPanel sites
configure_site_cpanel() {
	local domain="$1"
	local docroot="$2"
	
	echo "${PREVIEW_PREFIX}Processing site $domain with DocumentRoot: $docroot"
	
	# assuming cPanel docroot: /home/user/public_html
	# parse user via pure Bash parameter expansion (no regex)
	local user="${docroot#/home/}" # removes /home/ prefix
	user="${user%%/*}"             # removes longest matching suffix i.e. everything after first /
	
	# Copy lucee-upgrade-in-progress.html to docroot
	copy_upgrade_html "$docroot"
	
	# Create userdata directories
	echo -n "  "
	execute_or_simulate "create_dir" "${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}"
	echo -n "  "
	execute_or_simulate "create_dir" "${CPANEL_USERDATA_STD_PATH}/${user}/${domain}"

	# Check if per-site includes already exist
	if has_site_include_file_for_404 "$domain" "443" && has_site_include_file_for_404 "$domain" "80"; then
		echo "  ${PREVIEW_PREFIX}Per-site includes already exist for ${domain}; updating userdata files"
	else
		# Extract 404 block from existing .htaccess or userdata if any
		local cp_404_block=""
		local cp_from_htaccess="false"
		
		# Prefer .htaccess for comment preservation and precedence; proceed only if last 404 is CF
		if [ -f "$docroot/.htaccess" ] && last_404_is_cf "$docroot/.htaccess"; then
			cp_404_block=$(extract_404_block "$docroot/.htaccess" || true)
			if [ -n "$cp_404_block" ]; then
				echo "  ${PREVIEW_PREFIX}Using 404 from .htaccess for cPanel per-site includes"
				cp_from_htaccess="true"
			fi
		fi
		
		# If still empty, try to find in existing userdata files
		if [ -z "$cp_404_block" ]; then
			for d in "${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}" "${CPANEL_USERDATA_STD_PATH}/${user}/${domain}"; do
				[ -d "$d" ] || continue
				while IFS= read -r f; do
					[ -f "$f" ] || continue
					# Only proceed if the last 404 in this file is CF
					if last_404_is_cf "$f"; then
						cp_404_block=$(extract_404_block "$f" || true)
						if [ -n "$cp_404_block" ]; then
							echo "  ${PREVIEW_PREFIX}Using 404 from userdata file: $f"
							break
						fi
					fi
				done < <(find "$d" -type f -maxdepth 1 2>/dev/null)
				if [ -n "$cp_404_block" ]; then
					break
				fi
			done
		fi
		
		# Generate per-site include files if we have a 404 block
		if [ -n "$cp_404_block" ]; then
			generate_site_404_include "$domain" "443" "$cp_404_block"
			generate_site_404_include "$domain" "80" "$cp_404_block"
			
			# Comment out original 404s after successful include generation
			if [ "$cp_from_htaccess" = "true" ]; then
				[ -f "$docroot/.htaccess" ] && echo -n "  "
				execute_or_simulate "backup_file" "$docroot/.htaccess"
				if [ "$PREVIEW_MODE" = false ]; then
					comment_all_404_lines "$docroot/.htaccess"
				fi
			fi
			
			# Comment out any pre-existing 404s in existing userdata files
			for d in "${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}" "${CPANEL_USERDATA_STD_PATH}/${user}/${domain}"; do
				[ -d "$d" ] || continue
				while IFS= read -r f; do
					[ -f "$f" ] || continue
					if grep -qiE "$ANY404_REGEX" "$f"; then
						echo "  ${PREVIEW_PREFIX}Commenting out pre-existing 404s in userdata file: $f"
						[ -f "$f" ] && echo -n "  "
						execute_or_simulate "backup_file" "$f"
						if [ "$PREVIEW_MODE" = false ]; then
							comment_all_404_lines "$f"
						fi
					fi
				done < <(find "$d" -type f -maxdepth 1 2>/dev/null)
			done
		fi
	fi
	
	# Create/update userdata files with includes
	local ssl_include="${SITE_INCLUDES_404_DIR}/${domain}-443.conf"
	local http_include="${SITE_INCLUDES_404_DIR}/${domain}-80.conf"
	
	# SSL userdata file
	[ -f "${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}/lucee.conf" ] && echo -n "  "
	execute_or_simulate "backup_file" "${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}/lucee.conf"
	
	echo -n "  "
	execute_or_simulate "create_file" "${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}/lucee.conf"
	
	if [ "$PREVIEW_MODE" = false ]; then
		cat > ${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}/lucee.conf << EOF
# This file is automatically generated and managed by
# ${UPG_DIR}/configure-apache.sh
# Any manual changes will be overwritten when the script runs
EOF
		# Add per-site include if it exists
		if [ -f "$ssl_include" ]; then
			printf "\nInclude $ssl_include" >> ${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}/lucee.conf
		fi
		printf "\nInclude ${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf\n" >> ${CPANEL_USERDATA_SSL_PATH}/${user}/${domain}/lucee.conf
	fi
	
	# HTTP userdata file
	[ -f "${CPANEL_USERDATA_STD_PATH}/${user}/${domain}/lucee.conf" ] && echo -n "  "
	execute_or_simulate "backup_file" "${CPANEL_USERDATA_STD_PATH}/${user}/${domain}/lucee.conf"
	
	echo -n "  "
	execute_or_simulate "create_file" "${CPANEL_USERDATA_STD_PATH}/${user}/${domain}/lucee.conf"
	
	if [ "$PREVIEW_MODE" = false ]; then
		cat > ${CPANEL_USERDATA_STD_PATH}/${user}/${domain}/lucee.conf << EOF
# This file is automatically generated and managed by
# ${UPG_DIR}/configure-apache.sh
# Any manual changes will be overwritten when the script runs

EOF
		# Add per-site include if it exists
		if [ -f "$http_include" ]; then
			printf "\nInclude $http_include" >> ${CPANEL_USERDATA_STD_PATH}/${user}/${domain}/lucee.conf
		fi
		printf "\nInclude ${HTTPD_LUCEE_ROOT}/lucee-detect-upgrade.conf\n" >> ${CPANEL_USERDATA_STD_PATH}/${user}/${domain}/lucee.conf
	fi
}

# Helper function to find vhost file for RHEL systems
find_redhat_vhost_file() {
	local domain="$1"
	local docroot="$2"
	local port_pattern="$3"  # e.g., ":443" or ":80"
	
	while IFS= read -r line; do
		local site_domain site_docroot site_vhost_file
		site_domain=$(echo "$line" | awk '{print $1}')
		site_docroot=$(echo "$line" | awk '{print $2}')
		site_vhost_file=$(echo "$line" | awk '{print $3}')
		
		if [ "$site_domain" = "$domain" ] && [ "$site_docroot" = "$docroot" ]; then
			if [ -f "$site_vhost_file" ]; then
				if [ "$port_pattern" = ":443" ] && grep -Eq '<VirtualHost[^>]*:443' "$site_vhost_file" 2>/dev/null; then
					printf "%s" "$site_vhost_file"
					return 0
				elif [ "$port_pattern" = ":80" ] && (grep -Eq '<VirtualHost[^>]*:80' "$site_vhost_file" 2>/dev/null || ! grep -Eq '<VirtualHost[^>]*:443' "$site_vhost_file" 2>/dev/null); then
					printf "%s" "$site_vhost_file"
					return 0
				fi
			fi
		fi
	done < "$SITES_FILE"
}

# Function to configure RHEL sites
configure_site_redhat() {
	local domain="$1"
	local docroot="$2"

	echo "${PREVIEW_PREFIX}Processing site $domain with DocumentRoot: $docroot"

	# Copy lucee-upgrade-in-progress.html to DocumentRoot
	copy_upgrade_html "$docroot"

	# Find SSL VirtualHost file from sites-configured.txt
	local ssl_conf_file
	ssl_conf_file=$(find_redhat_vhost_file "$domain" "$docroot" ":443")

	local ssl_404_block=""
	if [ -n "$ssl_conf_file" ]; then
		ssl_404_block=$(process_vhost_for_includes "$domain" "443" "$ssl_conf_file" "$docroot" "SSL")
	else
		echo "  No SSL VirtualHost found for $domain"
	fi

	# Find HTTP VirtualHost file from sites-configured.txt
	local http_conf_file
	http_conf_file=$(find_redhat_vhost_file "$domain" "$docroot" ":80")

	if [ -n "$http_conf_file" ]; then
		process_vhost_for_includes "$domain" "80" "$http_conf_file" "$docroot" "HTTP"
	else
		echo "  Info: No HTTP VirtualHost found for $domain"
	fi

	# Final normalization: if per-site includes exist and .htaccess still has any 404s, comment them out
	normalize_htaccess_404s "$domain" "$docroot"
}

# Function to process all sites from the configuration file
process_sites() {
	
	echo ""
	echo "${PREVIEW_PREFIX}Configuring Lucee sites for scripted 'Upgrade in Progress' notifications ..."

	local configure_func="$1"
	
	# Get data from txt file
	while IFS= read -r line; do
		local domain=$(echo "$line" | awk '{print $1}')
		local docroot=$(echo "$line" | awk '{print $2}')
		# vhost_file=$(echo "$line" | awk '{print $3}') # Available but not used in this context
		$configure_func "$domain" "$docroot"
		
	done < "$SITES_FILE"
}

# Function to get user confirmation (only in preview mode)
get_user_confirmation() {
	
	[ "$PREVIEW_MODE" = false ] && return 0
	
	echo ""
	read -r -p "Do you want to proceed with these pending changes? [y/N] " response

	case "$response" in
		[yY]|[yY][eE][sS])
			return 0
			;;
		*)
			echo "Operation cancelled by user."
			return 1
			;;
	esac
}

# Main execution logic function
run_main_logic() {
	local env_type
	if [ "$IS_DEBIAN" = true ]; then
		env_type="debian"
	elif [ -n "$CONF_DIR" ]; then
		if [ "$IS_CPANEL" = true ]; then
			env_type="cpanel"
		else
			env_type="redhat"
		fi
	else
		echo "Unsupported environment (Debian or RedHat family required)"
		exit 1
	fi
	
	ensure_global_confs
	
	if [ "$PREVIEW_MODE" = false ]; then
		press_enter_to_continue
	fi
	
	process_sites "configure_site_${env_type}"

	echo ""
	execute_or_simulate "apache_reload"

	echo ""
	echo "${PREVIEW_PREFIX}Backups created in: ${UPG_DIR}/backups/${BACKUP_TS}"
}

# MAIN SCRIPT EXECUTION

# Show header
if [ "$PREVIEW_MODE" = true ]; then
	echo "=========================="
	echo "PREVIEW OF PENDING CHANGES"
	echo "=========================="
else
	echo "Executing Apache configuration changes..."
fi

# Run main logic
run_main_logic

# Handle preview mode confirmation and execution
if [ "$PREVIEW_MODE" = true ]; then
	echo ""
	echo "==============================================="
	
	if ! get_user_confirmation; then
		exit 0
	fi
	
	# Switch to execute mode and re-run main logic directly
	clear
	PREVIEW_MODE=false
	PREVIEW_PREFIX=""
	printf "\nExecuting Apache configuration changes...\n"
	run_main_logic
fi

printf "\nDONE!\n"
