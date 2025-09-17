#!/bin/bash

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
. "${PARENT_DIR}/ENVIRONMENT.sh"
. "${PARENT_DIR}/shared-functions.sh"

# Set backup timestamp for this run to keep all backups in the same directory
BACKUP_TS="$(date +%Y-%m-%d-%H%M%S)"

# exit if not Debian
if [ "$IS_DEBIAN" = false ]; then
	echo "This script is only for Debian, Ubuntu, Pop!_OS, etc."
	exit 1
fi

# Function to remove duplicate IfDefine blocks, keeping only the last one
remove_duplicate_ifdefine_blocks() {
	local vhost_file="$1"
	[ -f "$vhost_file" ] || return 0
	
	local tmp
	tmp=$(mktemp)
	
	# First pass: find all IfDefine block positions
	awk '
		BEGIN { block_count=0; in_block=0 }
		
		# Track IfDefine block starts
		/^[[:space:]]*<IfDefine[[:space:]]+!LUCEE_UPGRADE_IN_PROGRESS>/ {
			if (!in_block) {
				block_count++
				block_start[block_count] = NR
				in_block = 1
			}
		}
		
		# Track IfDefine block ends
		/^[[:space:]]*<\/IfDefine>/ && in_block {
			block_end[block_count] = NR
			in_block = 0
		}
		
		END {
			print "BLOCK_COUNT=" block_count
			for (i=1; i<=block_count; i++) {
				print "BLOCK_" i "_START=" block_start[i]
				print "BLOCK_" i "_END=" block_end[i]
			}
		}
	' "$vhost_file" > "$tmp.info"
	
	# Read block information
	local block_count
	block_count=$(grep "^BLOCK_COUNT=" "$tmp.info" | cut -d= -f2)
	
	if [ "$block_count" -gt 1 ]; then
		# Second pass: remove all but the last block (and preceding empty lines)
		awk -v info_file="$tmp.info" '
			BEGIN {
				# Read block positions
				while ((getline line < info_file) > 0) {
					if (match(line, /^BLOCK_([0-9]+)_START=([0-9]+)$/, arr)) {
						block_start[arr[1]] = arr[2]
					}
					else if (match(line, /^BLOCK_([0-9]+)_END=([0-9]+)$/, arr)) {
						block_end[arr[1]] = arr[2]
					}
					else if (match(line, /^BLOCK_COUNT=([0-9]+)$/, arr)) {
						block_count = arr[1]
					}
				}
				close(info_file)
				
				# Mark lines to skip (all blocks except the last one)
				for (i=1; i<block_count; i++) {
					# Check for empty line before block start
					if (block_start[i] > 1) {
						skip_line[block_start[i]-1] = "maybe_empty"
					}
					# Mark entire block for removal
					for (j=block_start[i]; j<=block_end[i]; j++) {
						skip_line[j] = "block"
					}
				}
			}
			
			# Process each line
			{
				if (skip_line[NR] == "block") {
					next
				}
				else if (skip_line[NR] == "maybe_empty" && /^[[:space:]]*$/) {
					next
				}
				else {
					print
				}
			}
		' "$vhost_file" > "$tmp"
		
		if [ $? -eq 0 ]; then
			# Preserve original permissions before overwriting
			local orig_perms
			orig_perms=$(stat -c %a "$vhost_file" 2>/dev/null || echo "644")
			mv "$tmp" "$vhost_file"
			chmod "$orig_perms" "$vhost_file" 2>/dev/null || chmod 644 "$vhost_file"
		else
			rm -f "$tmp"
		fi
	fi
	
	rm -f "$tmp.info"
}

# Function to revert vhost changes
revert_vhost_changes() {
	local vhost_file="$1"
	[ -f "$vhost_file" ] || return 0
	
	local tmp
	tmp=$(mktemp)
	
	# Remove Include line and preceding empty line, unwrap IfDefine blocks
	awk '
		BEGIN { 
			in_ifdefine=0; 
			in_ifdefine_pos=0; 
			skip_next_empty=0;
			blank_line_count = 0;
			max_consecutive_blanks = 1;
		}
		
		# Process blank lines
		/^[[:space:]]*$/ {
			if (skip_next_empty) { 
				skip_next_empty=0; 
				next 
			}
			
			blank_line_count++
			# Only print if we have not exceeded max consecutive blanks
			if (blank_line_count <= max_consecutive_blanks) {
				print
			}
			next
		}
		
		# Remove Include line and mark to skip preceding empty line
		/^[[:space:]]*Include[[:space:]]+\/etc\/apache2\/lucee-upgrade-in-progress\/lucee-detect-upgrade\.conf/ {
			skip_next_empty=1
			blank_line_count = 0
			next
		}
		
		# Start of our IfDefine block
		/^[[:space:]]*<IfDefine[[:space:]]+!LUCEE_UPGRADE_IN_PROGRESS>/ {
			in_ifdefine=1
			blank_line_count = 0
			next
		}
		# Start of positive upgrade-mode IfDefine block (remove entirely)
		/^[[:space:]]*<IfDefine[[:space:]]+LUCEE_UPGRADE_IN_PROGRESS>/ {
			in_ifdefine_pos=1
			blank_line_count = 0
			next
		}
		
		# End of our IfDefine block
		/^[[:space:]]*<\/IfDefine>/ && in_ifdefine {
			in_ifdefine=0
			blank_line_count = 0
			next
		}
		# End of positive upgrade-mode IfDefine block
		/^[[:space:]]*<\/IfDefine>/ && in_ifdefine_pos {
			in_ifdefine_pos=0
			blank_line_count = 0
			next
		}
		
		# Inside our IfDefine block - remove one tab/4 spaces of indentation
		in_ifdefine {
			blank_line_count = 0
			if (match($0, /^\t/)) {
				print substr($0, 2)
			}
			else if (match($0, /^    /)) {
				print substr($0, 5)
			}
			else {
				print $0
			}
			next
		}
		# Inside positive upgrade-mode IfDefine block - drop lines entirely
		in_ifdefine_pos { next }
		
		# Regular lines outside IfDefine
		!in_ifdefine { 
			blank_line_count = 0
			print
			skip_next_empty=0 
		}
	' "$vhost_file" > "$tmp"
	
	if [ $? -eq 0 ]; then
		# Preserve original permissions before overwriting
		local orig_perms
		orig_perms=$(stat -c %a "$vhost_file" 2>/dev/null || echo "644")
		mv "$tmp" "$vhost_file"
		chmod "$orig_perms" "$vhost_file" 2>/dev/null || chmod 644 "$vhost_file"
	else
		rm -f "$tmp"
	fi
}

# Function to remove ErrorDocument 404 /404.cfm lines and preceding comments/empty lines
remove_errordocument_404() {
	local conf_file="$1"
	[ -f "$conf_file" ] || return 0
	
	local tmp
	tmp=$(mktemp)
	
	# Process file to remove ErrorDocument 404 lines and preceding comments/empty lines
	awk '
		BEGIN { 
			buffer_size = 0
			clear_buffer = 0
		}
		
		# Check if current line contains ErrorDocument 404 /404.cfm
		/ErrorDocument[[:space:]]+404[[:space:]]+\/404\.cfm/ {
			# Clear the buffer (removes preceding comments/empty lines)
			buffer_size = 0
			# Skip this ErrorDocument line
			next
		}
		
		# Handle comments and empty lines - buffer them
		/^[[:space:]]*#/ || /^[[:space:]]*$/ {
			buffer[buffer_size] = $0
			buffer_size++
			next
		}
		
		# Non-comment, non-empty line - flush buffer and print
		{
			# Print buffered lines
			for (i = 0; i < buffer_size; i++) {
				print buffer[i]
			}
			buffer_size = 0
			# Print current line
			print
		}
	' "$conf_file" > "$tmp"
	
	if [ $? -eq 0 ]; then
		# Preserve original permissions before overwriting
		local orig_perms
		orig_perms=$(stat -c %a "$conf_file" 2>/dev/null || echo "644")
		mv "$tmp" "$conf_file"
		chmod "$orig_perms" "$conf_file" 2>/dev/null || chmod 644 "$conf_file"
	else
		rm -f "$tmp"
	fi
}

# Function to remove per-site include files and their Include directives from vhost configs
remove_site_includes() {
	local conf_file="$1"
	[ -f "$conf_file" ] || return 0
	
	# Extract domain and port from conf file name
	local domain port
	domain=$(basename "$conf_file" | sed -E 's/^([^_]+)(_[0-9]+)?\.conf$/\1/')
	port=$(basename "$conf_file" | grep -oE '_[0-9]+' | tr -d '_' || echo "80")
	
	# Remove the actual include files
	if [ -n "$SITE_INCLUDES_404_DIR" ] && [ -f "${SITE_INCLUDES_404_DIR}/${domain}-${port}.conf" ]; then
		backup_file "${SITE_INCLUDES_404_DIR}/${domain}-${port}.conf"
		rm -f "${SITE_INCLUDES_404_DIR}/${domain}-${port}.conf" 2>/dev/null
	fi
	
	local tmp
	tmp=$(mktemp)
	
	# Remove Include lines for per-site includes and handle whitespace
	awk '
		BEGIN { 
			blank_line_count = 0 
			max_consecutive_blanks = 1
			skip_next_blank = 0
		}
		
		# Process blank lines
		/^[[:space:]]*$/ {
			if (skip_next_blank) {
				skip_next_blank = 0
				next
			}
			blank_line_count++
			# Only print if we have not exceeded max consecutive blanks
			if (blank_line_count <= max_consecutive_blanks) {
				print
			}
			next
		}
		
		# Check for Include lines for per-site includes
		/^[[:space:]]*Include[[:space:]]+\/etc\/apache2\/lucee-upgrade-in-progress\/site-includes-for-404\/.*\.conf/ {
			# Skip this line and mark to skip the next blank line
			skip_next_blank = 1
			next
		}
		
		# For non-blank lines, reset counter and print
		{
			blank_line_count = 0
			print
		}
	' "$conf_file" > "$tmp"
	
	if [ $? -eq 0 ]; then
		# Preserve original permissions before overwriting
		local orig_perms
		orig_perms=$(stat -c %a "$conf_file" 2>/dev/null || echo "644")
		mv "$tmp" "$conf_file"
		chmod "$orig_perms" "$conf_file" 2>/dev/null || chmod 644 "$conf_file"
	else
		rm -f "$tmp"
	fi
}

# Function to restore .htaccess ErrorDocument 404 lines
restore_htaccess_404() {
	local htaccess_file="$1"
	[ -f "$htaccess_file" ] || return 0
	
	local tmp
	tmp=$(mktemp)
	
	# Get directory ownership to preserve it
	local dir_path
	dir_path=$(dirname "$htaccess_file")
	local dir_owner
	local dir_group
	dir_owner=$(stat -c '%U' "$dir_path")
	dir_group=$(stat -c '%G' "$dir_path")
	
	# Remove NOTE lines and uncomment ErrorDocument 404 lines
	awk '
		# Skip NOTE lines added by configure-apache.sh
		/^# NOTE: ErrorDocument 404 moved/ { next }
		
		# Uncomment ErrorDocument 404 lines that contain /404.cfm
		/^# ErrorDocument[[:space:]]+404.*\/404\.cfm/ {
			# Remove leading "# " to uncomment
			sub(/^# /, "")
			print
			next
		}
		
		# Print all other lines as-is
		{ print }
	' "$htaccess_file" > "$tmp"
	
	if [ $? -eq 0 ]; then
		mv "$tmp" "$htaccess_file"
		# Restore ownership and permissions
		chown "$dir_owner:$dir_group" "$htaccess_file"
		chmod 664 "$htaccess_file"
	else
		rm -f "$tmp"
	fi
}

# Function to clean up apache2.conf
cleanup_apache2_conf() {
	local conf_file="$1"
	[ -f "$conf_file" ] || return 0
	
	local tmp
	tmp=$(mktemp)
	
	# Remove previously commented lines and normalize whitespace
	awk '
		BEGIN { 
			blank_line_count = 0
			max_consecutive_blanks = 1
			in_commented_block = 0
		}
		
		# Detect start of commented Lucee proxy block
		/^# Lucee proxy configuration moved to/ {
			in_commented_block = 1
			next
		}
		
		# Skip all lines in the commented block
		in_commented_block && /^#/ { next }
		
		# End of commented block when we hit a non-comment line
		in_commented_block && !/^#/ { in_commented_block = 0 }
		
		# Process blank lines
		/^[[:space:]]*$/ {
			blank_line_count++
			# Only print if we have not exceeded max consecutive blanks
			if (blank_line_count <= max_consecutive_blanks) {
				print
			}
			next
		}
		
		# For non-blank lines, reset counter and print
		{
			blank_line_count = 0
			print
		}
		
		# We will let normalize_conf_whitespace handle the trailing newline
	' "$conf_file" > "$tmp"
	
	if [ $? -eq 0 ]; then
		# Preserve original permissions before overwriting
		local orig_perms
		orig_perms=$(stat -c %a "$conf_file" 2>/dev/null || echo "644")
		mv "$tmp" "$conf_file"
		chmod "$orig_perms" "$conf_file" 2>/dev/null || chmod 644 "$conf_file"
	else
		rm -f "$tmp"
	fi
}

# Function to normalize whitespace in VirtualHost blocks
normalize_vhost_whitespace() {
	# Use the simplified generic whitespace normalization function
	normalize_conf_whitespace "$1"
}

# Function to add empty line between </VirtualHost> and <Directory tags
# and ensure empty line at end of file
normalize_vhost_tags() {
	local conf_file="$1"
	[ -f "$conf_file" ] || return 0
	
	local tmp
	tmp=$(mktemp)
	
	# Process file to add empty line between </VirtualHost> and <Directory
	awk '
		BEGIN { 
			prev_line_was_virtualhost_end = 0
		}
		
		# Check if line is </VirtualHost> closing tag
		/^[[:space:]]*<\/VirtualHost>/ {
			print
			prev_line_was_virtualhost_end = 1
			next
		}
		
		# Check if line starts a <Directory tag and previous line was </VirtualHost>
		/^[[:space:]]*<Directory/ {
			if (prev_line_was_virtualhost_end) {
				# Add empty line before <Directory
				print ""
			}
			print
			prev_line_was_virtualhost_end = 0
			next
		}
		
		# Any other line
		{
			print
			prev_line_was_virtualhost_end = 0
		}
	' "$conf_file" > "$tmp"
	
	if [ $? -eq 0 ]; then
		# Preserve original permissions before overwriting
		local orig_perms
		orig_perms=$(stat -c %a "$conf_file" 2>/dev/null || echo "644")
		mv "$tmp" "$conf_file"
		chmod "$orig_perms" "$conf_file" 2>/dev/null || chmod 644 "$conf_file"
		# Ensure exactly one newline at the end
		normalize_conf_whitespace "$conf_file"
	else
		rm -f "$tmp"
	fi
}

rm -rf /etc/apache2/lucee-upgrade-in-progress
rm -f /var/lucee-upgrade-in-progress

# append contents of lucee-proxy.conf to apache2.conf (without header comment)
if [ -f "/etc/apache2/conf-available/lucee-proxy.conf" ]; then
	# Skip the first line (header comment) when appending
	awk 'NR>1' "/etc/apache2/conf-available/lucee-proxy.conf" >> "/etc/apache2/apache2.conf"
	
	# Clean up apache2.conf to remove commented blocks and normalize whitespace
	cleanup_apache2_conf "/etc/apache2/apache2.conf"
fi

# Disable and delete configuration files
disable_and_remove_conf "lucee-proxy"
disable_and_remove_conf "lucee-upgrade-in-progress"

# Normalize whitespace in all sites-available files
echo "Normalizing whitespace in Apache vhost configuration files..."
if [ -d "/etc/apache2/sites-available" ]; then
	find "/etc/apache2/sites-available" -type f -name "*.conf" | while read -r vhost_file; do
		echo "  Processing $vhost_file"
		normalize_vhost_whitespace "$vhost_file"
	done
fi

# Remove per-site 404 include files if they exist
include_404_dir="/etc/apache2/lucee-upgrade-in-progress/site-includes-for-404"
if [ -d "$include_404_dir" ]; then
	echo ""
	echo "Backing up then removing per-site include files from $include_404_dir..."
	backup_folder "$include_404_dir"
	rm -rf "$include_404_dir"
fi

# Process all .conf files in sites-available
echo ""
echo "Processing all .conf files in sites-available..."
for conf_file in /etc/apache2/sites-available/*.conf; do
	if [ -f "$conf_file" ]; then
		echo ""
		echo "  Processing $(basename "$conf_file")"
		remove_duplicate_ifdefine_blocks "$conf_file"
		revert_vhost_changes "$conf_file"
		remove_errordocument_404 "$conf_file"
		remove_site_includes "$conf_file"
		
		# Add empty line between </VirtualHost> and <Directory tags
		# and ensure exactly one newline at the end
		normalize_vhost_tags "$conf_file"
		
		# Extract DocumentRoot and process files
		docroot=$(grep -i '^[[:space:]]*DocumentRoot' "$conf_file" | head -1 | awk '{print $2}' | tr -d '"')
		if [ -n "$docroot" ]; then
			# Remove lucee-upgrade-in-progress.html
			if [ -f "${docroot}/lucee-upgrade-in-progress.html" ]; then
				echo "  Removing ${docroot}/lucee-upgrade-in-progress.html"
				rm -f "${docroot}/lucee-upgrade-in-progress.html"
			fi
			# Process .htaccess file (restore ErrorDocument 404 and fix ownership)
			if [ -f "${docroot}/.htaccess" ]; then
				echo "  Processing ${docroot}/.htaccess"
				restore_htaccess_404 "${docroot}/.htaccess"
			fi
		fi
	fi
done

echo ""
# apache_reload() is globally sourced from ENVIRONMENT.sh
apache_reload
echo ""
echo "DEV reset complete!"
echo ""
