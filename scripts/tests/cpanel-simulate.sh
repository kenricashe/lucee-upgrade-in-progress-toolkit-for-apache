#!/bin/bash

# cPanel Simulation Toggle Script
# Usage: ./tests/cpanel-simulate.sh [on|off|status]

# strict error handling because this is a test script
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "${SCRIPT_DIR}/../ENVIRONMENT.sh"
. "${SCRIPT_DIR}/../shared-functions.sh"

cpanel_config="/etc/apache2/conf/httpd.conf"

CPANEL_FILES=(
	"$cpanel_config"
	"/usr/local/cpanel/cpanel"
	"/scripts/rebuildhttpdconf"
	"/scripts/restartsrv_httpd"
	"/etc/apache2/conf.d/userdata/ssl/2_4"
	"/etc/apache2/conf.d/userdata/std/2_4"
	"/etc/apache2/conf.d/lucee-proxy.conf"
	"/etc/apache2/lucee-upgrade-in-progress/lucee-detect-upgrade.conf"
)

show_usage() {
	echo "Usage: $0 [on|off|status]"
	echo ""
	echo "Commands:"
	echo "  on     - Enable cPanel simulation (create dummy files)"
	echo "  off    - Disable cPanel simulation (remove dummy files, restore originals)"
	echo "  status - Show current simulation status"
	echo ""
	echo "This script creates cPanel simulation files for testing the toolkit in a non-cPanel environment."
}

detect_real_cpanel() {
	if [ -f "/usr/local/cpanel/version" ] || \
	   [ -f "/usr/local/cpanel/cpanel.config" ] || \
	   [ -f "/usr/local/cpanel/bin/cpwrap" ] || \
	   [ -d "/etc/apache2/bin" ] || \
	   [ -d "/etc/apache2/logs" ] || \
	   [ -d "/etc/apache2/modules" ] || \
	   [ -d "/etc/apache2/run" ] || \
	   pgrep -f "cpsrvd" >/dev/null 2>&1; then
		return 0
	fi
	return 1
}

abort_if_real_cpanel() {
	if detect_real_cpanel; then
		echo "ERROR: Real cPanel environment detected. This script is for simulation only."
		echo "Aborting to prevent damage to real cPanel installation."
		exit 1
	fi
}

# Create cPanel simulation httpd.conf with all VirtualHost blocks
create_httpd_conf() {
	if [ -f "$APACHE_CONF_FILE" ] && [ ! -f "$cpanel_config" ]; then
		echo "  Creating /etc/apache2/conf/httpd.conf for cPanel simulation"
		mkdir -p /etc/apache2/conf
		
		# Start with header comment
		echo "# cPanel simulation dummy file created by cpanel-simulate.sh for testing purposes only" > "$cpanel_config"
		echo "# Generated on: $(date)" >> "$cpanel_config"
		echo "" >> "$cpanel_config"

		# Include all conf.d .conf files
		echo "" >> "$cpanel_config"
		echo "IncludeOptional /etc/apache2/conf.d/*.conf" >> "$cpanel_config"
		echo "" >> "$cpanel_config"

		# Find and append VirtualHost blocks from other .conf files using discovery
		echo "" >> "$cpanel_config"
		echo "# Additional VirtualHost blocks discovered from Apache configuration files" >> "$cpanel_config"
		echo "" >> "$cpanel_config"
		
		# Use sites-configured.txt which already contains the list of VirtualHost files (third column)
		# First check if the file exists
		awk '{print $3}' "${SITES_FILE}" | sort -u | while read -r conf_file; do
			# Skip the primary config since we already included it
			if [ -f "$conf_file" ] && [ "$conf_file" != "$APACHE_CONF_FILE" ]; then
				contains_vhost=$(grep -q '<VirtualHost' "$conf_file" && echo true || echo false)
				if [ "$contains_vhost" = true ]; then
					echo "# From: $conf_file" >> "$cpanel_config"
					# Extract ServerName, DocumentRoot and Port
					user=$(grep -m1 '^\s*DocumentRoot\s' "$conf_file" | awk '{print $2}' | cut -d/ -f3)
					domain=$(grep -m1 '^\s*ServerName\s' "$conf_file" | awk '{print $2}')
					# Extract port from VirtualHost directive, handling multiple ports and formats like *:80 or 1.2.3.4:443
					port=$(grep -m1 '^\s*<VirtualHost\s' "$conf_file" | grep -oE ':[0-9]+' | head -1 | cut -d: -f2 || echo '80')
					
					# Determine if this is SSL or standard
					if [ "$port" = "443" ]; then
						ssl_dir="ssl"
					else
						ssl_dir="std"
					fi
					
					# Add IncludeOptional directive before the VirtualHost block
					echo "# From: $conf_file" >> "$cpanel_config"
					
					# Add the VirtualHost block with IncludeOptional inside
					{
						# Process the VirtualHost block line by line to insert IncludeOptional before closing tag
						while IFS= read -r line; do
							if [[ "$line" =~ ^[[:space:]]*\</VirtualHost\> ]]; then
								# Insert IncludeOptional before closing VirtualHost tag
								echo -e "\t# cPanel includes"
								echo -e "\tIncludeOptional \"/etc/apache2/conf.d/userdata/${ssl_dir}/2_4/${user}/${domain}/*.conf\""
								echo ""
							fi
							echo "$line"
						done < "$conf_file"
					} >> "$cpanel_config" 2>/dev/null || {
						echo "Warning: Failed to process VirtualHost blocks from $conf_file" >&2
					}
				fi
			fi
			# disable vhost files that would interfere with cPanel simulation
			if [ "$contains_vhost" = true ]; then
				mv "${conf_file}" "${conf_file}.disabled-for-cpanel-sim"
			fi
		done
	fi
}

# Create /usr/local/cpanel/cpanel (detection file)
create_usr_local_cpanel_cpanel() {
	mkdir -p /usr/local/cpanel
	cat > /usr/local/cpanel/cpanel << 'EOF'
#!/bin/bash
# cPanel simulation dummy file created by cpanel-simulate.sh for testing purposes only
# Generated on: $(date)
EOF
	chmod +x /usr/local/cpanel/cpanel
	echo "  Created: /usr/local/cpanel/cpanel"
}

# Create /scripts/rebuildhttpdconf
create_rebuildhttpdconf() {
	mkdir -p /scripts
	cat > /scripts/rebuildhttpdconf << 'EOF'
#!/bin/bash
# cPanel simulation dummy file created by cpanel-simulate.sh for testing purposes only
# Generated on: $(date)
EOF
	chmod +x /scripts/rebuildhttpdconf
	echo "  Created: /scripts/rebuildhttpdconf"
}

# Create /scripts/restartsrv_httpd
create_restartsrv_httpd() {
	cat > /scripts/restartsrv_httpd << 'EOF'
#!/bin/bash
# cPanel simulation dummy file created by cpanel-simulate.sh for testing purposes only
# Generated on: $(date)

systemctl reload httpd.service
EOF
	chmod +x /scripts/restartsrv_httpd
	echo "  Created: /scripts/restartsrv_httpd"
}

# The sites file must not contain /etc/apache2 left over from previous cpanel-simulate.sh run
require_default_sites_file() {
	if [ ! -f "$SITES_FILE" ]; then
		echo "Error: $SITES_FILE not found."
		echo "Run menu.sh to get sites."
		exit 1
	fi
	if grep -q "/etc/apache2" "$SITES_FILE"; then
		echo "Error: $SITES_FILE is left over from previous cpanel-simulate.sh run."
		echo "Run menu.sh to get sites while NOT in cPanel simulation mode."
		exit 1
	fi
}

create_dummy_files() {

	printf "\nCreating cPanel simulation files..."
	
	create_httpd_conf
	create_usr_local_cpanel_cpanel
	create_rebuildhttpdconf
	create_restartsrv_httpd

	# Create userdata directories
	mkdir -p /etc/apache2/conf.d/userdata/ssl/2_4
	mkdir -p /etc/apache2/conf.d/userdata/std/2_4
	echo "  Created: /etc/apache2/conf.d/userdata directories"
	
	# Copy lucee-proxy.conf if exists (look in original RedHat location)
	if [ -f "/etc/httpd/conf.d/lucee-proxy.conf" ]; then
		cp "/etc/httpd/conf.d/lucee-proxy.conf" /etc/apache2/conf.d/
		mv "/etc/httpd/conf.d/lucee-proxy.conf" "/etc/httpd/conf.d/lucee-proxy.conf.disabled-for-cpanel-sim"
		echo "  Created: /etc/apache2/conf.d/lucee-proxy.conf"
		echo "  Disabled: /etc/httpd/conf.d/lucee-proxy.conf"
	fi

	# Copy lucee-detect-upgrade.conf
	mkdir -p /etc/apache2/lucee-upgrade-in-progress
	cp -f --no-preserve=all "${UPG_DIR}/lucee-detect-upgrade.conf" /etc/apache2/lucee-upgrade-in-progress/
	# replace /etc/httpd with /etc/apache2
	sed -i 's|/etc/httpd|/etc/apache2|g' /etc/apache2/lucee-upgrade-in-progress/lucee-detect-upgrade.conf
	echo "  Created: /etc/apache2/lucee-upgrade-in-progress/lucee-detect-upgrade.conf"

}

remove_dummy_files() {

	echo "Removing cPanel simulation files..."
	rm -rf /etc/apache2
	rm -rf /usr/local/cpanel
	rm -rf /scripts
}

enable_CONF_DIR() {
	echo "Enabling primary conf.d..."
	cd "/etc/httpd/conf.d" || return 1
	for f in *.conf.disabled-for-cpanel-sim; do
		# Skip if no files match the pattern
		[ "$f" = '*.conf.disabled-for-cpanel-sim' ] && continue
		mv "$f" "${f%.disabled-for-cpanel-sim}"
	done
}

show_status() {

	echo ""
	echo "cPanel Simulation Status:"
	echo ""
	
	if detect_real_cpanel; then
		echo ""
		echo "Oops! Real cPanel environment detected. This script is for simulation only."
		exit 0
	fi

	local all_exist=true
	for file in "${CPANEL_FILES[@]}"; do
		if [ -e "$file" ]; then
			echo "  ✓ $file (exists)"
		else
			echo "  ✗ $file (missing)"
			all_exist=false
		fi
	done
	
	echo ""
	if [ "$all_exist" = true ]; then
		echo "Status: cPanel simulation is ENABLED"
		
		# Test the detection
		if [ -f "/usr/local/cpanel/cpanel" ]; then
			echo "Detection test: cPanel would be detected as present"
		fi
	else
		echo "Status: cPanel simulation is DISABLED"
	fi
}

# Main script logic

abort_if_real_cpanel

case "${1:-}" in
	"on")
		if [ -f "/etc/apache2/conf/httpd.conf" ]; then
			printf "\ncPanel mode is already enabled.\nTo refresh the dummy files from an updated version of the toolkit,\nrun cpanel-simulate.sh off then cpanel-simulate.sh on again.\n"
		else
			require_default_sites_file
			create_dummy_files
			echo ""
			echo "✓ cPanel simulation ENABLED"
			echo ""
			echo "You can now test the toolkit in cPanel mode."
			echo "Use '$0 off' to disable simulation."
		fi
		;;
	"off")
		remove_dummy_files
		enable_CONF_DIR
		echo ""
		echo "✓ cPanel simulation DISABLED"
		;;
	"status")
		show_status
		;;
	*)
		show_usage
		exit 1
		;;
esac
