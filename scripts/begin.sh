#!/bin/bash

# Source shared helper# Source environment variables and functions
SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "${SCRIPT_DIR}/ENVIRONMENT.sh"
. "${SCRIPT_DIR}/shared-functions.sh"

# preflight: check if Apache has been configured for lucee-upgrade-in-progress
if ! is_apache_configured; then
	echo "Error: Apache has not been configured for lucee-upgrade-in-progress."
	echo "Please run the 'Configure Apache' option from the menu first."
	exit 1
fi

REQUIRED_FILES=(
	"$HTTPD_LUCEE_ROOT/ip-allow.conf"
	"$HTTPD_LUCEE_ROOT/lucee-proxy-for-allowed-ip.conf"
)
MISSING_FILES=0
for file in "${REQUIRED_FILES[@]}"; do
	if [ ! -f "$file" ]; then
		echo "Error: Required file $file does not exist."
		MISSING_FILES=1
		continue
	fi
done
if [ $MISSING_FILES -eq 1 ]; then
	echo "Please run the 'Configure Apache' option from the menu first."
	exit 1
fi

# The flag file is referenced by cron jobs, etc, to abort during 
# Lucee upgrade (just before or after Lucee is stopped).
# It is not used by Apache because Define on Apache start/reload
# is more efficient than checking for the file's existence on every request.
touch /var/lucee-upgrade-in-progress

# Debian, Ubuntu, Pop!_OS, etc
if [ "$IS_DEBIAN" = true ]; then
	enable_conf lucee-upgrade-in-progress
	disable_conf lucee-proxy
	if ! apache_reload; then
		exit 1
	fi

# Fedora, Red Hat, AlmaLinux, Rocky Linux, etc
elif [ -n "$CONF_DIR" ]; then
	cd "${CONF_DIR}" || exit 1
	echo "Enabling lucee-upgrade-in-progress configuration..."
	mv -f lucee-upgrade-in-progress.conf.disabled lucee-upgrade-in-progress.conf
	echo "Disabling lucee-proxy configuration..."
	mv -f lucee-proxy.conf lucee-proxy.conf.disabled
	if ! apache_reload; then
		exit 1
	fi

else
	echo "Unsupported environment (Debian or RedHat family required)"
	exit 1
fi

echo "DONE!"
