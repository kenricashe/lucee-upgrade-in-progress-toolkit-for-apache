#!/bin/bash

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "${SCRIPT_DIR}/ENVIRONMENT.sh"
. "${SCRIPT_DIR}/shared-functions.sh"

# preflight: check if Apache has been configured for lucee-upgrade-in-progress
if ! is_apache_configured; then
	echo "Error: Apache has not been configured for lucee-upgrade-in-progress."
	echo "Please run the 'Configure Apache' option from the menu first."
	exit 1
fi

# Debian, Ubuntu, Pop!_OS, etc
if [ "$IS_DEBIAN" = true ]; then
	enable_conf lucee-proxy
	disable_conf lucee-upgrade-in-progress
	if ! apache_reload; then
		echo "ERROR: Apache reload failed."
		exit 1
	fi

# Fedora, Red Hat, AlmaLinux, Rocky Linux, etc
elif [ -n "$CONF_DIR" ]; then
	cd "${CONF_DIR}" || exit 1
	echo "Enabling lucee-proxy configuration..."
	mv -f lucee-proxy.conf.disabled lucee-proxy.conf
	echo "Disabling lucee-upgrade-in-progress configuration..."
	mv -f lucee-upgrade-in-progress.conf lucee-upgrade-in-progress.conf.disabled
	if ! apache_reload; then
		exit 1
	fi
else
	echo "Unsupported environment (Debian or RedHat family required)"
	exit 1
fi

rm -f /var/lucee-upgrade-in-progress

echo "DONE!"
