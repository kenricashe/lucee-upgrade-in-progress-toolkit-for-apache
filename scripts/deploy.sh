#!/bin/bash

# chmod +x /path/to/this/script/deploy.sh
# sudo /path/to/this/script/deploy.sh

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "${SCRIPT_DIR}/ENVIRONMENT.sh"
. "${SCRIPT_DIR}/shared-functions.sh"
. "${SCRIPT_DIR}/version.sh"

FILES=(
	"ENVIRONMENT.sh"
	"shared-functions.sh"
	"version.sh"
	"menu.sh"
	"get-lucee-sites.sh"
	"configure-apache.sh"
	"get-current-configs.sh"
	"begin.sh"
	"end.sh"
	"lucee-detect-upgrade.conf"
	"lucee-upgrade-in-progress.conf"
	"lucee-upgrade-in-progress.html"
	"uninstall.sh"
	"tests/dev-reset.sh"
	"tests/cpanel-simulate.sh"
)

# preflight: ensure all source files exist in their respective directories
missing=()
parent_dir="$(dirname "$SCRIPT_DIR")"

for f in "${FILES[@]}"; do
	if [[ "$f" == *.conf ]]; then
		src_dir="${parent_dir}/apache"
	elif [[ "$f" == *.html ]]; then
		src_dir="${parent_dir}/html"
	else
		src_dir="$SCRIPT_DIR"
	fi
	
	if [ ! -f "${src_dir}/$f" ]; then
		missing+=("$f")
	fi
done

if [ ${#missing[@]} -gt 0 ]; then
	echo "Error: Missing source files:"
	for m in "${missing[@]}"; do
		echo "  - $m"
	done
	exit 1
fi

echo ""
echo "Deploying ${VERSION_STRING}"

# Use Lucee root path from command line argument or prompt for it
DEFAULT_LUCEE_ROOT="/opt/lucee"

# Check if a path was provided as an argument
if [ -n "$1" ]; then
	LUCEE_ROOT="$1"
	echo ""
	echo "Using Lucee root path: $LUCEE_ROOT"
else
	# No argument provided, prompt for input
	read -r -p "Enter target Lucee root path [${DEFAULT_LUCEE_ROOT}]: " INPUT_LUCEE_ROOT
	LUCEE_ROOT="${INPUT_LUCEE_ROOT:-$DEFAULT_LUCEE_ROOT}"
fi

UPG_DIR="${LUCEE_ROOT}/sys/upgrade-in-progress"
mkdir -p "$UPG_DIR/tests"

function copy_and_chmod() {
	local file="$1"
	local src_dir
	local dst="${UPG_DIR}/$file"
	local parent_dir="$(dirname "$SCRIPT_DIR")"
	if [[ "$file" == *.conf ]]; then
		src_dir="${parent_dir}/apache"
	elif [[ "$file" == *.html ]]; then
		src_dir="${parent_dir}/html"
	else
		src_dir="$SCRIPT_DIR"
	fi
	local src="${src_dir}/$file"
	cp -f --no-preserve=all "$src" "$dst"
	if [[ "$file" == *.sh ]]; then
		chmod +x "$dst"
	fi
}

for file in "${FILES[@]}"; do
	copy_and_chmod "$file"
done

# Rewrite Include paths inside lucee-detect-upgrade.conf to match selected LUCEE_ROOT
CONF_FILE="${UPG_DIR}/lucee-detect-upgrade.conf"
if [ -f "$CONF_FILE" ]; then
	# Escape '&' for sed replacement safety
	ESC_HTTPD_ROOT="${HTTPD_ROOT//&/\\&}"
	# Replace the template's hardcoded /etc/apache2/lucee-upgrade-in-progress with just HTTPD_LUCEE_ROOT
	sed -i "s|/etc/apache2/lucee-upgrade-in-progress|${ESC_HTTPD_ROOT}/lucee-upgrade-in-progress|g" "$CONF_FILE"
fi

echo ""
echo "Deployment to ${UPG_DIR} completed successfully."
