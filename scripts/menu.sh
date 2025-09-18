#!/bin/bash

# Interactive menu for Lucee "Upgrade in Progress" toolkit
# Location (after deploy): /opt/lucee/sys/upgrade-in-progress/menu.sh

# Determine script directory and source shared env
SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Load ENVIRONMENT.sh first to get DEBUG_MODE
. "${SCRIPT_DIR}/ENVIRONMENT.sh"

# Now use DEBUG_MODE for conditional output
[ "$DEBUG_MODE" = true ] && echo "[DEBUG] Starting menu.sh initialization..."
[ "$DEBUG_MODE" = true ] && echo "[DEBUG] Script directory: $SCRIPT_DIR"
[ "$DEBUG_MODE" = true ] && echo "[DEBUG] ENVIRONMENT.sh loaded"

[ "$DEBUG_MODE" = true ] && echo "[DEBUG] Loading shared-functions.sh..."
. "${SCRIPT_DIR}/shared-functions.sh"
[ "$DEBUG_MODE" = true ] && echo "[DEBUG] shared-functions.sh loaded"

[ "$DEBUG_MODE" = true ] && echo "[DEBUG] Loading version.sh..."
. "${SCRIPT_DIR}/version.sh"
[ "$DEBUG_MODE" = true ] && echo "[DEBUG] version.sh loaded"

[ "$DEBUG_MODE" = true ] && echo "[DEBUG] Initialization complete, starting menu loop..."

run_edit_exclusions() {
	ensure_default_exclusions_file
	${EDITOR:-nano} "$EXCLUSIONS_FILE"
}

run_get_sites() {
	clear
	"${UPG_DIR}/get-lucee-sites.sh"
	press_enter_to_continue
}

run_edit_sites() {
	if [ ! -f "${SITES_FILE}" ]; then
		clear
		printf "\nSites file not found: ${SITES_FILE}\n\nRun 'Get Apache Site Data' first to generate it."
		press_enter_to_continue
		return
	fi
	${EDITOR:-nano} "${SITES_FILE}"
}

run_edit_ip_allow() {

	create_ip_allow_txt_if_not_exist

	${EDITOR:-nano} "${IP_ALLOW_TXT_FILE}"

	clear
	
	build_ip_all_conf_from_txt

	if ! apache_reload; then
		echo "Warning: Apache reload may have failed; see messages above."
	fi

	press_enter_to_continue
}

run_configure_apache() {
	clear
	"${UPG_DIR}/configure-apache.sh"
}

run_discover_apache_configs() {
	clear
	"${UPG_DIR}/get-current-configs.sh"
}

run_begin() {
	clear
	"${UPG_DIR}/begin.sh"
}

run_end() {
	clear
	"${UPG_DIR}/end.sh"
}

run_uninstall() {
	clear
	"${UPG_DIR}/uninstall.sh"
}

while true; do
	clear
	echo "------------------------------------------"
	echo " 'Upgrade in Progress' for Lucee + Apache"
	echo "  ${VERSION_STRING}"
	if [ -e "/var/lucee-upgrade-in-progress" ]; then
		echo "Current Server Status: UPGRADE IN PROGRESS"
	else
		echo " Current Server Status: NORMAL OPERATIONS"
	fi
	echo " (based on /var/lucee-upgrade-in-progress)"
	echo "------------------------------------------"
	echo ""
	echo "s) Customize Site Search Exclusions (optional)"
	echo ""
	echo "g) Get Apache Site Data"
	echo ""
	echo "v) View/Edit Apache Site Data File"
	echo ""
	echo "c) Configure Apache (previews changes and prompts for confirmation)"
	echo ""
	echo "r) Apache Configuration Discovery Report"
	echo ""
	echo "i) IP Allow List (for QA Testing)"
	echo ""
	echo "b) Begin 'Upgrade in Progress'"
	echo ""
	echo "e) End 'Upgrade in Progress'"
	echo ""
	echo "q) Quit"
	echo ""
	echo "u) Uninstall"
	echo ""
	read -r -p "Select an option: " choice
	case "${choice}" in
		s|S)
			run_edit_exclusions
			;;
		g|G)
			run_get_sites
			;;
		v|V)
			run_edit_sites
			;;
		c|C)
			run_configure_apache
			press_enter_to_continue
			;;
		r|R)
			run_discover_apache_configs
			press_enter_to_continue
			;;
		i|I)
			run_edit_ip_allow
			;;
		b|B)
			run_begin
			press_enter_to_continue
			;;
		e|E)
			run_end
			press_enter_to_continue
			;;
		q|Q)
			echo "Exiting."
			exit 0
			;;
		u|U)
			run_uninstall
			press_enter_to_continue
			;;
		*)
			echo "Invalid selection."
			;;
	esac
done
