#!/bin/bash

# Usage:
# curl -fsSL https://raw.githubusercontent.com/kenricashe/lucee-upgrade-in-progress-toolkit-for-apache/main/scripts/install.sh | sudo bash
#
# Example with custom Lucee root path in environment variable:
# curl -fsSL https://raw.githubusercontent.com/kenricashe/lucee-upgrade-in-progress-toolkit-for-apache/main/scripts/install.sh | sudo env LUCEE_ROOT=/opt/lucee6 bash
#
# Example with non-main branch name in URL e.g. for QA testing:
# (URL="https://raw.githubusercontent.com/kenricashe/lucee-upgrade-in-progress-toolkit-for-apache/refs/heads/branch-name/scripts/install.sh"; curl -fsSL "$URL" | sudo env SOURCE_URL="$URL" bash)
#
# GitHub CDN caching can last 5 minutes. For quicker testing, in the URL replace branch with the commit sha:
# (URL="https://raw.githubusercontent.com/kenricashe/lucee-upgrade-in-progress-toolkit-for-apache/<commit-sha>/scripts/install.sh"; curl -fsSL "$URL" | sudo env SOURCE_URL="$URL" bash)

# require root
if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root"
	exit 1
fi

OWNER=${OWNER:-kenricashe}
REPO=${REPO:-lucee-upgrade-in-progress-toolkit-for-apache}

# Allow the invoking environment to pass the exact installer URL via SOURCE_URL
# This is the recommended approach for specifying non-default branches
if [ -n "$SOURCE_URL" ]; then
	# Extract components from the URL
	SRC_OWNER=$(printf '%s\n' "$SOURCE_URL" | sed -n 's|.*/raw.githubusercontent.com/\([^/]*\)/[^/]*/.*|\1|p')
	SRC_REPO=$(printf '%s\n' "$SOURCE_URL" | sed -n 's|.*/raw.githubusercontent.com/[^/]*/\([^/]*\)/.*|\1|p')
	# Try to capture refs that contain slashes by matching the known suffix path
	SRC_REF=$(printf '%s\n' "$SOURCE_URL" | sed -n 's|.*/raw.githubusercontent.com/[^/]*/[^/]*/\(.*\)/scripts/install.sh|\1|p')
	# Fallback to single-segment capture if the precise match fails
	if [ -z "$SRC_REF" ]; then
		SRC_REF=$(printf '%s\n' "$SOURCE_URL" | sed -n 's|.*/raw.githubusercontent.com/[^/]*/[^/]*/\([^/]*\)/.*|\1|p')
	fi
	if [ -n "$SRC_OWNER" ] && [ "$OWNER" = "kenricashe" ]; then
		OWNER="$SRC_OWNER"
	fi
	if [ -n "$SRC_REPO" ] && [ "$REPO" = "lucee-upgrade-in-progress-toolkit-for-apache" ]; then
		REPO="$SRC_REPO"
	fi
	if [ -n "$SRC_REF" ] && [ -z "$REF" ]; then
		REF="$SRC_REF"
	fi
fi
REF=${REF:-main}

TARBALL_URL="https://codeload.github.com/${OWNER}/${REPO}/tar.gz/${REF}"
TMPDIR=$(mktemp -d)

cleanup() {
	if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
		rm -rf "$TMPDIR"
	fi
}
trap cleanup EXIT

echo ""
echo "Downloading ${OWNER}/${REPO}@${REF} ..."

# When extracting GitHub tarballs, the top directory will be named {repo}-{ref}
# where {ref} has '/' characters replaced with '-'
if ! curl -fsSL "$TARBALL_URL" | tar -xz -C "$TMPDIR"; then
	echo ""
	echo "Error: Failed to download or extract tarball: $TARBALL_URL"
	exit 1
fi

# Find the subdirectory containing this toolset
# GitHub tarballs include a top-level directory named {repo}-{ref}
# where branch refs with slashes are converted to hyphens
echo ""
echo "Searching for scripts directory..."

# First, find the top-level directory
TOP_DIR=$(find "$TMPDIR" -mindepth 1 -maxdepth 1 -type d | head -n1)
echo ""
echo "Found top-level directory: $TOP_DIR"

# Now look for the scripts directory within that top-level directory
SUBDIR="$TOP_DIR/scripts"

if [ ! -d "$SUBDIR" ]; then
	# If direct path doesn't work, try a more general search
	SUBDIR=$(find "$TMPDIR" -type d -path "*/scripts" | head -n1)

	if [ -z "$SUBDIR" ]; then
		# Debug: Show the directory structure to help diagnose the issue
		echo ""
		echo "Directory structure in tarball:"
		find "$TMPDIR" -type d | sort
		echo ""
		echo "Error: Could not locate subdirectory scripts in the tarball"
		exit 1
	fi
fi

echo ""
echo "Found scripts directory at: $SUBDIR"

# Run the deployment script from the extracted directory
if [ ! -x "$SUBDIR/deploy.sh" ]; then
	chmod +x "$SUBDIR/deploy.sh" 2>/dev/null || true
fi

# Check for Lucee root path from environment variable first
DEFAULT_LUCEE_ROOT="/opt/lucee"

if [ -n "$LUCEE_ROOT" ]; then
	# Environment variable provided
	: # do nothing
elif [ -t 0 ]; then
	# Interactive mode - prompt for Lucee root path
	echo ""
	read -r -p "Enter target Lucee root path [${DEFAULT_LUCEE_ROOT}]: " INPUT_LUCEE_ROOT
	LUCEE_ROOT="${INPUT_LUCEE_ROOT:-$DEFAULT_LUCEE_ROOT}"
else
	# Non-interactive mode (curl pipe) - use default and continue
	LUCEE_ROOT="$DEFAULT_LUCEE_ROOT"
fi

# Execute the deployment script and capture its exit status
"$SUBDIR/deploy.sh" "$LUCEE_ROOT"
if [ $? -eq 0 ]; then
	# Deployment was successful
	echo ""
	echo "=================================================================="
	echo ""
	echo "Installation complete!"
	echo ""
	echo "To configure and manage 'Upgrade in Progress' toggling, run:"
	echo ""
	echo "sudo ${LUCEE_ROOT}/sys/upgrade-in-progress/menu.sh"
	echo ""
	echo "=================================================================="
else
	# Deployment failed
	DEPLOY_STATUS=$?
	echo ""
	echo "=================================================================="
	echo "ERROR: Deployment failed with exit code $DEPLOY_STATUS"
	echo "Please check the error messages above for more information."
	echo "=================================================================="
	exit $DEPLOY_STATUS
fi
