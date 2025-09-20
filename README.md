# Lucee 'Upgrade in Progress' Toolkit for Apache

[![License: LGPL v2.1](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)

Web-based status notifications during Lucee upgrades are a Catch-22 because Lucee itself is not running during the upgrade. That results in an ugly "503 Service Unavailable" error. While it's true that `ErrorDocument 503` can be customized, that page is only displayed when Lucee is not running.

In actual practice it's safest to keep displaying the "Upgrade in Progress" notification not just until after the upgrade is done, but more importantly until *thorough QA testing* has been completed.

Temporary firewalls are often used to allow access from only specific IP addresses, but again that's not best for end users because it has the same appearance as a network issue.

While load-balanced environments often handle upgrades by removing individual nodes from rotation, this toolkit remains valuable for scenarios where all nodes need to be upgraded simultaneously and thoroughly tested before resuming normal operations. If there is enough demand, a future version
may include coordination of upgrades across multiple nodes and integration with CI/CD pipelines.
Pull requests are also welcome!

## Apache-level advantages over app-level maintenance mode:

- **No dependency on Lucee**: Works even when Lucee/Tomcat is completely stopped or broken.
- **Performance**: No application overhead - handled before reaching Lucee
- **Security**: No user or bot interference with QA testing. App-level maintenance mode may also be vulnerable to attacks due to untested app.
- **Reliability**: Cannot fail due to application errors, memory issues, code bugs, etc.

## Implementation:

When you enable "Upgrade in Progress" mode via the app menu, a status notification is displayed in response to every Lucee-bound request. That applies to every website on your server that has been configured for this flip-a-switch style automation.

Users are not redirected to a different page, so the URL does not change. They will see the notice of how the page will automatically refresh when the upgrade is complete. That is implemented by detecting a unique http header via HEAD request which is more efficient than refreshing the page.

## Other Features

- Toggles `ErrorDocument 404` (if already pointing to Lucee script).

- Toggles `/var/lucee-upgrade-in-progress` (reference that file to pause cron jobs, etc).

- Enables optional custom branding of the "Upgrade in Progress" page per site.

- Automatically loads user's originally requested page after upgrade complete.

- Doesn't require CDN, load balancing, etc.

- Previews pending changes and waits for confirmation before applying them.

- Backs up existing files before modifying them.

- Option to Uninstall.

- Open source!


## Requirements

- One of the two main Linux families (Debian, Ubuntu, Pop!_OS, etc or Fedora, Red Hat, AlmaLinux, Rocky Linux, etc).
cPanel-managed servers are also supported.

- Root or sudo permissions.

- Apache 2.4 with mod_rewrite, mod_proxy, mod_headers, and mod_setenvif (mod_cfml is optional and not modified by this package).

- Lucee-related directives found in global Apache config as well as site-specific `.htaccess` will be migrated into semantically correct `.conf` files (e.g. `lucee-proxy.conf`) to enable toggling (also best practice for performance, consistency, security, and manageability).


## Backup Folders

`/opt/lucee/sys/upgrade-in-progress/backups/...`

Backups are created when a file already exists and has pending modifications.


## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/kenricashe/lucee-upgrade-in-progress-toolkit-for-apache/main/scripts/install.sh | sudo bash
```

## Customize (optional)

Example: Before opening the menu and running the Apache configuration script,
you may want to change the 15 minute estimated downtime or any other content
in the HTML template:

`/opt/lucee/sys/upgrade-in-progress/lucee-upgrade-in-progress.html`

## Usage

### Open the Toolkit Menu

```bash
sudo /opt/lucee/sys/upgrade-in-progress/menu.sh
```

Then run each item in the menu in the order that they are listed.


## QA Testing

To add an IP address to the allow list, use the menu option "IP Allow List (for QA Testing)". `127.0.0.1` and `::1` (localhost) are pre-configured, but can be disabled by commenting out the line(s) with `#`.

To exclude an entire site, *before configuring Apache*, remove it from the sites data file via the app menu option "View/Edit Site Data". That is mostly suitable only for QA domains e.g. `qa.example.com`.
If Apache was already configured, you will need to Uninstall the toolkit, 
then exclude the site, then configure Apache again.
