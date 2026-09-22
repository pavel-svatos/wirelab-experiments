#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run this installer with sudo from the repository root.' >&2
    exit 1
fi
test -x build/magicboxd
test -f web/index.html
install -m 0755 build/magicboxd /usr/local/bin/magicboxd
install -d -m 0755 /usr/local/share/magicbox/web /usr/local/share/magicbox/web/vendor
install -m 0644 web/index.html web/app.js web/style.css /usr/local/share/magicbox/web/
install -m 0644 web/vendor/vue.global.prod.js /usr/local/share/magicbox/web/vendor/
install -m 0644 web/vendor/LICENSE.vue /usr/local/share/magicbox/web/vendor/
install -d -m 0700 /etc/magicbox /var/lib/magicbox
if [ ! -f /etc/magicbox/token ]; then
    (umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > /etc/magicbox/token)
fi
install -m 0644 deploy/magicboxd.service /etc/systemd/system/magicboxd.service
systemctl daemon-reload
echo 'Installed. Start with: sudo systemctl enable --now magicboxd'
echo 'Retrieve the management token with: sudo cat /etc/magicbox/token'
echo 'Network changes are disabled by default. See README.md before enabling them.'
