#!/bin/bash
# Certbot deploy hook for personal_mtproxy.
# Installed to /etc/letsencrypt/renewal-hooks/deploy/ by `make install`.
# Runs automatically after every successful certificate renewal.
# Also triggered manually by `make install` when a certificate already exists.
#
# Supports multiple vhosts: iterates over all DATADIR/<domain>/cert-lineage
# symlinks and copies certs for any that match the renewed lineage.

DATADIR=/var/lib/personal_mtproxy
SERVICE=personal_mtproxy

reloaded=0

for lineage_link in "$DATADIR"/*/cert-lineage; do
    [ -L "$lineage_link" ] || continue

    expected=$(readlink "$lineage_link" 2>/dev/null) || continue
    [ "${RENEWED_LINEAGE}" = "$expected" ] || continue

    domain_dir="${lineage_link%/cert-lineage}"

    install -o "$SERVICE" -g "$SERVICE" -m 600 "$RENEWED_LINEAGE/privkey.pem"   "$domain_dir/privkey.pem"
    install -o "$SERVICE" -g "$SERVICE" -m 644 "$RENEWED_LINEAGE/fullchain.pem" "$domain_dir/fullchain.pem"

    echo "personal_mtproxy deploy hook: certificates copied to $domain_dir/"
    reloaded=1
done

if [ "$reloaded" = "1" ]; then
    systemctl reload-or-restart "$SERVICE" 2>/dev/null || true
fi
