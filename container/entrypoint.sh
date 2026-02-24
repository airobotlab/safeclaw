#!/bin/bash
set -e

# --- Security Layer 3: Network egress whitelist ---
# If ALLOWED_EGRESS_IPS is set, apply iptables rules to restrict outbound traffic.
# Only connections to whitelisted IPs (resolved from allowed domains) are permitted.
# This runs as root before dropping privileges.
if [ -n "$ALLOWED_EGRESS_IPS" ]; then
  iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || true

  IFS=',' read -ra IPS <<< "$ALLOWED_EGRESS_IPS"
  for ip in "${IPS[@]}"; do
    iptables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
  done

  iptables -A OUTPUT -j DROP 2>/dev/null || true
  echo "Network egress restricted to ${#IPS[@]} allowed IPs" >&2
fi

# --- Determine target user ---
# HOST_UID/HOST_GID are passed from the host for permission mapping.
# Default to node user (1000) if not specified.
TARGET_UID="${HOST_UID:-1000}"
TARGET_GID="${HOST_GID:-1000}"

if [ "$TARGET_UID" != "1000" ]; then
  usermod -u "$TARGET_UID" node 2>/dev/null || true
  groupmod -g "$TARGET_GID" node 2>/dev/null || true
  chown -R node:node /home/node 2>/dev/null || true
fi

# --- Build TypeScript ---
cd /app && npx tsc --outDir /tmp/dist 2>&1 >&2
ln -s /app/node_modules /tmp/dist/node_modules
chmod -R a-w /tmp/dist

# --- Read input ---
cat > /tmp/input.json
chown node:node /tmp/input.json

# --- Drop to node user for agent execution ---
exec su -s /bin/bash node -c "node /tmp/dist/index.js < /tmp/input.json"
