#!/bin/bash
# Xray + XTLS + Reality + Fake DNS Setup Script for Ubuntu

# Step 1: Update system and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl socat unzip wget jq

# Step 2: Install Xray Core
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Step 3: Generate Reality keys
x25519_keys=$(xray x25519)
private_key=$(echo "$x25519_keys" | grep "Private key" | cut -d ' ' -f3)
public_key=$(echo "$x25519_keys" | grep "Public key" | cut -d ' ' -f3)

# Step 4: Set up configuration variables
dest_server="www.whatsapp.com"
server_ip=$(curl -s ifconfig.me)
uuid=$(cat /proc/sys/kernel/random/uuid)

# Step 5: Create Xray configuration file with Fake DNS
cat << EOF > /usr/local/etc/xray/config.json
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      {
        "address": "https+local://1.1.1.1/dns-query",
        "domains": ["geosite:geolocation-!cn"]
      },
      {
        "address": "8.8.8.8",
        "domains": ["geosite:geolocation-!cn"]
      }
    ],
    "fakeIP": {
      "enabled": true,
      "ipPool": "198.18.0.0/16",
      "strategy": "use_ip"
    }
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${dest_server}:443",
          "xver": 0,
          "serverNames": [
            "www.whatsapp.com",
            "web.whatsapp.com"
          ],
          "privateKey": "${private_key}",
          "shortIds": [""]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": {
        "domainStrategy": "UseIP"
      }
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private", "geoip:cn"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

# Step 6: Restart and Enable Xray service
systemctl restart xray
systemctl enable xray

# Step 7: Display Client Configuration
echo "=========== CONFIGURATION INFO ============="
echo "Server IP: ${server_ip}"
echo "Port: 443"
echo "Protocol: VLESS"
echo "ID (UUID): ${uuid}"
echo "Flow: xtls-rprx-vision"
echo "Network: tcp"
echo "Security: reality"
echo "SNI: www.whatsapp.com"
echo "Fingerprint: chrome"
echo "Public Key: ${public_key}"
echo "============================================"
echo "Use the above info to configure your client (v2rayNG, Nekoray, etc.)"

# Step 8: Verify Xray Status
systemctl status xray --no-pager

# Step 9: Display Fake DNS Information
echo "=========== FAKE DNS INFO =================="
echo "Fake DNS has been enabled with the following settings:"
echo "- DNS Servers: Cloudflare DNS-over-HTTPS (1.1.1.1), Google DNS (8.8.8.8)"
echo "- Fake IP Pool: 198.18.0.0/16"
echo "- Domain Strategy: IPIfNonMatch with UseIP for outbound connections"
echo "============================================"
