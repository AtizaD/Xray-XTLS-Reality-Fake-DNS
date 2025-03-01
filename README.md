# Xray XTLS Reality with Fake DNS

A powerful setup script for creating a high-security, DPI-resistant proxy server using Xray with XTLS Reality protocol and Fake DNS technology.

## Features

- **XTLS Reality Protocol**: Advanced security using Reality protocol for superior traffic obfuscation
- **Vision Flow**: Implements the optimized `xtls-rprx-vision` flow for better performance and security
- **Fake DNS System**: Prevents DNS-based tracking, censorship, and DPI detection
- **Automated Setup**: One-click installation and configuration on Ubuntu systems
- **DPI Evasion**: Multiple layers of protection against Deep Packet Inspection
- **Domain Fronting**: Appears as legitimate traffic to common websites

## Requirements

- Ubuntu server (18.04+)
- Root access
- Open port 443 (configurable)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/AtizaD/Xray-XTLS-Reality-Fake-DNS.git
cd Xray-XTLS-Reality-Fake-DNS
```

2. Make the script executable:
```bash
chmod +x setup.sh
```

3. Run the setup script:
```bash
sudo ./setup.sh
```

4. Take note of the configuration information displayed after installation

## Client Configuration

After running the script, you'll receive configuration details similar to:

```
=========== CONFIGURATION INFO =============
Server IP: 123.456.789.0
Port: 443
Protocol: VLESS
ID (UUID): 00000000-0000-0000-0000-000000000000
Flow: xtls-rprx-vision
Network: tcp
Security: reality
SNI: www.whatsapp.com
Fingerprint: chrome
Public Key: abcdefghijklmnopqrstuvwxyz123456
============================================
```

Enter these details into compatible clients:
- v2rayN (Windows)
- v2rayNG (Android)
- Nekoray (Cross-platform)
- Shadowrocket (iOS)

## How It Works

### Reality Protocol
Reality implements a next-generation TLS obfuscation that creates truly indistinguishable traffic patterns from legitimate websites.

### Fake DNS
The Fake DNS system intercepts DNS queries and:
- Routes them through encrypted channels
- Uses a private IP pool for domain resolution
- Prevents DNS-based censorship and logging

### Anti-DPI Measures
- Domain fronting through WhatsApp SNI
- TCP with XTLS-Vision for optimized traffic patterns
- IP-based routing strategies that prevent domain resolution leaks

## Advanced Configuration

The default setup uses `www.whatsapp.com` as the target domain. To change this or other settings, edit the script before running, or modify `/usr/local/etc/xray/config.json` after installation.

## Troubleshooting

If you encounter issues:

1. Check Xray status:
```bash
systemctl status xray
```

2. View logs:
```bash
journalctl -u xray --no-pager
```

3. Verify configuration:
```bash
xray -test -config /usr/local/etc/xray/config.json
```

## Security Considerations

- This setup helps evade DPI but is not guaranteed to work against all censorship systems
- Keep your client configuration private
- Regularly update the Xray core: `bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install`

## License

MIT License

## Acknowledgments

- [Xray-core Project](https://github.com/XTLS/Xray-core)
- [Project X Community](https://github.com/XTLS)
