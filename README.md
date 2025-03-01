# Xray-XTLS-Reality-Fake-DNS

A streamlined bash script for setting up Xray with XTLS, Reality protocol, and Fake DNS functionality on Ubuntu servers.

## Features

- **Xray Core** - The latest version of Xray-core is installed automatically
- **XTLS-Vision** - Utilizes the high-performance XTLS-Vision flow
- **Reality Protocol** - Advanced TLS fingerprinting evasion with server name validation
- **Fake DNS** - Prevents DNS leaks by routing all DNS queries through private IPs
- **Auto-configuration** - Automatically generates all necessary keys and identifiers
- **Client-ready Output** - Displays all information needed to configure clients

## Requirements

- Ubuntu server (18.04 LTS or newer recommended)
- Root privileges
- Open port 443 (TCP)

## Quick Installation

```bash
# Download the script
wget https://raw.githubusercontent.com/AtizaD/Xray-XTLS-Reality-Fake-DNS/main/setup.sh

# Make it executable
chmod +x setup.sh

# Run the script
sudo ./setup.sh
```

## What the Script Does

1. Updates the system and installs dependencies
2. Installs the latest version of Xray Core
3. Generates X25519 keypair for the Reality protocol
4. Configures Xray with VLESS + TCP + XTLS-Vision + Reality
5. Sets up Fake DNS to prevent DNS leaks
6. Configures routing rules to block connections to private IPs and China
7. Starts and enables the Xray service
8. Displays all information needed for client configuration

## Client Configuration

After running the script, you'll receive all the necessary information to configure your client applications:

- Server IP
- Port: 443
- Protocol: VLESS
- UUID
- Flow: xtls-rprx-vision
- Network: tcp
- Security: reality
- SNI: www.whatsapp.com
- Fingerprint: chrome
- Public Key

## Compatible Clients

This setup works with various clients that support Xray with Reality protocol:

- v2rayN (Windows)
- v2rayNG (Android)
- Nekoray (Cross-platform)
- Shadowrocket (iOS)
- V2Box (iOS)
- Sing-box (Cross-platform)

## Fake DNS Functionality

The Fake DNS feature intercepts DNS requests and returns virtual IP addresses from a private range (198.18.0.0/16). This helps:

- Prevent DNS leaks
- Ensure all traffic goes through the proxy
- Improve security by using trusted DNS providers (Cloudflare and Google)

## Security Considerations

- The script blocks connections to private IP ranges and China IP ranges
- All DNS queries are handled securely through Cloudflare DNS-over-HTTPS or Google DNS
- The Reality protocol verifies server names to prevent MITM attacks

## Troubleshooting

If you encounter issues after installation:

1. Check the Xray service status:
   ```
   systemctl status xray
   ```

2. View the Xray logs:
   ```
   journalctl -u xray -f
   ```

3. Verify that port 443 is open:
   ```
   lsof -i :443
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is designed for legitimate privacy protection and secure communication. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.
