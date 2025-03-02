#!/bin/bash

# ================ COLOR DEFINITIONS ================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ================ GLOBAL VARIABLES ================
installed=false
server_ip=$(curl -s ipv4.icanhazip.com)
server_port=443
dest_server="www.microsoft.com"
uuid=$(cat /proc/sys/kernel/random/uuid)
private_key=""
public_key=""
fingerprint="chrome"
use_fake_dns=true
short_id=$(openssl rand -hex 8)  # Generate random 8-byte shortID

# === MULTIPLE USER SUPPORT ===
# Variables to store users (compatible with bash)
user_uuids=("$uuid")
user_names=("Default User")

# ================ UTILITY FUNCTIONS ================
# Function to display a nice banner
display_banner() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                   ║${NC}"
    echo -e "${BLUE}║${NC}  ${MAGENTA}Xray VLESS + XTLS Reality Setup Script${NC}  ${BLUE}║${NC}"
    echo -e "${BLUE}║                                                   ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${NC}"
    echo
}

# Function to check if Xray is already installed
check_installation() {
    echo -e "${BLUE}Checking if Xray is already installed...${NC}"
    if command -v xray > /dev/null 2>&1; then
        echo -e "${GREEN}Xray is already installed.${NC}"
        installed=true
        
        # If installed, try to read existing config to get current values
        if [ -f "/usr/local/etc/xray/config.json" ]; then
            read_existing_config
        fi
    else
        echo -e "${YELLOW}Xray is not installed.${NC}"
        installed=false
    fi
}

# Function to read existing configuration
read_existing_config() {
    if command -v jq > /dev/null 2>&1; then
        if [ -f "/usr/local/etc/xray/config.json" ]; then
            # Try to extract values from config
            local config_file="/usr/local/etc/xray/config.json"
            
            # Extract port
            local config_port=$(jq -r '.inbounds[0].port' "$config_file" 2>/dev/null)
            if [ ! -z "$config_port" ] && [ "$config_port" != "null" ]; then
                server_port=$config_port
            fi
            
            # Extract destination
            local config_dest=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$config_file" 2>/dev/null | cut -d':' -f1)
            if [ ! -z "$config_dest" ] && [ "$config_dest" != "null" ]; then
                dest_server=$config_dest
            fi
            
            # Extract private key
            local config_private_key=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$config_file" 2>/dev/null)
            if [ ! -z "$config_private_key" ] && [ "$config_private_key" != "null" ]; then
                private_key=$config_private_key
                # Generate public key from private key if possible
                if command -v xray > /dev/null 2>&1; then
                    public_key=$(echo $private_key | xray x25519 -i)
                fi
            fi
            
            # Extract shortId
            local config_short_id=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$config_file" 2>/dev/null)
            if [ ! -z "$config_short_id" ] && [ "$config_short_id" != "null" ] && [ "$config_short_id" != "" ]; then
                short_id=$config_short_id
            fi
            
            # Check if using FakeDNS
            if jq -e '.dns.fakeIP.enabled' "$config_file" > /dev/null 2>&1; then
                use_fake_dns=true
            else
                use_fake_dns=false
            fi
            
            # Extract UUIDs and try to match with user names from current config
            local uuids=$(jq -r '.inbounds[0].settings.clients[].id' "$config_file" 2>/dev/null)
            if [ ! -z "$uuids" ]; then
                # Clear the current arrays to rebuild them
                user_uuids=()
                user_names=()
                
                # For each UUID in the config
                local i=0
                while read -r line; do
                    user_uuids+=("$line")
                    user_names+=("User-$i")  # Default name format
                    ((i++))
                done <<< "$uuids"
            fi
        fi
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    apt update
    apt install -y curl wget unzip jq openssl net-tools
    echo -e "${GREEN}Dependencies installed.${NC}"
}

# Function to install Xray
install_xray() {
    echo -e "${BLUE}Installing Xray...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    echo -e "${GREEN}Xray installed successfully.${NC}"
    installed=true
}

# Function to generate Reality keys
generate_keys() {
    echo -e "${BLUE}Generating Reality keys...${NC}"
    local key_output=$(xray x25519)
    private_key=$(echo "$key_output" | grep "Private key:" | cut -d : -f 2 | tr -d ' ')
    public_key=$(echo "$key_output" | grep "Public key:" | cut -d : -f 2 | tr -d ' ')
    echo -e "${GREEN}Keys generated successfully.${NC}"
    echo -e "${CYAN}Private key: ${NC}${private_key}"
    echo -e "${CYAN}Public key: ${NC}${public_key}"
}

# Function to generate shortID
generate_short_id() {
    echo -e "${BLUE}Generating new shortID...${NC}"
    short_id=$(openssl rand -hex 8)
    echo -e "${GREEN}ShortID generated: ${NC}${short_id}"
}

# Function to restart Xray
restart_xray() {
    echo -e "${BLUE}Restarting Xray service...${NC}"
    systemctl restart xray
    
    # Check if restart was successful
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}Xray service restarted successfully.${NC}"
    else
        echo -e "${RED}Failed to restart Xray. Checking for errors...${NC}"
        journalctl -xeu xray --no-pager | tail -n 20
    fi
}

# Function to display Xray service status
display_status() {
    echo -e "${YELLOW}========== XRAY SERVICE STATUS ============${NC}"
    systemctl status xray --no-pager
    echo
    echo -e "${YELLOW}Recent logs:${NC}"
    journalctl -u xray --no-pager | tail -n 10
    echo -e "${YELLOW}==========================================${NC}"
}

# Function to change SNI destination
change_sni() {
    display_banner
    echo -e "${CYAN}Current SNI Destination: ${NC}${dest_server}"
    echo
    echo -e "${YELLOW}Popular destinations:${NC}"
    echo -e "1) www.microsoft.com"
    echo -e "2) www.apple.com"
    echo -e "3) www.amazon.com"
    echo -e "4) www.cloudflare.com"
    echo -e "5) www.google.com"
    echo -e "6) www.ayoba.me"
    echo -e "7) www.facebook.com"
    echo -e "8) www.whatsapp.com"
    echo -e "9) www.mtnhoods.com"
    echo -e "10) Custom domain"
    echo
    read -p "Enter your choice [1-10]: " sni_choice
    
    case $sni_choice in
        1) dest_server="www.microsoft.com" ;;
        2) dest_server="www.apple.com" ;;
        3) dest_server="www.amazon.com" ;;
        4) dest_server="www.cloudflare.com" ;;
        5) dest_server="www.google.com" ;;
        6) dest_server="www.ayoba.me" ;;
        7) dest_server="www.facebook.com" ;;
        8) dest_server="www.whatsapp.com" ;;
        9) dest_server="www.mtnhoods.com" ;;
        10)
            read -p "Enter custom domain (without https://): " custom_domain
            if [ -n "$custom_domain" ]; then
                dest_server="$custom_domain"
            else
                echo -e "${RED}Invalid domain. Using default.${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid choice. Keeping current setting.${NC}"
            ;;
    esac
    
    echo -e "${GREEN}SNI Destination set to: ${NC}${dest_server}"
    read -p "Press Enter to continue..."
}

# Function to change server port
change_port() {
    display_banner
    echo -e "${CYAN}Current Port: ${NC}${server_port}"
    echo
    read -p "Enter new port (1-65535): " new_port
    
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
        # Check if port is already in use
        if netstat -tuln | grep -q ":$new_port "; then
            echo -e "${RED}Port $new_port is already in use by another service.${NC}"
            echo -e "${YELLOW}Do you want to use this port anyway? (y/n): ${NC}"
            read force_port
            if [[ ! "$force_port" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}Port change cancelled.${NC}"
                read -p "Press Enter to continue..."
                return
            fi
        fi
        
        server_port="$new_port"
        echo -e "${GREEN}Port set to: ${NC}${server_port}"
    else
        echo -e "${RED}Invalid port. Keeping current setting.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to toggle FakeDNS
toggle_fake_dns() {
    display_banner
    echo -e "${CYAN}Current DNS Mode: ${NC}$(if [ "$use_fake_dns" = true ]; then echo -e "${GREEN}FakeDNS Enabled${NC}"; else echo -e "${YELLOW}Standard DNS${NC}"; fi)"
    echo
    echo -e "${YELLOW}1)${NC} Use FakeDNS (better for bypassing DNS blocking)"
    echo -e "${YELLOW}2)${NC} Use Standard DNS configuration"
    echo
    read -p "Enter your choice [1-2]: " dns_choice
    
    case $dns_choice in
        1)
            use_fake_dns=true
            echo -e "${GREEN}FakeDNS mode enabled.${NC}"
            ;;
        2)
            use_fake_dns=false
            echo -e "${YELLOW}Standard DNS mode enabled.${NC}"
            ;;
        *)
            echo -e "${RED}Invalid choice. Keeping current setting.${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# Function to manage shortID
manage_short_id() {
    display_banner
    echo -e "${CYAN}Current ShortID: ${NC}${short_id}"
    echo
    echo -e "${YELLOW}1)${NC} Generate new random ShortID"
    echo -e "${YELLOW}2)${NC} Enter custom ShortID"
    echo -e "${YELLOW}3)${NC} Back to main menu"
    echo
    read -p "Enter your choice [1-3]: " sid_choice
    
    case $sid_choice in
        1)
            generate_short_id
            ;;
        2)
            read -p "Enter custom ShortID (hexadecimal, max 16 chars): " custom_sid
            if [[ "$custom_sid" =~ ^[0-9a-fA-F]{1,16}$ ]]; then
                short_id="$custom_sid"
                echo -e "${GREEN}ShortID set to: ${NC}${short_id}"
            else
                echo -e "${RED}Invalid format. ShortID must be hexadecimal and max 16 characters.${NC}"
                echo -e "${YELLOW}Keeping current ShortID.${NC}"
            fi
            ;;
        3)
            return
            ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# Function to regenerate Reality keys
regenerate_keys() {
    display_banner
    echo -e "${YELLOW}Warning: Regenerating keys will require all clients to update their configurations.${NC}"
    read -p "Are you sure you want to regenerate keys? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        generate_keys
    else
        echo -e "${GREEN}Key regeneration cancelled.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to manage users
manage_users() {
    display_banner
    echo -e "${CYAN}User Management${NC}"
    echo -e "${YELLOW}Current Users:${NC}"
    
    # Display all users
    local i=0
    while [ $i -lt ${#user_uuids[@]} ]; do
        echo -e "${YELLOW}$((i+1)))${NC} ${user_names[$i]} - ${CYAN}UUID:${NC} ${user_uuids[$i]}"
        ((i++))
    done
    
    echo
    echo -e "${YELLOW}a)${NC} Add new user"
    echo -e "${YELLOW}d)${NC} Delete user"
    echo -e "${YELLOW}r)${NC} Rename user"
    echo -e "${YELLOW}b)${NC} Back to main menu"
    echo
    
    read -p "Enter your choice: " user_choice
    
    case $user_choice in
        a)
            add_user
            ;;
        d)
            delete_user
            ;;
        r)
            rename_user
            ;;
        b)
            return
            ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
    manage_users
}

# Function to add a new user
add_user() {
    local new_uuid=$(cat /proc/sys/kernel/random/uuid)
    read -p "Enter name for new user: " user_name
    
    if [ -z "$user_name" ]; then
        user_name="User-$(date +%s)"
    fi
    
    user_uuids+=("$new_uuid")
    user_names+=("$user_name")
    echo -e "${GREEN}New user added:${NC}"
    echo -e "${CYAN}Name:${NC} $user_name"
    echo -e "${CYAN}UUID:${NC} $new_uuid"
}

# Function to delete a user
delete_user() {
    if [ ${#user_uuids[@]} -le 1 ]; then
        echo -e "${RED}Cannot delete the last user.${NC}"
        return
    fi
    
    echo -e "${YELLOW}Select user to delete:${NC}"
    local i=0
    while [ $i -lt ${#user_uuids[@]} ]; do
        echo -e "${YELLOW}$((i+1)))${NC} ${user_names[$i]} - ${CYAN}UUID:${NC} ${user_uuids[$i]}"
        ((i++))
    done
    
    read -p "Enter number of user to delete: " user_number
    
    if [[ "$user_number" =~ ^[0-9]+$ ]] && [ "$user_number" -ge 1 ] && [ "$user_number" -le "${#user_uuids[@]}" ]; then
        local delete_index=$((user_number-1))
        local delete_name="${user_names[$delete_index]}"
        local delete_uuid="${user_uuids[$delete_index]}"
        
        # Remove the user from arrays
        user_names=("${user_names[@]:0:$delete_index}" "${user_names[@]:$((delete_index+1))}")
        user_uuids=("${user_uuids[@]:0:$delete_index}" "${user_uuids[@]:$((delete_index+1))}")
        
        echo -e "${GREEN}User '$delete_name' with UUID '$delete_uuid' deleted.${NC}"
    else
        echo -e "${RED}Invalid selection.${NC}"
    fi
}

# Function to rename a user
rename_user() {
    echo -e "${YELLOW}Select user to rename:${NC}"
    local i=0
    while [ $i -lt ${#user_uuids[@]} ]; do
        echo -e "${YELLOW}$((i+1)))${NC} ${user_names[$i]} - ${CYAN}UUID:${NC} ${user_uuids[$i]}"
        ((i++))
    done
    
    read -p "Enter number of user to rename: " user_number
    
    if [[ "$user_number" =~ ^[0-9]+$ ]] && [ "$user_number" -ge 1 ] && [ "$user_number" -le "${#user_uuids[@]}" ]; then
        local rename_index=$((user_number-1))
        read -p "Enter new name for ${user_names[$rename_index]}: " new_name
        
        if [ -n "$new_name" ]; then
            local old_name="${user_names[$rename_index]}"
            user_names[$rename_index]="$new_name"
            echo -e "${GREEN}User renamed from '$old_name' to '$new_name'.${NC}"
        else
            echo -e "${RED}Name cannot be empty.${NC}"
        fi
    else
        echo -e "${RED}Invalid selection.${NC}"
    fi
}

# Function to change TLS fingerprint
change_fingerprint() {
    display_banner
    echo -e "${CYAN}Current TLS Fingerprint: ${NC}${fingerprint}"
    echo
    echo -e "${YELLOW}Available Fingerprints:${NC}"
    echo -e "${YELLOW}1)${NC} chrome (Default)"
    echo -e "${YELLOW}2)${NC} firefox"
    echo -e "${YELLOW}3)${NC} safari"
    echo -e "${YELLOW}4)${NC} ios"
    echo -e "${YELLOW}5)${NC} android"
    echo -e "${YELLOW}6)${NC} edge"
    echo -e "${YELLOW}7)${NC} 360"
    echo -e "${YELLOW}8)${NC} qq"
    echo -e "${YELLOW}9)${NC} random"
    echo -e "${YELLOW}10)${NC} Back to main menu"
    echo
    
    read -p "Enter your choice [1-10]: " fp_choice
    
    case $fp_choice in
        1) fingerprint="chrome" ;;
        2) fingerprint="firefox" ;;
        3) fingerprint="safari" ;;
        4) fingerprint="ios" ;;
        5) fingerprint="android" ;;
        6) fingerprint="edge" ;;
        7) fingerprint="360" ;;
        8) fingerprint="qq" ;;
        9) fingerprint="random" ;;
        10) return ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            read -p "Press Enter to continue..."
            change_fingerprint
            return
            ;;
    esac
    
    echo -e "${GREEN}TLS Fingerprint set to: ${NC}${fingerprint}"
    read -p "Press Enter to continue..."
}

# Function to configure firewall (UFW)
configure_firewall() {
    display_banner
    echo -e "${BLUE}Firewall Configuration${NC}"
    
    # Check if UFW is installed
    if ! command -v ufw > /dev/null 2>&1; then
        echo -e "${YELLOW}UFW not found. Installing...${NC}"
        apt update
        apt install -y ufw
    fi
    
    # Check UFW status
    ufw_status=$(ufw status | grep "Status: " | cut -d ' ' -f2)
    
    echo -e "${YELLOW}Current UFW Status: ${NC}${ufw_status}"
    echo -e "${YELLOW}Xray Port: ${NC}${server_port}"
    echo
    echo -e "${YELLOW}1)${NC} Allow Xray port"
    echo -e "${YELLOW}2)${NC} Enable UFW"
    echo -e "${YELLOW}3)${NC} Disable UFW"
    echo -e "${YELLOW}4)${NC} Show UFW status"
    echo -e "${YELLOW}5)${NC} Back to main menu"
    echo
    
    read -p "Enter your choice [1-5]: " fw_choice
    
    case $fw_choice in
        1)
            echo -e "${BLUE}Configuring UFW for Xray port ${server_port}...${NC}"
            ufw allow ssh comment 'SSH access'
            ufw allow ${server_port}/tcp comment 'Xray VLESS'
            echo -e "${GREEN}Firewall rules added for port ${server_port}.${NC}"
            ;;
        2)
            if [ "$ufw_status" != "active" ]; then
                echo -e "${YELLOW}Warning: This might disconnect your SSH session if port 22 is not allowed.${NC}"
                read -p "Are you sure you want to enable UFW? (y/n): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    ufw allow ssh comment 'SSH access'
                    ufw --force enable
                    echo -e "${GREEN}UFW enabled.${NC}"
                fi
            else
                echo -e "${YELLOW}UFW is already enabled.${NC}"
            fi
            ;;
        3)
            if [ "$ufw_status" = "active" ]; then
                ufw disable
                echo -e "${GREEN}UFW disabled.${NC}"
            else
                echo -e "${YELLOW}UFW is already disabled.${NC}"
            fi
            ;;
        4)
            ufw status verbose
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
    configure_firewall
}

# Function to uninstall Xray
uninstall_xray() {
    display_banner
    echo -e "${RED}WARNING: This will completely remove Xray from your system.${NC}"
    read -p "Are you sure you want to continue? (y/n): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Uninstallation cancelled.${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -e "${BLUE}Stopping Xray service...${NC}"
    systemctl stop xray
    systemctl disable xray
    
    echo -e "${BLUE}Removing Xray files...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
    
    echo -e "${BLUE}Removing configuration files...${NC}"
    rm -rf /usr/local/etc/xray
    
    echo -e "${BLUE}Removing firewall rules...${NC}"
    if command -v ufw > /dev/null 2>&1; then
        ufw delete allow ${server_port}/tcp
    fi
    
    installed=false
    echo -e "${GREEN}Xray successfully uninstalled from the system.${NC}"
    read -p "Press Enter to continue..."
}

# Function to check for Xray updates
check_updates() {
    display_banner
    echo -e "${BLUE}Checking for Xray updates...${NC}"
    
    # Get current installed version
    current_version=$(xray -version | head -n1 | cut -d ' ' -f2)
    
    # Get latest version from GitHub
    latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    echo -e "${CYAN}Current version: ${NC}${current_version}"
    echo -e "${CYAN}Latest version: ${NC}${latest_version}"
    
    if [ "$current_version" = "$latest_version" ]; then
        echo -e "${GREEN}You have the latest version of Xray installed.${NC}"
    else
        echo -e "${YELLOW}A new version of Xray is available.${NC}"
        read -p "Do you want to update? (y/n): " update_choice
        
        if [[ "$update_choice" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Updating Xray...${NC}"
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
            echo -e "${GREEN}Xray updated successfully.${NC}"
            restart_xray
        fi
    fi
    
    read -p "Press Enter to continue..."
}

# Modified function to create Xray configuration with FakeDNS option
create_config() {
    echo -e "${BLUE}Creating Xray configuration file...${NC}"
    
    # Build clients array for config
    local clients_config=""
    local i=0
    
    while [ $i -lt ${#user_uuids[@]} ]; do
        if [ $i -gt 0 ]; then
            clients_config="${clients_config},"
        fi
        
        clients_config="${clients_config}
          {
            \"id\": \"${user_uuids[$i]}\",
            \"flow\": \"xtls-rprx-vision\"
          }"
        
        ((i++))
    done
    
    # Create directory if it doesn't exist
    mkdir -p /usr/local/etc/xray
    
    # Create config based on selected DNS mode
    if [ "$use_fake_dns" = true ]; then
        # FakeDNS config
        cat > /usr/local/etc/xray/config.json << EOF
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
      "port": ${server_port},
      "protocol": "vless",
      "settings": {
        "clients": [${clients_config}
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
            "${dest_server}",
            "web.${dest_server}"
          ],
          "privateKey": "${private_key}",
          "shortIds": ["${short_id}"]
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
    else
        # Standard config
        cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "https+local://1.1.1.1/dns-query",
      "8.8.8.8",
      "1.1.1.1"
    ]
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${server_port},
      "protocol": "vless",
      "settings": {
        "clients": [${clients_config}
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
            "${dest_server}",
            "web.${dest_server}"
          ],
          "privateKey": "${private_key}",
          "shortIds": ["${short_id}"]
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
    "domainStrategy": "AsIs",
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
    fi
    echo -e "${GREEN}Configuration file created at /usr/local/etc/xray/config.json${NC}"
}

# Function to generate client configuration
generate_client_config() {
    display_banner
    echo -e "${BLUE}Client Configuration${NC}"
    
    # Display all users to select from
    echo -e "${YELLOW}Select user to generate configuration for:${NC}"
    local i=0
    while [ $i -lt ${#user_uuids[@]} ]; do
        echo -e "${YELLOW}$((i+1)))${NC} ${user_names[$i]}"
        ((i++))
    done
    
    read -p "Enter user number: " user_number
    
    if [[ "$user_number" =~ ^[0-9]+$ ]] && [ "$user_number" -ge 1 ] && [ "$user_number" -le "${#user_uuids[@]}" ]; then
        local user_index=$((user_number-1))
        local user_uuid="${user_uuids[$user_index]}"
        local user_name="${user_names[$user_index]}"
        
        # Create share link
        local vless_link="vless://${user_uuid}@${server_ip}:${server_port}?security=reality&encryption=none&pbk=${public_key}&headerType=none&fp=${fingerprint}&type=tcp&flow=xtls-rprx-vision&sni=${dest_server}&sid=${short_id}#${user_name}-Reality"
        
        # Display configurations
        echo -e "${GREEN}VLESS-Reality Configuration for ${user_name}:${NC}"
        echo -e "${CYAN}Address:${NC} ${server_ip}"
        echo -e "${CYAN}Port:${NC} ${server_port}"
        echo -e "${CYAN}UUID:${NC} ${user_uuid}"
        echo -e "${CYAN}SNI:${NC} ${dest_server}"
        echo -e "${CYAN}Public Key:${NC} ${public_key}"
        echo -e "${CYAN}ShortID:${NC} ${short_id}"
        echo -e "${CYAN}Fingerprint:${NC} ${fingerprint}"
        echo -e "${CYAN}Flow:${NC} xtls-rprx-vision"
        echo
        echo -e "${CYAN}Share Link:${NC}"
        echo -e "${vless_link}"
        
        # Generate QR code for the link if qrencode is installed
        if command -v qrencode > /dev/null 2>&1; then
            echo -e "${YELLOW}QR Code:${NC}"
            qrencode -t ANSIUTF8 "${vless_link}"
        else
            echo -e "${YELLOW}Install qrencode for QR code display:${NC} apt install qrencode"
        fi
        
        # Save to file option
        echo
        read -p "Save config to file? (y/n): " save_choice
        if [[ "$save_choice" =~ ^[Yy]$ ]]; then
            mkdir -p /root/vless_configs
            config_file="/root/vless_configs/${user_name}-config.txt"
            
            cat > "${config_file}" << EOF
==== ${user_name} VLESS-Reality Configuration ====
Address: ${server_ip}
Port: ${server_port}
UUID: ${user_uuid}
SNI: ${dest_server}
Public Key: ${public_key}
ShortID: ${short_id}
Fingerprint: ${fingerprint}
Flow: xtls-rprx-vision

Share Link:
${vless_link}
EOF
            echo -e "${GREEN}Configuration saved to ${config_file}${NC}"
        fi
    else
        echo -e "${RED}Invalid selection.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to display main menu
main_menu() {
    while true; do
        display_banner
        
        if [ "$installed" = false ]; then
            echo -e "${YELLOW}Xray is not installed. Some options will not be available.${NC}"
            echo
        else
            echo -e "${GREEN}Xray is installed and running.${NC}"
            echo -e "${CYAN}Current Configuration:${NC}"
            echo -e "  ${YELLOW}Server:${NC} ${server_ip}:${server_port}"
            echo -e "  ${YELLOW}SNI:${NC} ${dest_server}"
            echo -e "  ${YELLOW}DNS Mode:${NC} $(if [ "$use_fake_dns" = true ]; then echo -e "FakeDNS"; else echo -e "Standard DNS"; fi)"
            echo -e "  ${YELLOW}Users:${NC} ${#user_uuids[@]}"
            echo
        fi
        
        echo -e "${BLUE}╔════════════════ MENU ════════════════╗${NC}"
        
        if [ "$installed" = false ]; then
            echo -e "${BLUE}║${NC} ${YELLOW}1)${NC} Install Xray with Reality          ${BLUE}║${NC}"
        else
            echo -e "${BLUE}║${NC} ${YELLOW}1)${NC} Update Configuration               ${BLUE}║${NC}"
        fi
        
        echo -e "${BLUE}║${NC} ${YELLOW}2)${NC} Change SNI Destination             ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC} ${YELLOW}3)${NC} Change Server Port                 ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC} ${YELLOW}4)${NC} Toggle FakeDNS/Standard DNS        ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC} ${YELLOW}5)${NC} Manage ShortID                     ${BLUE}║${NC}"
        
        if [ "$installed" = true ]; then
            echo -e "${BLUE}║${NC} ${YELLOW}6)${NC} Regenerate Reality Keys            ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}7)${NC} Generate Client Configuration      ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}8)${NC} Manage Users                       ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}9)${NC} Change TLS Fingerprint             ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}10)${NC} Configure Firewall                ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}11)${NC} View Xray Status                  ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}12)${NC} Restart Xray                      ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}13)${NC} Check for Updates                 ${BLUE}║${NC}"
            echo -e "${BLUE}║${NC} ${YELLOW}14)${NC} Uninstall Xray                    ${BLUE}║${NC}"
        fi
        
        echo -e "${BLUE}║${NC} ${YELLOW}0)${NC} Exit                               ${BLUE}║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
        echo
        read -p "Enter your choice: " choice
        
        case $choice in
            0)
                clear
                echo -e "${GREEN}Thank you for using Xray Reality Setup Script!${NC}"
                exit 0
                ;;
            1)
                if [ "$installed" = false ]; then
                    # Full installation process
                    install_dependencies
                    install_xray
                    generate_keys
                    create_config
                    restart_xray
                    echo -e "${GREEN}Xray with Reality has been successfully installed!${NC}"
                    read -p "Press Enter to continue..."
                else
                    # Just update configuration
                    create_config
                    restart_xray
                    echo -e "${GREEN}Configuration updated!${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            2)
                change_sni
                ;;
            3)
                change_port
                ;;
            4)
                toggle_fake_dns
                ;;
            5)
                manage_short_id
                ;;
            6)
                if [ "$installed" = true ]; then
                    regenerate_keys
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            7)
                if [ "$installed" = true ]; then
                    generate_client_config
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            8)
                if [ "$installed" = true ]; then
                    manage_users
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            9)
                if [ "$installed" = true ]; then
                    change_fingerprint
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            10)
                if [ "$installed" = true ]; then
                    configure_firewall
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            11)
                if [ "$installed" = true ]; then
                    display_status
                    read -p "Press Enter to continue..."
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            12)
                if [ "$installed" = true ]; then
                    restart_xray
                    read -p "Press Enter to continue..."
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            13)
                if [ "$installed" = true ]; then
                    check_updates
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            14)
                if [ "$installed" = true ]; then
                    uninstall_xray
                else
                    echo -e "${RED}Xray is not installed yet.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Main execution
check_installation
main_menu
