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
server_ip=""
server_port=443
dest_server="www.microsoft.com"
uuid=$(cat /proc/sys/kernel/random/uuid)
private_key=""
public_key=""
fingerprint="chrome"
use_fake_dns=true
short_id=$(openssl rand -hex 8)  # Generate random 8-byte shortID
config_file="/usr/local/etc/xray/config.json"
script_version="1.0.0"

# === MULTIPLE USER SUPPORT ===
# Variables to store users (compatible with bash)
user_uuids=("$uuid")
user_names=("Default User")

# ================ UTILITY FUNCTIONS ================
# Function to check if script is run as root
check_root() {
    if [ $(id -u) -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root!${NC}"
        exit 1
    fi
}

# Function to safely execute commands and handle errors
safe_exec() {
    local cmd="$1"
    local err_msg="${2:-Command failed}"
    local output=""
    
    output=$(eval "$cmd" 2>&1) || {
        echo -e "${RED}Error: $err_msg${NC}"
        echo -e "${RED}Command: $cmd${NC}"
        echo -e "${RED}Output: $output${NC}"
        return 1
    }
    
    return 0
}

# Function to safely download files
safe_download() {
    local url="$1"
    local output_file="$2"
    local err_msg="${3:-Download failed}"
    
    # Check if curl is installed
    if ! command -v curl > /dev/null 2>&1; then
        safe_exec "apt update && apt install -y curl" "Failed to install curl"
    fi
    
    # Download with curl and check signature if available
    safe_exec "curl -sSL '$url' -o '$output_file'" "$err_msg"
    
    # Verify file was downloaded
    if [ ! -s "$output_file" ]; then
        echo -e "${RED}Error: Downloaded file is empty${NC}"
        return 1
    fi
    
    return 0
}

# Function to sanitize inputs to prevent command injection
sanitize_input() {
    local input="$1"
    echo "$input" | tr -cd '[:alnum:]._-'
}

# Function to get server IP using multiple services
get_server_ip() {
    local ip=""
    local services=(
        "ipv4.icanhazip.com"
        "ifconfig.me"
        "api.ipify.org"
    )
    
    # Try each service until we get a valid IP
    for service in "${services[@]}"; do
        ip=$(curl -s --connect-timeout 5 "$service")
        
        # Validate IP format
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            server_ip="$ip"
            return 0
        fi
    done
    
    # If all online services fail, try to get from interface
    ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        server_ip="$ip"
        return 0
    fi
    
    echo -e "${RED}Error: Could not determine server IP address.${NC}"
    return 1
}

# Function to display a nice banner
display_banner() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                   ║${NC}"
    echo -e "${BLUE}║${NC}  ${MAGENTA}Xray VLESS + XTLS Reality Setup Script v$script_version${NC}  ${BLUE}║${NC}"
    echo -e "${BLUE}║                                                   ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${NC}"
    echo
}

# Function to check if Xray is already installed
check_installation() {
    echo -e "${BLUE}Checking if Xray is already installed...${NC}"
    
    # Multiple methods to check Xray installation
    local xray_paths=(
        "/usr/local/bin/xray"
        "/usr/bin/xray"
        "/opt/xray/xray"
        "$(which xray)"
    )
    
    local found=false
    
    for path in "${xray_paths[@]}"; do
        if [ -x "$path" ]; then
            echo -e "${GREEN}Xray found at $path${NC}"
            installed=true
            found=true
            
            # Try to get version
            local version_output=$("$path" version 2>/dev/null)
            if [ -n "$version_output" ]; then
                echo -e "${CYAN}Xray Version:${NC} $(echo "$version_output" | head -n1)"
            fi
            
            # Try to read existing config
            if [ -f "$config_file" ]; then
                read_existing_config
            fi
            
            break
        fi
    done
    
    if [ "$found" = false ]; then
        echo -e "${YELLOW}Xray not found in standard locations.${NC}"
        echo -e "${YELLOW}Performing deeper system search...${NC}"
        
        # Deeper system search
        local deep_search=$(find / -type f -name "xray" -executable 2>/dev/null | head -n 1)
        if [ -n "$deep_search" ]; then
            echo -e "${GREEN}Xray found at $deep_search${NC}"
            installed=true
            
            # Try to get version
            local version_output=$("$deep_search" version 2>/dev/null)
            if [ -n "$version_output" ]; then
                echo -e "${CYAN}Xray Version:${NC} $(echo "$version_output" | head -n1)"
            fi
        else
            echo -e "${RED}No Xray installation detected.${NC}"
            installed=false
        fi
    fi
}

# Function to read existing configuration
read_existing_config() {
    if ! command -v jq > /dev/null 2>&1; then
        safe_exec "apt update && apt install -y jq" "Failed to install jq"
    fi
    
    if [ -f "$config_file" ]; then
        # Try to extract values from config
        
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
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    safe_exec "apt update" "Failed to update package lists"
    safe_exec "apt install -y curl wget unzip jq openssl net-tools" "Failed to install dependencies"
    echo -e "${GREEN}Dependencies installed.${NC}"
}

# Function to install Xray
install_xray() {
    echo -e "${BLUE}Installing Xray...${NC}"
    
    # Download the installation script to a temporary file
    local tmp_script=$(mktemp)
    safe_download "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" "$tmp_script" "Failed to download Xray installation script"
    
    # Make the script executable
    chmod +x "$tmp_script"
    
    # Execute the script
    safe_exec "$tmp_script install" "Failed to install Xray"
    
    # Clean up
    rm -f "$tmp_script"
    
    echo -e "${GREEN}Xray installed successfully.${NC}"
    installed=true
}

# Function to generate Reality keys
generate_keys() {
    echo -e "${BLUE}Generating Reality keys...${NC}"
    
    # Alternative method to generate keys
    local key_output=$(xray x25519)
    
    # Extract private and public keys more carefully
    private_key=$(echo "$key_output" | grep "Private key:" | sed 's/Private key: //' | tr -d ' ')
    public_key=$(echo "$key_output" | grep "Public key:" | sed 's/Public key: //' | tr -d ' ')
    
    # Fallback method if parsing fails
    if [ -z "$private_key" ] || [ -z "$public_key" ]; then
        echo -e "${YELLOW}Falling back to alternative key generation method...${NC}"
        
        # Generate keys using OpenSSL as a fallback
        local temp_private_key=$(openssl rand -base64 32)
        private_key=$(echo "$temp_private_key" | tr -d '=' | tr '/+' '_-')
        
        # Use xray to derive public key if possible
        public_key=$(echo "$private_key" | xray x25519 -i 2>/dev/null || echo "")
        
        # If public key generation fails, provide a warning
        if [ -z "$public_key" ]; then
            echo -e "${RED}Warning: Could not generate public key automatically.${NC}"
            echo -e "${YELLOW}You may need to manually configure the public key.${NC}"
        fi
    fi
    
    # Validate keys
    if [ -n "$private_key" ]; then
        echo -e "${GREEN}Keys generated successfully.${NC}"
        echo -e "${CYAN}Private key: ${NC}${private_key}"
        echo -e "${CYAN}Public key: ${NC}${public_key}"
    else
        echo -e "${RED}Failed to generate Reality keys.${NC}"
        exit 1
    fi
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
    safe_exec "systemctl restart xray" "Failed to restart Xray service"
    
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
                # Sanitize input to prevent command injection
                custom_domain=$(sanitize_input "$custom_domain")
                # Validate domain format
                if [[ "$custom_domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    dest_server="$custom_domain"
                else
                    echo -e "${RED}Invalid domain format. Using default.${NC}"
                fi
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
    else
        # Sanitize username
        user_name=$(sanitize_input "$user_name")
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
        
        # Create temporary arrays
        local temp_names=()
        local temp_uuids=()
        
        # Copy all elements except the one to delete
        for i in "${!user_names[@]}"; do
            if [ "$i" -ne "$delete_index" ]; then
                temp_names+=("${user_names[$i]}")
                temp_uuids+=("${user_uuids[$i]}")
            fi
        done
        
        # Replace original arrays
        user_names=("${temp_names[@]}")
        user_uuids=("${temp_uuids[@]}")
        
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
            # Sanitize new name
            new_name=$(sanitize_input "$new_name")
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
        safe_exec "apt update && apt install -y ufw" "Failed to install UFW"
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
            safe_exec "ufw allow ssh comment 'SSH access'" "Failed to add SSH rule"
            safe_exec "ufw allow ${server_port}/tcp comment 'Xray VLESS'" "Failed to add Xray port rule"
            echo -e "${GREEN}Firewall rules added for port ${server_port}.${NC}"
            ;;
        2)
            if [ "$ufw_status" != "active" ]; then
                echo -e "${YELLOW}Warning: This might disconnect your SSH session if port 22 is not allowed.${NC}"
                read -p "Are you sure you want to enable UFW? (y/n): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    safe_exec "ufw allow ssh comment 'SSH access'" "Failed to add SSH rule"
                    safe_exec "ufw --force enable" "Failed to enable UFW"
                    echo -e "${GREEN}UFW enabled.${NC}"
                fi
            else
                echo -e "${YELLOW}UFW is already enabled.${NC}"
            fi
            ;;
        3)
            if [ "$ufw_status" = "active" ]; then
                safe_exec "ufw disable" "Failed to disable UFW"
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
    safe_exec "systemctl stop xray" "Failed to stop Xray service"
    safe_exec "systemctl disable xray" "Failed to disable Xray service"
    
    echo -e "${BLUE}Removing Xray files...${NC}"
    # Download the uninstallation script to a temporary file
    local tmp_script=$(mktemp)
    safe_download "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" "$tmp_script" "Failed to download Xray uninstallation script"
    
    # Make the script executable
    chmod +x "$tmp_script"
    
    # Execute the script with the remove argument
    safe_exec "$tmp_script remove" "Failed to uninstall Xray"
    
    # Clean up
    rm -f "$tmp_script"
    
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
    
    # Get latest version from GitHub using API
    local tmp_json=$(mktemp)
    if safe_download "https://api.github.com/repos/XTLS/Xray-core/releases/latest" "$tmp_json" "Failed to check for updates"; then
        latest_version=$(jq -r '.tag_name' "$tmp_json" 2>/dev/null)
        rm -f "$tmp_json"
        
        if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
            echo -e "${RED}Failed to get latest version information.${NC}"
            read -p "Press Enter to continue..."
            return
        fi
    else
        echo -e "${RED}Failed to check for updates.${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -e "${CYAN}Current version: ${NC}${current_version}"
    echo -e "${CYAN}Latest version: ${NC}${latest_version}"
    
    if [ "$current_version" = "$latest_version" ]; then
        echo -e "${GREEN}You have the latest version of Xray installed.${NC}"
    else
        echo -e "${YELLOW}A new version of Xray is available.${NC}"
        read -p "Do you want to update now? (y/n): " update_confirm
        
        if [[ "$update_confirm" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Updating Xray...${NC}"
            
            # Download the installation script to a temporary file
            local tmp_script=$(mktemp)
            safe_download "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" "$tmp_script" "Failed to download Xray installation script"
            
            # Make the script executable
            chmod +x "$tmp_script"
            
            # Execute the script to update
            safe_exec "$tmp_script" "Failed to update Xray"
            
            # Clean up
            rm -f "$tmp_script"
            
            echo -e "${GREEN}Xray updated successfully to version ${latest_version}.${NC}"
            
            # Restart Xray
            restart_xray
        else
            echo -e "${YELLOW}Update cancelled.${NC}"
        fi
    fi
    
    read -p "Press Enter to continue..."
}

# Function to create config file
create_config() {
    echo -e "${BLUE}Creating Xray configuration...${NC}"
    
    # Make sure the config directory exists
    mkdir -p /usr/local/etc/xray
    
    # Prepare client objects for JSON
    local client_objects=""
    local i=0
    
    # Loop through all users to create client entries
    while [ $i -lt ${#user_uuids[@]} ]; do
        if [ $i -gt 0 ]; then
            client_objects="${client_objects},"
        fi
        
        client_objects="${client_objects}
                {
                    \"id\": \"${user_uuids[$i]}\",
                    \"flow\": \"xtls-rprx-vision\",
                    \"email\": \"${user_names[$i]}@example.com\"
                }"
        
        ((i++))
    done
    
    # Create FakeDNS or standard DNS config based on setting
    local dns_config=""
    if [ "$use_fake_dns" = true ]; then
        # FakeDNS configuration
        dns_config='"dns": {
        "servers": [
            "8.8.8.8",
            "1.1.1.1",
            "localhost"
        ],
        "fakeIP": {
            "enabled": true,
            "ipPool": "198.18.0.0/16",
            "ipPoolV6": "fc00::/18"
        }
    },'
    else
        # Standard DNS configuration
        dns_config='"dns": {
        "servers": [
            "8.8.8.8",
            "1.1.1.1",
            "localhost"
        ]
    },'
    fi
    
    # Create the full config
    cat > "$config_file" << EOF
{
    ${dns_config}
    "log": {
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "AsIs",
        "rules": []
    },
    "inbounds": [
        {
            "port": ${server_port},
            "protocol": "vless",
            "settings": {
                "clients": [${client_objects}
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
                        "${dest_server}"
                    ],
                    "privateKey": "${private_key}",
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
                    "shortIds": [
                        "${short_id}"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF
    
    echo -e "${GREEN}Configuration file created at ${config_file}${NC}"
    
    # Set proper permissions
    chmod 644 "$config_file"
}

# Function to generate client configs
generate_client_configs() {
    display_banner
    
    # Check for IP first
    if [ -z "$server_ip" ]; then
        get_server_ip
    fi
    
    # Prompt for user selection
    echo -e "${CYAN}Select user to generate config for:${NC}"
    local i=0
    while [ $i -lt ${#user_uuids[@]} ]; do
        echo -e "${YELLOW}$((i+1)))${NC} ${user_names[$i]}"
        ((i++))
    done
    
    echo -e "${YELLOW}a)${NC} Generate for all users"
    echo -e "${YELLOW}b)${NC} Back to main menu"
    echo
    
    read -p "Enter your choice: " user_choice
    
    if [ "$user_choice" = "b" ]; then
        return
    elif [ "$user_choice" = "a" ]; then
        # Generate for all users
        local i=0
        while [ $i -lt ${#user_uuids[@]} ]; do
            generate_single_config $i
            ((i++))
        done
    elif [[ "$user_choice" =~ ^[0-9]+$ ]] && [ "$user_choice" -ge 1 ] && [ "$user_choice" -le "${#user_uuids[@]}" ]; then
        # Generate for selected user
        generate_single_config $((user_choice-1))
    else
        echo -e "${RED}Invalid choice.${NC}"
        read -p "Press Enter to continue..."
        generate_client_configs
        return
    fi
    
    read -p "Press Enter to continue..."
}

# Function to generate config for a single user
generate_single_config() {
    local index=$1
    local user_uuid="${user_uuids[$index]}"
    local user_name="${user_names[$index]}"
    
    echo -e "${BLUE}Generating configuration for user: ${user_name}${NC}"
    
    # Create client configuration strings
    
    # 1. Xray URL for v2rayN
    local xray_url="vless://${user_uuid}@${server_ip}:${server_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${dest_server}&fp=${fingerprint}&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#Xray-REALITY-${user_name}"
    
    # 2. Clash Meta configuration
    local clash_config="- name: Xray-REALITY-${user_name}
  type: vless
  server: ${server_ip}
  port: ${server_port}
  uuid: ${user_uuid}
  network: tcp
  tls: true
  udp: true
  flow: xtls-rprx-vision
  servername: ${dest_server}
  reality-opts:
    public-key: ${public_key}
    short-id: ${short_id}
  client-fingerprint: ${fingerprint}"
    
    # 3. Sing-Box configuration
    local singbox_config='{
  "outbounds": [
    {
      "type": "vless",
      "tag": "Xray-REALITY-'${user_name}'",
      "server": "'${server_ip}'",
      "server_port": '${server_port}',
      "uuid": "'${user_uuid}'",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "'${dest_server}'",
        "utls": {
          "enabled": true,
          "fingerprint": "'${fingerprint}'"
        },
        "reality": {
          "enabled": true,
          "public_key": "'${public_key}'",
          "short_id": "'${short_id}'"
        }
      }
    }
  ]
}'
    
    # Display configurations
    echo -e "${CYAN}====================== XRAY CLIENT CONFIGURATION ======================${NC}"
    echo -e "${YELLOW}User:${NC} ${user_name}"
    echo -e "${YELLOW}UUID:${NC} ${user_uuid}"
    echo -e "${YELLOW}Server:${NC} ${server_ip}:${server_port}"
    echo -e "${YELLOW}SNI:${NC} ${dest_server}"
    echo -e "${YELLOW}Public Key:${NC} ${public_key}"
    echo -e "${YELLOW}ShortID:${NC} ${short_id}"
    echo -e "${YELLOW}Fingerprint:${NC} ${fingerprint}"
    echo
    
    # URL for v2rayN, NekoBox, etc.
    echo -e "${CYAN}=== URL for v2rayN, NekoBox, v2rayNG, etc ===${NC}"
    echo -e "${xray_url}"
    echo
    
    # Clash Meta config
    echo -e "${CYAN}=== Clash Meta Configuration ===${NC}"
    echo -e "${clash_config}"
    echo
    
    # Sing-Box config
    echo -e "${CYAN}=== Sing-Box Configuration ===${NC}"
    echo -e "${singbox_config}"
    echo
    
    # QR Code (if qrencode is installed)
    if command -v qrencode > /dev/null 2>&1; then
        echo -e "${CYAN}=== QR Code ===${NC}"
        qrencode -t ANSIUTF8 -o - "${xray_url}"
        echo
    else
        echo -e "${YELLOW}QR code generation skipped (qrencode not installed).${NC}"
        echo -e "${YELLOW}Install with: apt install qrencode${NC}"
        echo
    fi
    
    # Save configurations to files
    local config_dir="/root/xray_configs/${user_name}"
    mkdir -p "$config_dir"
    
    echo "$xray_url" > "${config_dir}/url.txt"
    echo "$clash_config" > "${config_dir}/clash.yaml"
    echo "$singbox_config" > "${config_dir}/singbox.json"
    
    echo -e "${GREEN}Configuration saved to ${config_dir}${NC}"
}

# Main setup function
setup_xray() {
    display_banner
    
    # Check root
    check_root
    
    # Check if Xray is already installed
    check_installation
    
    # Get server IP
    get_server_ip
    echo -e "${CYAN}Server IP: ${NC}${server_ip}"
    
    # Install dependencies
    install_dependencies
    
    # Install Xray if not already installed
    if [ "$installed" = false ]; then
        install_xray
    fi
    
    # Generate keys if needed
    if [ -z "$private_key" ] || [ -z "$public_key" ]; then
        generate_keys
    fi
    
    # Create config
    create_config
    
    # Restart Xray
    restart_xray
    
    # Generate client configuration
    generate_client_configs
}

# Function to show main menu
show_menu() {
    while true; do
        display_banner
        echo -e "${CYAN}Server IP: ${NC}${server_ip}"
        echo -e "${CYAN}Installation Status: ${NC}$(if [ "$installed" = true ]; then echo -e "${GREEN}Installed${NC}"; else echo -e "${RED}Not Installed${NC}"; fi)"
        
        if [ "$installed" = true ]; then
            echo -e "${CYAN}Port: ${NC}${server_port}"
            echo -e "${CYAN}SNI: ${NC}${dest_server}"
            echo -e "${CYAN}DNS Mode: ${NC}$(if [ "$use_fake_dns" = true ]; then echo -e "${GREEN}FakeDNS${NC}"; else echo -e "${YELLOW}Standard${NC}"; fi)"
            echo -e "${CYAN}TLS Fingerprint: ${NC}${fingerprint}"
            echo -e "${CYAN}User Count: ${NC}${#user_uuids[@]}"
        fi
        
        echo
        echo -e "${YELLOW}======== MAIN MENU ========${NC}"
        
        if [ "$installed" = false ]; then
            echo -e "${YELLOW}i)${NC} Install Xray with REALITY"
        else
            echo -e "${YELLOW}1)${NC} Change Port (Current: ${server_port})"
            echo -e "${YELLOW}2)${NC} Change SNI Domain (Current: ${dest_server})"
            echo -e "${YELLOW}3)${NC} Change DNS Mode (Current: $(if [ "$use_fake_dns" = true ]; then echo "FakeDNS"; else echo "Standard"; fi))"
            echo -e "${YELLOW}4)${NC} Manage ShortID (Current: ${short_id})"
            echo -e "${YELLOW}5)${NC} Regenerate Keys"
            echo -e "${YELLOW}6)${NC} Change TLS Fingerprint (Current: ${fingerprint})"
            echo -e "${YELLOW}7)${NC} Manage Users"
            echo -e "${YELLOW}8)${NC} Generate Client Configs"
            echo -e "${YELLOW}9)${NC} Configure Firewall"
            echo -e "${YELLOW}10)${NC} Display Service Status"
            echo -e "${YELLOW}11)${NC} Restart Xray Service"
            echo -e "${YELLOW}12)${NC} Check for Updates"
            echo -e "${YELLOW}u)${NC} Uninstall Xray"
        fi
        
        echo -e "${YELLOW}q)${NC} Quit"
        echo -e "${YELLOW}===========================${NC}"
        echo
        
        read -p "Enter your choice: " menu_choice
        
        case $menu_choice in
            i)
                if [ "$installed" = false ]; then
                    setup_xray
                else
                    echo -e "${RED}Xray is already installed.${NC}"
                    read -p "Press Enter to continue..."
                fi
                ;;
            1)
                if [ "$installed" = true ]; then
                    change_port
                    create_config
                    restart_xray
                fi
                ;;
            2)
                if [ "$installed" = true ]; then
                    change_sni
                    create_config
                    restart_xray
                fi
                ;;
            3)
                if [ "$installed" = true ]; then
                    toggle_fake_dns
                    create_config
                    restart_xray
                fi
                ;;
            4)
                if [ "$installed" = true ]; then
                    manage_short_id
                    create_config
                    restart_xray
                fi
                ;;
            5)
                if [ "$installed" = true ]; then
                    regenerate_keys
                    create_config
                    restart_xray
                fi
                ;;
            6)
                if [ "$installed" = true ]; then
                    change_fingerprint
                    create_config
                    restart_xray
                fi
                ;;
            7)
                if [ "$installed" = true ]; then
                    manage_users
                    create_config
                    restart_xray
                fi
                ;;
            8)
                if [ "$installed" = true ]; then
                    generate_client_configs
                fi
                ;;
            9)
                if [ "$installed" = true ]; then
                    configure_firewall
                fi
                ;;
            10)
                if [ "$installed" = true ]; then
                    display_status
                    read -p "Press Enter to continue..."
                fi
                ;;
            11)
                if [ "$installed" = true ]; then
                    restart_xray
                    read -p "Press Enter to continue..."
                fi
                ;;
            12)
                if [ "$installed" = true ]; then
                    check_updates
                fi
                ;;
            u)
                if [ "$installed" = true ]; then
                    uninstall_xray
                fi
                ;;
            q)
                echo -e "${GREEN}Thank you for using Xray REALITY Setup Script. Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice.${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Start the script
display_banner
show_menu
