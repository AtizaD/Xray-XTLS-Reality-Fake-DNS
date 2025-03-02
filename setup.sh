# === MULTIPLE USER SUPPORT ===
# Variables to store users (compatible with basic bash)
user_uuids=("$uuid")
user_names=("Default User")

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

# === TLS FINGERPRINT CUSTOMIZATION ===
# Variable to store the current fingerprint
fingerprint="chrome"

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

# === FIREWALL CONFIGURATION ===
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

# === UNINSTALL FUNCTION ===
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

# === UPDATE CHECKER ===
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

# === MODIFIED CONFIGURATION FUNCTIONS ===
# Modified function to create Xray configuration with multiple users
create_config() {
    echo -e "${BLUE}Creating Xray configuration file with Fake DNS...${NC}"
    
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
    echo -e "${GREEN}Configuration file created successfully.${NC}"
}

# Modified function to display client configuration (show all users)
display_config() {
    echo -e "${YELLOW}=========== CONFIGURATION INFO =============${NC}"
    echo -e "${CYAN}Server IP: ${NC}${server_ip}"
    echo -e "${CYAN}Port: ${NC}${server_port}"
    echo -e "${CYAN}Protocol: ${NC}VLESS"
    echo -e "${CYAN}Flow: ${NC}xtls-rprx-vision"
    echo -e "${CYAN}Network: ${NC}tcp"
    echo -e "${CYAN}Security: ${NC}reality"
    echo -e "${CYAN}SNI: ${NC}${dest_server}"
    echo -e "${CYAN}Fingerprint: ${NC}${fingerprint}"
    echo -e "${CYAN}Public Key: ${NC}${public_key}"
    
    echo -e "${YELLOW}------------- USERS ----------------------${NC}"
    local i=0
    while [ $i -lt ${#user_uuids[@]} ]; do
        echo -e "${CYAN}User: ${NC}${user_names[$i]}"
        echo -e "${CYAN}UUID: ${NC}${user_uuids[$i]}"
        echo
        ((i++))
    done
    
    echo -e "${YELLOW}============================================${NC}"
    echo -e "Use the above info to configure your client (v2rayNG, Nekoray, etc.)"
}

# === MAIN MENU MODIFICATION ===
# Updated main menu function with new options
main_menu() {
    while true; do
        display_banner
        echo -e "${CYAN}Server IP: ${NC}${server_ip}"
        echo -e "${CYAN}Current Status: ${NC}$(if [ "$installed" = true ]; then echo -e "${GREEN}Installed${NC}"; else echo -e "${RED}Not Installed${NC}"; fi)"
        echo
        echo -e "${YELLOW}1)${NC} Install/Reinstall Xray with Reality"
        echo -e "${YELLOW}2)${NC} Manage Users"
        echo -e "${YELLOW}3)${NC} Change SNI Destination"
        echo -e "${YELLOW}4)${NC} Change Port"
        echo -e "${YELLOW}5)${NC} Change TLS Fingerprint"
        echo -e "${YELLOW}6)${NC} Regenerate Reality Keys"
        echo -e "${YELLOW}7)${NC} Configure Firewall"
        echo -e "${YELLOW}8)${NC} Apply Changes"
        echo -e "${YELLOW}9)${NC} Display Current Configuration"
        echo -e "${YELLOW}10)${NC} Check for Updates"
        echo -e "${YELLOW}11)${NC} Uninstall Xray"
        echo -e "${YELLOW}12)${NC} Exit"
        echo
        read -p "Enter your choice [1-12]: " main_choice
        
        case $main_choice in
            1)
                perform_installation
                ;;
            2)
                manage_users
                ;;
            3)
                change_sni
                ;;
            4)
                change_port
                ;;
            5)
                change_fingerprint
                ;;
            6)
                regenerate_keys
                ;;
            7)
                configure_firewall
                ;;
            8)
                apply_changes
                ;;
            9)
                display_banner
                display_config
                read -p "Press Enter to continue..."
                ;;
            10)
                check_updates
                ;;
            11)
                uninstall_xray
                ;;
            12)
                echo -e "${GREEN}Exiting the script. Thank you for using Xray Reality setup!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please enter a number between 1 and 12.${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Modification to apply_changes function to use the new variables
apply_changes() {
    display_banner
    echo -e "${BLUE}Applying configuration changes...${NC}"
    
    if [ -z "$private_key" ] || [ -z "$public_key" ]; then
        generate_keys
    fi
    
    create_config
    restart_xray
    display_config
    display_status
    
    read -p "Press Enter to continue to main menu..."
}

# Modification to perform_installation function
perform_installation() {
    display_banner
    check_installation
    
    if [ "$installed" = false ]; then
        install_dependencies
        install_xray
    fi
    
    if [ -z "$private_key" ] || [ -z "$public_key" ]; then
        generate_keys
    fi
    
    # Initialize user arrays if empty
    if [ ${#user_uuids[@]} -eq 0 ]; then
        user_uuids=("$uuid")
        user_names=("Default User")
    fi
    
    create_config
    restart_xray
    display_config
    display_status
    
    read -p "Press Enter to continue to main menu..."
}
