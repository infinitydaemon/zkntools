#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root!" >&2
    exit 1
fi

install_wireguard() {
    curl -L https://install.pivpn.io | bash
}

create_user() {
    CLIENT_NAME=$(whiptail --inputbox "Enter client name:" 10 50 3>&1 1>&2 2>&3)
    if [[ -n "$CLIENT_NAME" ]]; then
        pivpn -a -n "$CLIENT_NAME"
        whiptail --msgbox "Client $CLIENT_NAME added!" 10 40
    else
        whiptail --msgbox "No client name entered!" 10 40
    fi
}

display_users() {
    CLIENT_LIST=$(pivpn -l | awk 'NR>2 {print $1}')
    if [[ -z "$CLIENT_LIST" ]]; then
        whiptail --msgbox "No clients found!" 10 40
    else
        whiptail --msgbox "Clients:\n$CLIENT_LIST" 20 50
    fi
}

delete_user() {
    CLIENT_LIST=$(pivpn -l | awk 'NR>2 {print $1}')
    if [[ -z "$CLIENT_LIST" ]]; then
        whiptail --msgbox "No clients found!" 10 40
        return
    fi

    MENU_OPTIONS=()
    while read -r CLIENT; do
        MENU_OPTIONS+=("$CLIENT" "WireGuard user")
    done <<< "$CLIENT_LIST"

    CLIENT_NAME=$(whiptail --title "Select User" --menu "Choose a client to remove:" 20 60 10 "${MENU_OPTIONS[@]}" 3>&1 1>&2 2>&3)

    if [[ -n "$CLIENT_NAME" ]]; then
        pivpn -r "$CLIENT_NAME"
        whiptail --msgbox "Client $CLIENT_NAME removed!" 10 40
    else
        whiptail --msgbox "No client selected!" 10 40
    fi
}

reconfigure_wireguard() {
    PUBLIC_IP=$(curl -s https://api.ipify.org)
    if [[ -z "$PUBLIC_IP" ]]; then
        whiptail --msgbox "Failed to fetch public IP!" 10 40
        return
    fi

    sed -i "s/^PUBLIC_IP=.*/PUBLIC_IP=$PUBLIC_IP/" /etc/pivpn/setupVars.conf

    pivpn -d
    systemctl restart wg-quick@wg0
    
    whiptail --msgbox "WireGuard reconfigured with public IP: $PUBLIC_IP" 10 60
}

menu() {
    while true; do
        OPTION=$(whiptail --title "ZKN WireGuard Management" --menu "Choose an option:" 15 60 6 \
            "1" "Install WireGuard" \
            "2" "Create User" \
            "3" "Display Users" \
            "4" "Delete User" \
            "5" "Reconfigure WireGuard" \
            "6" "Exit" 3>&1 1>&2 2>&3)

        case "$OPTION" in
            1) install_wireguard ;;
            2) create_user ;;
            3) display_users ;;
            4) delete_user ;;
            5) reconfigure_wireguard ;;
            6) exit 0 ;;
            *) echo "Invalid option!" ;;
        esac
    done
}

menu
