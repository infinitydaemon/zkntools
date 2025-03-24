#!/bin/bash

# Script to install Tor and configure it as a relay on your device

# Update and install Tor
sudo apt update
sudo apt install -y tor

# Backup the original Tor configuration file if it exists
sudo cp /etc/tor/torrc /etc/tor/torrc.backup

# Configure Tor as a relay
echo "Configuring Tor as a relay..."
sudo bash -c 'cat > /etc/tor/torrc << EOL
RunAsDaemon 1
# Basic Tor relay settings
Nickname cwdsystems
ContactInfo cwdsystems@esomewhere.net
# Set up the relay
ORPort 9001 # Must be reachable via port forwards.
ExitRelay 0
RelayBandwidthRate 10 MBytes  # Limit to 10 MB/s
RelayBandwidthBurst 20 MBytes # Allow bursts up to 20 MB/s
# Ensure you have a static public IP
Address auto  # If using a static IP, replace with your public IP
# Set up the directory server to advertise your relay
DirPort 9030  # Optional, allows your relay to be a directory mirror
DirCache 1
# Security and hardening
SocksPort 0  # No SOCKS proxy, relay-only mode
ControlPort 9051
CookieAuthentication 1
# Logs and debugging
Log notice file /var/log/tor/notices.log
EOL'

# Restart Tor to apply the new configuration
sudo systemctl restart tor

# Enable Tor to start on boot
sudo systemctl enable tor

# Check Tor status
sudo systemctl status tor

echo "Tor has been installed and configured as a relay."
echo "You can monitor the Tor logs at /var/log/tor/notices.log"
