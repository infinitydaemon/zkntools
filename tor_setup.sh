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
ORPort 9001
Nickname cwdsystems
RelayBandwidthRate 10 MB
RelayBandwidthBurst 20 MB
ExitRelay 0
ContactInfo your-email@some-domain.com
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
