#!/usr/bin/env python3

import os
import sys
import requests
from dialog import Dialog
import ipsetpy
import iptc
import tempfile

# Dictionary of countries with their codes. More can be added
COUNTRIES = {
    "China": "CN",
    "United States": "US",
    "Russia": "RU",
    "Germany": "DE",
    "India": "IN",
    "Brazil": "BR",
    "United Kingdom": "GB",
    "France": "FR",
    "Japan": "JP",
    "South Korea": "KR"
}

d = Dialog(dialog="dialog")
d.set_background_title("IPTables Manager")

def check_requirements():
    """Check if running as root and required tools are available"""
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)

def download_ip_ranges(country_code):
    """Download IP ranges for a country"""
    url = f"https://cdn-lite.ip2location.com/datasets/{country_code}.txt"
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        temp_file.write(response.content)
        temp_file.close()
        
        if os.path.getsize(temp_file.name) == 0:
            d.msgbox("Downloaded IP ranges file is empty.\nThe country code might be invalid.", width=60)
            os.unlink(temp_file.name)
            return None
        return temp_file.name
    except requests.RequestException:
        d.msgbox("Failed to download IP ranges.\nCheck your internet connection.", width=60)
        os.unlink(temp_file.name)
        return None

def block_country():
    """Block IP ranges for a selected country"""
    choices = [(country, f"{country} ({code})") for country, code in COUNTRIES.items()]
    code, tag = d.menu("Select a country to block:", choices=choices, width=60, height=20)
    
    if code != d.OK:
        return
    
    country = tag.split(" (")[0]
    country_code = COUNTRIES[country]
    
    d.infobox(f"Blocking {country} ({country_code})...")
    
    ip_file = download_ip_ranges(country_code)
    if not ip_file:
        return

    try:
        # Create or flush ipset
        try:
            ipsetpy.create_set(country_code, "hash:net")
        except ipsetpy.IPSetError:
            ipsetpy.flush_set(country_code)

        # Add IP ranges to ipset
        with open(ip_file, 'r') as f:
            for line in f:
                ipsetpy.add_entry(country_code, line.strip())

        # Add iptables rules
        table = iptc.Table(iptc.Table.FILTER)
        for chain_name in ["INPUT", "FORWARD"]:
            chain = iptc.Chain(table, chain_name)
            rule = iptc.Rule()
            rule.src = f"set:{country_code}"
            rule.create_target("DROP")
            if not any(r.matches_rule(rule) for r in chain.rules):
                chain.insert_rule(rule)

        d.msgbox(f"{country} ({country_code}) blocked successfully!", width=40)
    except Exception as e:
        d.msgbox(f"Error blocking country: {str(e)}", width=60)
    finally:
        os.unlink(ip_file)

def unblock_country():
    """Unblock a previously blocked country"""
    ipsets = [s for s in ipsetpy.list_sets() if len(s) == 2 and s.isupper()]
    
    if not ipsets:
        d.msgbox("No countries are currently blocked!", width=40)
        return
        
    choices = [(s, s) for s in ipsets]
    code, tag = d.menu("Select a country to unblock:", choices=choices, width=60, height=20)
    
    if code != d.OK:
        return
        
    country_code = tag
    
    try:
        # Remove iptables rules
        table = iptc.Table(iptc.Table.FILTER)
        for chain_name in ["INPUT", "FORWARD"]:
            chain = iptc.Chain(table, chain_name)
            for rule in chain.rules:
                if rule.src == f"set:{country_code}" and rule.target.name == "DROP":
                    chain.delete_rule(rule)
        
        # Destroy ipset
        ipsetpy.destroy_set(country_code)
        
        d.msgbox(f"{country_code} unblocked successfully!", width=40)
    except Exception as e:
        d.msgbox(f"Error unblocking country: {str(e)}", width=60)

def show_blocked_countries():
    """Display currently blocked countries"""
    ipsets = [s for s in ipsetpy.list_sets() if len(s) == 2 and s.isupper()]
    if not ipsets:
        d.msgbox("No countries are currently blocked!", width=40)
    else:
        d.msgbox("Blocked Countries:\n" + "\n".join(ipsets), width=40, height=20)

def block_port():
    """Block a specific port"""
    code, port = d.inputbox("Enter port number (1-65535):", width=40)
    if code != d.OK or not port.isdigit() or not (1 <= int(port) <= 65535):
        d.msgbox("Invalid port number! Must be between 1-65535.", width=40)
        return

    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        
        for protocol in ["tcp", "udp"]:
            rule = iptc.Rule()
            rule.protocol = protocol
            rule.create_target("DROP")
            match = rule.create_match(protocol)
            match.dport = port
            if not any(r.matches_rule(rule) for r in chain.rules):
                chain.insert_rule(rule)
        
        d.msgbox(f"Port {port} blocked successfully!", width=40)
    except Exception as e:
        d.msgbox(f"Error blocking port: {str(e)}", width=60)

def unblock_port():
    """Unblock a specific port"""
    code, port = d.inputbox("Enter port number (1-65535):", width=40)
    if code != d.OK or not port.isdigit() or not (1 <= int(port) <= 65535):
        d.msgbox("Invalid port number! Must be between 1-65535.", width=40)
        return

    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")
        
        for protocol in ["tcp", "udp"]:
            for rule in chain.rules:
                if (rule.protocol == protocol and 
                    any(m.dport == port for m in rule.matches) and 
                    rule.target.name == "DROP"):
                    chain.delete_rule(rule)
        
        d.msgbox(f"Port {port} unblocked successfully!", width=40)
    except Exception as e:
        d.msgbox(f"Error unblocking port: {str(e)}", width=60)

def show_blocked_ports():
    """Display currently blocked ports"""
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "INPUT")
    ports = set()
    
    for rule in chain.rules:
        if rule.target.name == "DROP":
            for match in rule.matches:
                if hasattr(match, "dport"):
                    ports.add(match.dport)
    
    if not ports:
        d.msgbox("No ports are currently blocked!", width=40)
    else:
        d.msgbox("Blocked Ports:\n" + "\n".join(sorted(ports)), width=40, height=20)

def main():
    """Main menu loop"""
    check_requirements()
    
    menu_choices = [
        ("1", "Block a Country"),
        ("2", "Unblock a Country"),
        ("3", "Show Blocked Countries"),
        ("4", "Block a Port"),
        ("5", "Unblock a Port"),
        ("6", "Show Blocked Ports"),
        ("7", "Exit")
    ]
    
    while True:
        code, tag = d.menu("Select an option:", choices=menu_choices, width=60, height=20)
        
        if code != d.OK:
            break
            
        if tag == "1":
            block_country()
        elif tag == "2":
            unblock_country()
        elif tag == "3":
            show_blocked_countries()
        elif tag == "4":
            block_port()
        elif tag == "5":
            unblock_port()
        elif tag == "6":
            show_blocked_ports()
        elif tag == "7":
            break
    
    d.msgbox("Firewall Manager exited. Goodbye!", width=40)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        d.msgbox("Program terminated by user", width=40)
    except Exception as e:
        d.msgbox(f"An unexpected error occurred: {str(e)}", width=60)
    finally:
        os.system("clear")
