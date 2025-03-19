/*
 * packet_sniff.c - A Simple Packet Sniffer
 * -----------------------------------------
 * This program captures network packets using `libpcap` and provides a 
 * user-friendly interface using `ncurses`. It allows real-time monitoring 
 * of network traffic.
 *
 * Compilation:
 *  gcc -o packet_sniff packet_sniff.c -lpcap -lncurses
 *
 * Usage:
 *  sudo ./packet_sniff 
 * 
 *
 * Dependencies:
 *  - libpcap   : Packet capture library (install with `sudo apt install libpcap-dev`)
 *  - ncurses   : Terminal UI library (install with `sudo apt install libncurses-dev`)
 *
 *
 * Features:
 *  - Captures packets in real time
 *  - Displays packet details (source, destination, protocol, size)
 *  - Uses ncurses for an interactive interface
 *
 * Author: Professor Raziel K.
 * Date  : 19 March 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#define SNAP_LEN 1518  // Max packet size to capture
#define DEFAULT_INTERFACE "eth0"
#define DELAY 100000   // 100ms delay to slow down packet display

/* Function to resolve an IP address to a hostname */
const char *resolve_hostname(const char *ip_address) {
    struct in_addr addr;
    struct hostent *host_entry;

    if (!inet_aton(ip_address, &addr)) {
        return ip_address;  // Return original IP if conversion fails
    }

    host_entry = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (host_entry) {
        return host_entry->h_name;  // Return resolved hostname
    }

    return ip_address;  // Return IP if hostname resolution fails
}

/* Packet handler function */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Only process IP packets
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    // Convert source and destination IP to string
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Resolve hostnames
    const char *source_hostname = resolve_hostname(source_ip);
    const char *dest_hostname = resolve_hostname(dest_ip);

    // Print packet info to the console
    printf("Packet: %s (%s) -> %s (%s) | Size: %d bytes\n",
           source_ip, source_hostname, dest_ip, dest_hostname, header->len);

    usleep(DELAY);  // Slow down the display to 100ms delay
}

/* Main function */
int main(int argc, char *argv[]) {
    char *dev = DEFAULT_INTERFACE; // Default to eth0
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Allow user to specify interface
    if (argc > 1) {
        dev = argv[1];
    }

    // Open the device for packet capture
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Listening on %s...\n", dev);

    // Capture packets in a loop
    while (1) {
        pcap_dispatch(handle, 1, packet_handler, NULL); // Process one packet at a time
    }

    // Cleanup
    pcap_close(handle);
    return 0;
}
