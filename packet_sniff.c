/*
 * Advanced Packet Sniffer in C (Ettercap-like Passive Mode)
 * ---------------------------------------------------------
 * This program captures network packets using libpcap, extracts packet details,
 * resolves IP addresses to hostnames, and displays protocol information.
 * 
 * Features:
 * - Captures and processes live network traffic.
 * - Extracts IP addresses, resolves hostnames.
 * - Identifies protocols (TCP, UDP, ICMP).
 * - Displays packet size and source/destination information.
 * - Works on a specified network interface (default: eth0).
 *
 * Compilation:
 *  gcc -o packet_sniff packet_sniff.c -lpcap
 *
 * Usage:
 *  sudo ./packet_sniff [interface]
 *
 * Dependencies:
 *  - libpcap (Install with `sudo apt install libpcap-dev`)
 * 
 * Note:
 * This tool does **NOT** perform MITM attacks like Ettercap. It only passively
 * captures and analyzes packets.
 *
 * Author: Professor Raziel K.
 * Date  : 19th March 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#define SNAP_LEN 1518  // Max packet size to capture
#define DEFAULT_INTERFACE "eth0"
#define DELAY 200000    // 200ms delay in microseconds (200,000 μs)

/* Function to resolve IP address to hostname */
const char *resolve_hostname(const char *ip_address) {
    struct in_addr addr;
    struct hostent *host_entry;

    if (!inet_aton(ip_address, &addr)) {
        return ip_address;
    }

    host_entry = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (host_entry) {
        return host_entry->h_name;
    }

    return ip_address;
}

/* Function to print protocol information */
void print_protocol_info(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP:
            printf("Protocol: TCP ");
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP ");
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP ");
            break;
        default:
            printf("Protocol: OTHER ");
            break;
    }
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

    // Convert source and destination IPs to strings
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Resolve hostnames
    const char *source_hostname = resolve_hostname(source_ip);
    const char *dest_hostname = resolve_hostname(dest_ip);

    // Print packet details
    printf("\nPacket Captured - Size: %d bytes\n", header->len);
    printf("From: %s (%s) -> To: %s (%s)\n", source_ip, source_hostname, dest_ip, dest_hostname);
    print_protocol_info(ip_header->ip_p);
    printf("\n");

    fflush(stdout);

    // Delay to slow down output
    usleep(DELAY);  // 200ms (200,000 microseconds)
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

    // Open device for packet capture
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Listening on %s...\n", dev);

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Cleanup
    pcap_close(handle);
    return 0;
}
