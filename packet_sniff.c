// compile with gcc -o packet_sniff packet_sniff.c -lpcap -lncurses

#include <pcap.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#define SNAP_LEN 1518  // Max packet length

// Initialize ncurses with color settings
void init_ncurses() {
    initscr();
    start_color();
    init_pair(1, COLOR_GREEN, COLOR_BLUE);  // Green text, blue background
    bkgd(COLOR_PAIR(1));  // Apply background color
    attron(COLOR_PAIR(1)); // Use color pair for text
    cbreak();
    noecho();
    curs_set(0);
    timeout(100); // Non-blocking input
    keypad(stdscr, TRUE);
    refresh();
}

// Packet capture callback function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));

    if (ntohs(eth->h_proto) == ETH_P_IP) { // Check if IP packet
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

        strcpy(src_ip, inet_ntoa(ip_header->ip_src));
        strcpy(dst_ip, inet_ntoa(ip_header->ip_dst));

        char protocol[10];
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: strcpy(protocol, "TCP"); break;
            case IPPROTO_UDP: strcpy(protocol, "UDP"); break;
            case IPPROTO_ICMP: strcpy(protocol, "ICMP"); break;
            default: strcpy(protocol, "Other");
        }
        // Ncurses display update
        static int row = 3;
        mvprintw(row, 1, "Packet: %d bytes | Src: %s | Dst: %s | Protocol: %s",
                 header->len, src_ip, dst_ip, protocol);
        row++;
        if (row >= LINES - 2) row = 3; // Scroll within screen bounds

        mvprintw(1, 1, "Press 'q' to quit.");
        refresh();
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // Use the first device
    if (alldevs == NULL) {
        fprintf(stderr, "No devices found.\n");
        return 1;
    }
    device = alldevs;

    pcap_t *handle = pcap_open_live(device->name, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    // Initialize ncurses with colors
    init_ncurses();
    mvprintw(0, 1, "Network Monitor - Listening on %s", device->name);
    refresh();

    // Capture packets and handle user input
    while (1) {
        pcap_dispatch(handle, 1, packet_handler, NULL);

        int ch = getch();
        if (ch == 'q') break;  // Quit on 'q'
    }

    // Cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    endwin();
    return 0;
}
