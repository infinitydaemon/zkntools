# compile with gcc -o packet_sniff packet_sniff.c -lpcap -lncurses

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

// Ncurses window initialization
void init_ncurses() {
    initscr();
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
    char *device = pcap_lookupdev(errbuf); // Auto-detect network interface
    if (device == NULL) {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return 1;
    }

    pcap_t *handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        return 2;
    }

    // Initialize ncurses
    init_ncurses();
    mvprintw(0, 1, "Network Monitor - Listening on %s", device);
    refresh();

    // Capture packets and handle user input
    while (1) {
        pcap_dispatch(handle, 1, packet_handler, NULL);

        int ch = getch();
        if (ch == 'q') break;  // Quit on 'q'
    }

    // Cleanup
    pcap_close(handle);
    endwin();
    return 0;
}
