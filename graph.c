// ZKN realtime traffic graph
// Compile with gcc -o graph graph.c -lncurses

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ncurses.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX_INTERFACES 10
#define MAX_BAR_WIDTH 50
#define UPDATE_INTERVAL 20000 // 20ms in microseconds

typedef struct {
    char name[32];
    unsigned long long rx_bytes_prev;
    unsigned long long tx_bytes_prev;
    double rx_rate; 
    double tx_rate; 
} Interface;

Interface interfaces[MAX_INTERFACES];
int interface_count = 0;
int max_y, max_x;

void init_colors() {
    start_color();
    init_pair(1, COLOR_YELLOW, COLOR_BLUE);  
    init_pair(2, COLOR_GREEN, COLOR_BLUE);   
    init_pair(3, COLOR_RED, COLOR_BLUE);     
    init_pair(4, COLOR_WHITE, COLOR_BLUE);   
    bkgd(COLOR_PAIR(1));
}

void get_interfaces() {
    interface_count = 0;
    DIR *dir = opendir("/sys/class/net");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && interface_count < MAX_INTERFACES) {
        if (entry->d_type == DT_LNK) {  
            struct stat statbuf;
            char path[256];
            snprintf(path, sizeof(path), "/sys/class/net/%s", entry->d_name);
            if (stat(path, &statbuf) == 0) {
                strncpy(interfaces[interface_count].name, entry->d_name, sizeof(interfaces[interface_count].name)-1);
                interfaces[interface_count].rx_bytes_prev = 0;
                interfaces[interface_count].tx_bytes_prev = 0;
                interfaces[interface_count].rx_rate = 0.0;
                interfaces[interface_count].tx_rate = 0.0;
                interface_count++;
            }
        }
    }
    closedir(dir);
}

void update_traffic() {
    for (int i = 0; i < interface_count; i++) {
        char rx_path[256], tx_path[256];
        snprintf(rx_path, sizeof(rx_path), "/sys/class/net/%s/statistics/rx_bytes", interfaces[i].name);
        snprintf(tx_path, sizeof(tx_path), "/sys/class/net/%s/statistics/tx_bytes", interfaces[i].name);

        FILE *rx_file = fopen(rx_path, "r");
        FILE *tx_file = fopen(tx_path, "r");

        if (rx_file && tx_file) {
            unsigned long long rx_bytes, tx_bytes;
            fscanf(rx_file, "%llu", &rx_bytes);
            fscanf(tx_file, "%llu", &tx_bytes);

            if (interfaces[i].rx_bytes_prev != 0) { 
                interfaces[i].rx_rate = ((rx_bytes - interfaces[i].rx_bytes_prev) / 1024.0) / 0.02;
                interfaces[i].tx_rate = ((tx_bytes - interfaces[i].tx_bytes_prev) / 1024.0) / 0.02;
            }

            interfaces[i].rx_bytes_prev = rx_bytes;
            interfaces[i].tx_bytes_prev = tx_bytes;

            fclose(rx_file);
            fclose(tx_file);
        }
    }
}

void draw_graph() {
    clear();
    getmaxyx(stdscr, max_y, max_x);

    // Header
    attron(COLOR_PAIR(4) | A_BOLD);
    mvprintw(0, (max_x - 20) / 2, "Network Traffic Monitor");
    attroff(COLOR_PAIR(4) | A_BOLD);

    if (interface_count == 0) {
        mvprintw(max_y/2, (max_x - 20) / 2, "No interfaces found!");
        refresh();
        return;
    }

    int row = 2;
    for (int i = 0; i < interface_count && row < max_y - 2; i++) {

        mvprintw(row, 2, "%s", interfaces[i].name);

        int rx_bar = (int)(interfaces[i].rx_rate / 100.0 * MAX_BAR_WIDTH); 
        if (rx_bar > MAX_BAR_WIDTH) rx_bar = MAX_BAR_WIDTH;
        attron(COLOR_PAIR(2));
        for (int j = 0; j < rx_bar && j < max_x - 20; j++) {
            mvaddch(row + 1, 10 + j, '#');
        }
        attroff(COLOR_PAIR(2));
        mvprintw(row + 1, max_x - 10, "RX: %.1f KB/s", interfaces[i].rx_rate);

        int tx_bar = (int)(interfaces[i].tx_rate / 100.0 * MAX_BAR_WIDTH);
        if (tx_bar > MAX_BAR_WIDTH) tx_bar = MAX_BAR_WIDTH;
        attron(COLOR_PAIR(3));
        for (int j = 0; j < tx_bar && j < max_x - 20; j++) {
            mvaddch(row + 2, 10 + j, '#');
        }
        attroff(COLOR_PAIR(3));
        mvprintw(row + 2, max_x - 10, "TX: %.1f KB/s", interfaces[i].tx_rate);

        row += 4;
    }

    mvprintw(max_y - 1, 2, "Press 'q' to quit");
    refresh();
}

int main() {
    initscr();
    if (!has_colors()) {
        endwin();
        printf("Terminal doesn't support colors!\n");
        return 1;
    }

    init_colors();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    nodelay(stdscr, TRUE); 

    get_interfaces();
    if (interface_count == 0) {
        endwin();
        printf("No network interfaces found!\n");
        return 1;
    }

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = UPDATE_INTERVAL * 1000;

    while (1) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;

        update_traffic();
        draw_graph();
        nanosleep(&ts, NULL); 
    }

    endwin();
    return 0;
}
