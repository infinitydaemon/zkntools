// Specifically tracks the walletshield process (assumes the executable is named "walletshield").
// CPU Usage: Calculated from /proc/<pid>/stat
// Memory Usage: Calculated from /proc/<pid>/status (RSS) and /proc/meminfo (total memory)
// Compile with gcc -o walletshield_monitor walletshield_monitor.c -lncurses
// Execute with sudo

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ncurses.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_CONNECTIONS 100
#define MAX_LINE 256
#define UPDATE_INTERVAL 1 // seconds

typedef struct {
    char local_addr[32];
    char remote_addr[32];
    char state[16];
    int pid;
} TCPConnection;

int max_y, max_x;

void init_colors() {
    start_color();
    init_pair(1, COLOR_YELLOW, COLOR_BLUE);  
    init_pair(2, COLOR_GREEN, COLOR_BLUE);   
    init_pair(3, COLOR_RED, COLOR_BLUE);    
    init_pair(4, COLOR_WHITE, COLOR_BLUE);  
    bkgd(COLOR_PAIR(1));
}

float get_process_cpu_usage(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0.0;

    char buffer[MAX_LINE];
    if (!fgets(buffer, MAX_LINE, fp)) {
        fclose(fp);
        return 0.0;
    }
    fclose(fp);

    unsigned long utime, stime, cutime, cstime, start_time;
    sscanf(buffer, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %lu %lu %*d %*d %*d %*d %lu",
           &utime, &stime, &cutime, &cstime, &start_time);

    FILE *uptime_fp = fopen("/proc/uptime", "r");
    if (!uptime_fp) return 0.0;
    float uptime;
    fscanf(uptime_fp, "%f", &uptime);
    fclose(uptime_fp);

    float total_time = (utime + stime + cutime + cstime) / (float)sysconf(_SC_CLK_TCK);
    float elapsed = uptime - (start_time / (float)sysconf(_SC_CLK_TCK));
    if (elapsed == 0) return 0.0;

    return 100.0 * total_time / elapsed;
}

float get_process_mem_usage(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0.0;

    char buffer[MAX_LINE];
    unsigned long vm_rss = 0;
    while (fgets(buffer, MAX_LINE, fp)) {
        if (sscanf(buffer, "VmRSS: %lu kB", &vm_rss) == 1) break;
    }
    fclose(fp);

    FILE *meminfo_fp = fopen("/proc/meminfo", "r");
    if (!meminfo_fp) return 0.0;
    unsigned long mem_total = 0;
    while (fgets(buffer, MAX_LINE, meminfo_fp)) {
        if (sscanf(buffer, "MemTotal: %lu kB", &mem_total) == 1) break;
    }
    fclose(meminfo_fp);

    if (mem_total == 0) return 0.0;
    return 100.0 * vm_rss / mem_total;
}

void get_process_io(int pid, unsigned long *read_bytes, unsigned long *write_bytes) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/io", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        *read_bytes = 0;
        *write_bytes = 0;
        return;
    }

    char buffer[MAX_LINE];
    while (fgets(buffer, MAX_LINE, fp)) {
        if (sscanf(buffer, "read_bytes: %lu", read_bytes) == 1) continue;
        if (sscanf(buffer, "write_bytes: %lu", write_bytes) == 1) continue;
    }
    fclose(fp);
}

double get_process_uptime(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0.0;

    char buffer[MAX_LINE];
    if (!fgets(buffer, MAX_LINE, fp)) {
        fclose(fp);
        return 0.0;
    }
    fclose(fp);

    unsigned long start_time;
    sscanf(buffer, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %lu",
           &start_time);

    FILE *uptime_fp = fopen("/proc/uptime", "r");
    if (!uptime_fp) return 0.0;
    float uptime;
    fscanf(uptime_fp, "%f", &uptime);
    fclose(uptime_fp);

    return uptime - (start_time / (float)sysconf(_SC_CLK_TCK));
}

int find_walletshield_pid() {
    FILE *fp = popen("pidof walletshield", "r");
    if (!fp) return -1;

    int pid = -1;
    char buffer[32];
    if (fgets(buffer, sizeof(buffer), fp)) {
        pid = atoi(buffer);
    }
    pclose(fp);
    return pid;
}

int get_tcp_connections(TCPConnection *conns, int target_pid) {
    FILE *fp = popen("netstat -t -n -p | grep walletshield", "r");
    if (!fp) return 0;

    char buffer[MAX_LINE];
    int count = 0;
    fgets(buffer, MAX_LINE, fp); 

    while (fgets(buffer, MAX_LINE, fp) && count < MAX_CONNECTIONS) {
        char proto[10], pid_str[10];
        if (sscanf(buffer, "%s %*d %*d %s %s %s %*s/%s",
                   proto, conns[count].local_addr, conns[count].remote_addr,
                   conns[count].state, pid_str) == 5) {
            int pid = atoi(pid_str);
            if (pid == target_pid) {
                conns[count].pid = pid;
                count++;
            }
        }
    }
    pclose(fp);
    return count;
}

void draw_interface(int pid, float cpu_usage, float mem_usage, unsigned long read_bytes,
                    unsigned long write_bytes, double uptime, TCPConnection *conns, int conn_count) {
    clear();
    getmaxyx(stdscr, max_y, max_x);

    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw(0, (max_x - 20) / 2, "WalletShield Monitor");
    attroff(COLOR_PAIR(2) | A_BOLD);

    mvprintw(2, 2, "PID: %d", pid);
    int uptime_days = (int)(uptime / 86400);
    int uptime_hours = (int)((uptime - uptime_days * 86400) / 3600);
    int uptime_mins = (int)((uptime - uptime_days * 86400 - uptime_hours * 3600) / 60);
    mvprintw(3, 2, "Uptime: %dd %dh %dm", uptime_days, uptime_hours, uptime_mins);

    mvprintw(5, 2, "CPU Usage: %.1f%%", cpu_usage);
    int cpu_bar = (int)(cpu_usage / 100.0 * (max_x - 20));
    for (int i = 0; i < cpu_bar && i < max_x - 20; i++) {
        mvaddch(6, 2 + i, '#');
    }

    mvprintw(8, 2, "Memory Usage: %.1f%%", mem_usage);
    int mem_bar = (int)(mem_usage / 100.0 * (max_x - 20));
    for (int i = 0; i < mem_bar && i < max_x - 20; i++) {
        mvaddch(9, 2 + i, '#');
    }

    mvprintw(11, 2, "Disk I/O - Read: %lu KB  Write: %lu KB", read_bytes / 1024, write_bytes / 1024);

    int listening = 0, established = 0;
    for (int i = 0; i < conn_count; i++) {
        if (strcmp(conns[i].state, "LISTEN") == 0) listening++;
        else if (strcmp(conns[i].state, "ESTABLISHED") == 0) established++;
    }

    mvprintw(13, 2, "TCP Connections (%d total, %d LISTEN, %d ESTABLISHED):",
             conn_count, listening, established);

    if (conn_count == 0) {
        mvprintw(14, 4, "No TCP connections found");
    } else {
        mvprintw(14, 2, "Local Address         Remote Address        State");
        for (int i = 0; i < conn_count && i < max_y - 16; i++) {
            mvprintw(15 + i, 2, "%-20s  %-20s  %-12s",
                     conns[i].local_addr, conns[i].remote_addr, conns[i].state);
        }
    }

    attron(COLOR_PAIR(4));
    mvprintw(max_y - 1, 2, "Press 'q' to quit | Refresh every %ds", UPDATE_INTERVAL);
    attroff(COLOR_PAIR(4));
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

    int pid = find_walletshield_pid();
    if (pid == -1) {
        endwin();
        printf("walletshield process not found!\n");
        return 1;
    }

    TCPConnection connections[MAX_CONNECTIONS];
    while (1) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;

        float cpu_usage = get_process_cpu_usage(pid);
        float mem_usage = get_process_mem_usage(pid);
        unsigned long read_bytes, write_bytes;
        get_process_io(pid, &read_bytes, &write_bytes);
        double uptime = get_process_uptime(pid);
        int conn_count = get_tcp_connections(connections, pid);

        draw_interface(pid, cpu_usage, mem_usage, read_bytes, write_bytes, uptime, connections, conn_count);
        sleep(UPDATE_INTERVAL);
    }

    endwin();
    return 0;
}
