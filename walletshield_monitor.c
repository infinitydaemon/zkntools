#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ncurses.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define MAX_LINE 256
#define UPDATE_INTERVAL 1
#define PROCESS_NAME "walletshield"

int max_y, max_x;

void init_colors() {
    start_color();
    init_pair(1, COLOR_YELLOW, COLOR_BLACK);
    init_pair(2, COLOR_GREEN, COLOR_BLACK);
    init_pair(3, COLOR_RED, COLOR_BLACK);
    init_pair(4, COLOR_WHITE, COLOR_BLACK);
    bkgd(COLOR_PAIR(1));
}

int find_walletshield_pid() {
    FILE *fp = popen("pgrep -x walletshield", "r");
    if (!fp) return -1;

    int pid = -1;
    char buffer[32];
    if (fgets(buffer, sizeof(buffer), fp)) {
        pid = atoi(buffer);
    }
    pclose(fp);
    return pid;
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

    unsigned long utime, stime;
    sscanf(buffer, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
           &utime, &stime);

    static unsigned long last_utime = 0, last_stime = 0;
    static time_t last_time = 0;
    time_t now = time(NULL);
    float cpu_usage = 0.0;

    if (last_time != 0) {
        float elapsed = (float)(now - last_time) * sysconf(_SC_CLK_TCK);
        if (elapsed > 0) {
            cpu_usage = 100.0 * ((utime + stime) - (last_utime + last_stime)) / elapsed;
        }
    }

    last_utime = utime;
    last_stime = stime;
    last_time = now;

    return cpu_usage;
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

void draw_interface(int pid, float cpu_usage, float mem_usage) {
    clear();
    getmaxyx(stdscr, max_y, max_x);

    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw(0, (max_x - 20) / 2, "WalletShield Monitor");
    attroff(COLOR_PAIR(2) | A_BOLD);

    if (pid == -1) {
        attron(COLOR_PAIR(3) | A_BOLD);
        mvprintw(max_y/2, (max_x-30)/2, "walletshield not running!");
        attroff(COLOR_PAIR(3) | A_BOLD);
        refresh();
        return;
    }

    mvprintw(2, 2, "PID: %d", pid);

    // CPU Usage
    mvprintw(4, 2, "CPU Usage: %.1f%%", cpu_usage);
    attron(COLOR_PAIR(4));
    int cpu_bar = (int)(cpu_usage / 100.0 * (max_x - 20));
    for (int i = 0; i < cpu_bar && i < max_x - 20; i++) {
        mvaddch(5, 2 + i, '|');
    }
    attroff(COLOR_PAIR(4));

    // Memory Usage
    mvprintw(7, 2, "Memory Usage: %.1f%%", mem_usage);
    attron(COLOR_PAIR(4));
    int mem_bar = (int)(mem_usage / 100.0 * (max_x - 20));
    for (int i = 0; i < mem_bar && i < max_x - 20; i++) {
        mvaddch(8, 2 + i, '|');
    }
    attroff(COLOR_PAIR(4));

    attron(COLOR_PAIR(1));
    mvprintw(max_y - 1, 2, "Press 'q' to quit | Refresh every %ds", UPDATE_INTERVAL);
    attroff(COLOR_PAIR(1));
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

    while (1) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;

        int pid = find_walletshield_pid();
        float cpu_usage = 0.0, mem_usage = 0.0;

        if (pid != -1) {
            cpu_usage = get_process_cpu_usage(pid);
            mem_usage = get_process_mem_usage(pid);
        }

        draw_interface(pid, cpu_usage, mem_usage);
        sleep(UPDATE_INTERVAL);
    }

    endwin();
    return 0;
}
