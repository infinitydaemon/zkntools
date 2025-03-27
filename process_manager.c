// ZKN Process manager
// Compile with gcc -o process_manager process_manager.c -lncurses
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <ncurses.h>
#include <sys/types.h>

#define MAX_PROCESSES 500
#define MAX_CMD_LENGTH 256

typedef struct {
    int pid;
    char cmd[MAX_CMD_LENGTH];
} Process;

Process processes[MAX_PROCESSES];
int process_count = 0;
int selected = 0;
int max_y, max_x;

void refresh_process_list() {
    process_count = 0;
    DIR *dir;
    struct dirent *ent;
    
    if ((dir = opendir("/proc")) != NULL) {
        while ((ent = readdir(dir)) != NULL && process_count < MAX_PROCESSES) {
            if (ent->d_type == DT_DIR) {
                char *endptr;
                long pid = strtol(ent->d_name, &endptr, 10);
                
                if (*endptr == '\0') {  // It's a valid PID
                    char path[256];
                    snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
                    
                    FILE *cmdline = fopen(path, "r");
                    if (cmdline != NULL) {
                        char cmd[MAX_CMD_LENGTH] = {0};
                        if (fgets(cmd, sizeof(cmd), cmdline) {
                            // Replace null bytes with spaces for display
                            for (int i = 0; i < strlen(cmd); i++) {
                                if (cmd[i] == '\0') cmd[i] = ' ';
                            }
                            processes[process_count].pid = (int)pid;
                            strncpy(processes[process_count].cmd, cmd, MAX_CMD_LENGTH-1);
                            process_count++;
                        }
                        fclose(cmdline);
                    }
                }
            }
        }
        closedir(dir);
    }
}

void draw_interface() {
    clear();
    getmaxyx(stdscr, max_y, max_x);
    
    // Title
    attron(A_BOLD);
    mvprintw(0, (max_x - 20) / 2, "Process Manager");
    attroff(A_BOLD);
    
    // Header
    mvprintw(2, 2, "PID");
    mvprintw(2, 10, "Command");
    
    // Process list
    int start = 0;
    if (selected >= max_y - 6) {
        start = selected - (max_y - 6) + 1;
    }
    
    for (int i = start; i < process_count && i < start + max_y - 6; i++) {
        if (i == selected) {
            attron(A_REVERSE);
        }
        
        mvprintw(4 + i - start, 2, "%d", processes[i].pid);
        mvprintw(4 + i - start, 10, "%.*s", max_x - 11, processes[i].cmd);
        
        if (i == selected) {
            attroff(A_REVERSE);
        }
    }
    
    // Footer
    mvprintw(max_y - 2, 2, "↑/↓: Navigate | k: Kill | r: Restart | q: Quit");
    
    refresh();
}

void kill_process() {
    if (process_count == 0) return;
    
    int pid = processes[selected].pid;
    char cmd[MAX_CMD_LENGTH + 50];
    snprintf(cmd, sizeof(cmd), "kill -9 %d", pid);
    
    int result = system(cmd);
    
    if (result == 0) {
        mvprintw(max_y - 3, 2, "Process %d killed successfully.", pid);
    } else {
        mvprintw(max_y - 3, 2, "Failed to kill process %d.", pid);
    }
    
    refresh();
    napms(1000); // Show message for 1 second
    refresh_process_list();
}

void restart_process() {
    if (process_count == 0) return;
    
    int pid = processes[selected].pid;
    char cmd_line[MAX_CMD_LENGTH];
    strcpy(cmd_line, processes[selected].cmd);
    
    // Terminate the process first
    char kill_cmd[MAX_CMD_LENGTH + 50];
    snprintf(kill_cmd, sizeof(kill_cmd), "kill -9 %d", pid);
    system(kill_cmd);
    
    // Restart the process (first word is the command)
    char *first_space = strchr(cmd_line, ' ');
    if (first_space) *first_space = '\0';
    
    char restart_cmd[MAX_CMD_LENGTH + 50];
    snprintf(restart_cmd, sizeof(restart_cmd), "%s &", cmd_line);
    
    int result = system(restart_cmd);
    
    if (result == 0) {
        mvprintw(max_y - 3, 2, "Process %s restarted successfully.", cmd_line);
    } else {
        mvprintw(max_y - 3, 2, "Failed to restart process %s.", cmd_line);
    }
    
    refresh();
    napms(1000); // Show message for 1 second
    refresh_process_list();
}

int main() {
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    
    refresh_process_list();
    
    int ch;
    while ((ch = getch()) != 'q') {
        switch (ch) {
            case KEY_UP:
                if (selected > 0) selected--;
                break;
            case KEY_DOWN:
                if (selected < process_count - 1) selected++;
                break;
            case 'k':
                kill_process();
                if (selected >= process_count) selected = process_count - 1;
                break;
            case 'r':
                restart_process();
                break;
        }
        draw_interface();
    }
    
    endwin();
    return 0;
}
