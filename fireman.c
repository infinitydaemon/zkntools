​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// Define the FirewallRule structure
typedef struct {
    char chain[10];      // "INPUT", "OUTPUT", "FORWARD"
    char source_ip[16];  // IPv4 address
    char dest_ip[16];
    int source_port;     // 0 if not specified
    int dest_port;       // 0 if not specified
    char protocol[4];    // "TCP", "UDP", "ICMP"
    char action[6];      // "ACCEPT", "DROP", "REJECT", "LOG"
} FirewallRule;

// Define the RuleNode structure for the linked list
typedef struct RuleNode {
    FirewallRule rule;
    struct RuleNode* next;
} RuleNode;

// Validate a firewall rule
int validate_rule(FirewallRule* rule) {
    struct in_addr addr;
    // Validate source IP if specified
    if (strlen(rule->source_ip) > 0 && inet_pton(AF_INET, rule->source_ip, &addr) != 1) {
        return 0;
    }
    // Validate destination IP if specified
    if (strlen(rule->dest_ip) > 0 && inet_pton(AF_INET, rule->dest_ip, &addr) != 1) {
        return 0;
    }
    // Validate port ranges
    if (rule->source_port < 0 || rule->source_port > 65535) {
        return 0;
    }
    if (rule->dest_port < 0 || rule->dest_port > 65535) {
        return 0;
    }
    // Validate protocol
    if (strcmp(rule->protocol, "TCP") != 0 && strcmp(rule->protocol, "UDP") != 0 && 
        strcmp(rule->protocol, "ICMP") != 0) {
        return 0;
    }
    // Validate action
    if (strcmp(rule->action, "ACCEPT") != 0 && strcmp(rule->action, "DROP") != 0 && 
        strcmp(rule->action, "REJECT") != 0 && strcmp(rule->action, "LOG") != 0) {
        return 0;
    }
    // Validate chain
    if (strcmp(rule->chain, "INPUT") != 0 && strcmp(rule->chain, "OUTPUT") != 0 && 
        strcmp(rule->chain, "FORWARD") != 0) {
        return 0;
    }
    return 1;
}

// Add a new rule to the linked list
void add_rule(RuleNode** head) {
    FirewallRule new_rule;
    printf("Enter chain (INPUT, OUTPUT, FORWARD): ");
    scanf("%9s", new_rule.chain);
    printf("Enter source IP (or leave blank for any): ");
    scanf("%15s", new_rule.source_ip);
    printf("Enter destination IP (or leave blank for any): ");
    scanf("%15s", new_rule.dest_ip);
    printf("Enter source port (0 for any): ");
    scanf("%d", &new_rule.source_port);
    printf("Enter destination port (0 for any): ");
    scanf("%d", &new_rule.dest_port);
    printf("Enter protocol (TCP, UDP, ICMP): ");
    scanf("%3s", new_rule.protocol);
    printf("Enter action (ACCEPT, DROP, REJECT, LOG): ");
    scanf("%5s", new_rule.action);

    // Validate the rule
    if (!validate_rule(&new_rule)) {
        printf("Invalid rule.\n");
        return;
    }

    // Allocate memory for the new node
    RuleNode* new_node = (RuleNode*)malloc(sizeof(RuleNode));
    if (!new_node) {
        printf("Memory allocation failed.\n");
        return;
    }
    new_node->rule = new_rule;
    new_node->next = *head;
    *head = new_node;
    printf("Rule added successfully.\n");
}

// Delete a rule by index
void delete_rule(RuleNode** head, int index) {
    if (*head == NULL) {
        printf("No rules to delete.\n");
        return;
    }
    if (index == 0) {
        RuleNode* temp = *head;
        *head = (*head)->next;
        free(temp);
        printf("Rule deleted successfully.\n");
        return;
    }
    RuleNode* current = *head;
    int i = 0;
    while (current->next != NULL && i < index - 1) {
        current = current->next;
        i++;
    }
    if (current->next == NULL) {
        printf("Index out of range.\n");
        return;
    }
    RuleNode* temp = current->next;
    current->next = temp->next;
    free(temp);
    printf("Rule deleted successfully.\n");
}

// List all rules
void list_rules(RuleNode* head) {
    if (!head) {
        printf("No rules defined.\n");
        return;
    }
    printf("Index\tChain\tSource IP\tDest IP\tSrc Port\tDst Port\tProtocol\tAction\n");
    RuleNode* current = head;
    int index = 0;
    while (current != NULL) {
        printf("%d\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
               index,
               current->rule.chain,
               current->rule.source_ip,
               current->rule.dest_ip,
               current->rule.source_port,
               current->rule.dest_port,
               current->rule.protocol,
               current->rule.action);
        current = current->next;
        index++;
    }
}

// Save rules to a file
void save_rules(RuleNode* head, const char* filename) {
    FILE* fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }
    RuleNode* current = head;
    while (current != NULL) {
        fprintf(fp, "%s,%s,%s,%d,%d,%s,%s\n",
                current->rule.chain,
                current->rule.source_ip,
                current->rule.dest_ip,
                current->rule.source_port,
                current->rule.dest_port,
                current->rule.protocol,
                current->rule.action);
        current = current->next;
    }
    fclose(fp);
    printf("Rules saved to %s.\n", filename);
}

// Load rules from a file
void load_rules(RuleNode** head, const char* filename) {
    // Free existing rules
    free_rules(*head);
    *head = NULL;

    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char chain[10], source_ip[16], dest_ip[16], source_port_str[6], dest_port_str[6], protocol[4], action[6];
        int n = sscanf(line, "%9[^,],%15[^,],%15[^,],%5[^,],%5[^,],%3[^,],%5s",
                       chain, source_ip, dest_ip, source_port_str, dest_port_str, protocol, action);
        if (n == 7) {
            FirewallRule rule;
            strcpy(rule.chain, chain);
            strcpy(rule.source_ip, source_ip);
            strcpy(rule.dest_ip, dest_ip);
            rule.source_port = (strlen(source_port_str) > 0) ? atoi(source_port_str) : 0;
            rule.dest_port = (strlen(dest_port_str) > 0) ? atoi(dest_port_str) : 0;
            strcpy(rule.protocol, protocol);
            strcpy(rule.action, action);
            if (validate_rule(&rule)) {
                RuleNode* new_node = (RuleNode*)malloc(sizeof(RuleNode));
                if (!new_node) {
                    printf("Memory allocation failed.\n");
                    fclose(fp);
                    return;
                }
                new_node->rule = rule;
                new_node->next = *head;
                *head = new_node;
            } else {
                printf("Invalid rule in file: %s", line);
            }
        } else {
            printf("Invalid rule format in file: %s", line);
        }
    }
    fclose(fp);
    printf("Rules loaded from %s.\n", filename);
}

// Apply rules using iptables-restore
void apply_rules(RuleNode* head) {
    char template[] = "/tmp/firewall_rules_XXXXXX";
    int fd = mkstemp(template);
    if (fd == -1) {
        perror("Error creating temporary file");
        return;
    }
    FILE* fp = fdopen(fd, "w");
    if (fp == NULL) {
        perror("Error opening temporary file");
        close(fd);
        return;
    }
    // Write iptables-restore format
    fprintf(fp, "*filter\n");
    fprintf(fp, ":INPUT ACCEPT [0:0]\n");
    fprintf(fp, ":FORWARD ACCEPT [0:0]\n");
    fprintf(fp, ":OUTPUT ACCEPT [0:0]\n");
    RuleNode* current = head;
    while (current != NULL) {
        fprintf(fp, "-A %s", current->rule.chain);
        if (strlen(current->rule.protocol) > 0) {
            fprintf(fp, " -p %s", current->rule.protocol);
        }
        if (strlen(current->rule.source_ip) > 0) {
            fprintf(fp, " -s %s", current->rule.source_ip);
        }
        if (strlen(current->rule.dest_ip) > 0) {
            fprintf(fp, " -d %s", current->rule.dest_ip);
        }
        if (current->rule.source_port > 0) {
            fprintf(fp, " --sport %d", current->rule.source_port);
        }
        if (current->rule.dest_port > 0) {
            fprintf(fp, " --dport %d", current->rule.dest_port);
        }
        fprintf(fp, " -j %s\n", current->rule.action);
        current = current->next;
    }
    fprintf(fp, "COMMIT\n");
    fclose(fp);

    // Apply the rules
    char command[256];
    sprintf(command, "iptables-restore < %s", template);
    int result = system(command);
    if (result != 0) {
        printf("Error applying rules. Ensure you have root privileges.\n");
    } else {
        printf("Rules applied successfully.\n");
    }
    unlink(template); // Remove the temporary file
}

// Free the linked list
void free_rules(RuleNode* head) {
    RuleNode* current = head;
    while (current != NULL) {
        RuleNode* temp = current;
        current = current->next;
        free(temp);
    }
}

// Main function with menu-driven interface
int main() {
    RuleNode* rules = NULL;
    int choice;
    char filename[256];

    do {
        printf("\nFirewall Management Program\n");
        printf("1. Add rule\n");
        printf("2. Delete rule\n");
        printf("3. List rules\n");
        printf("4. Save rules\n");
        printf("5. Load rules\n");
        printf("6. Apply rules\n");
        printf("7. Exit\n");
        printf("Enter choice: ");
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }

        switch (choice) {
            case 1:
                add_rule(&rules);
                break;
            case 2:
                list_rules(rules);
                int index;
                printf("Enter index to delete: ");
                if (scanf("%d", &index) != 1) {
                    printf("Invalid index.\n");
                    while (getchar() != '\n');
                    break;
                }
                delete_rule(&rules, index);
                break;
            case 3:
                list_rules(rules);
                break;
            case 4:
                printf("Enter filename to save: ");
                scanf("%255s", filename);
                save_rules(rules, filename);
                break;
            case 5:
                printf("Enter filename to load: ");
                scanf("%255s", filename);
                load_rules(&rules, filename);
                break;
            case 6:
                apply_rules(rules);
                break;
            case 7:
                free_rules(rules);
                printf("Exiting program.\n");
                return 0;
            default:
                printf("Invalid choice. Please select 1-7.\n");
        }
    } while (1);

    return 0;
}
​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​​
