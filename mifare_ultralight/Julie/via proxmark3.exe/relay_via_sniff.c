cat << 'EOF' > naive.c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define PM3_EMIT "COM9"
#define PM3_SNIFF "COM10"
#define PM3_PATH "client\\proxmark3.exe"

// Fonction utilitaire pour extraire l'hexadécimal
void extract_hex(const char* line, char* out) {
    int pipe_count = 0;
    int j = 0;
    
    for (int i = 0; line[i] != '\0'; i++) {
        if (line[i] == '|') {
            pipe_count++;
            continue;
        }

        // Le format du log est : | Index | Timestamp | Src | DATA | CRC |
        // On veut ce qui se trouve entre le 3ème et le 4ème pipe
        if (pipe_count == 3) {
            // On ne garde que les caractères hexadécimaux et les espaces
            if (isxdigit(line[i]) || line[i] == ' ') {
                out[j++] = line[i];
            }
        }
        
        // On s'arrête dès qu'on atteint le 4ème pipe
        if (pipe_count >= 4) break;
    }
    out[j] = '\0';

    // Nettoyage des espaces à la fin
    int len = strlen(out);
    while (len > 0 && isspace((unsigned char)out[len - 1])) {
        out[--len] = '\0';
    }
}

int main() {
    char cmd[512];
    char buffer[1024];
    char captured_hex[256] = "";

    printf("=== AUTOMATE SNIFF > EMIT > LIST > REPLAY ===\n\n");

    // 1. ARMEMENT DU SNIFFER (PM3_SNIFF)
    // On lance le snoop en arrière-plan (avec START sur Windows pour ne pas bloquer le C)
    printf("[1/4] Armement du sniffer sur %s...\n", PM3_SNIFF);
    sprintf(cmd, "start /B %s %s -c \"hf 14a sniff\"", PM3_PATH, PM3_SNIFF);
    system(cmd);
    Sleep(2000); // On laisse 2 secondes au firmware pour passer en mode snoop

    // 2. ENVOI DE LA COMMANDE INITIALE (PM3_EMIT)
    printf("[2/4] PM3_1 envoie la commande source (REQA)...\n");
    sprintf(cmd, "%s %s -c \"hf 14a raw -a -k -c 26\"", PM3_PATH, PM3_EMIT);
    system(cmd);
    Sleep(1000);

    // 3. ARRÊT DU SNOOP ET LECTURE (PM3_SNIFF)
    //Attente de 5 secondes pour laisser le temps d'éteindre le sniff proprement
    printf("[*] Attente de 5 secondes pour laisser le temps d'arreter le sniff proprement...\n");
    Sleep(5000);
    // Envoyer une commande bidon permet de sortir du mode snoop proprement
    printf("[3/4] Recuperation des donnees sur %s...\n", PM3_SNIFF);
    sprintf(cmd, "%s %s -c \"hf 14a list\"", PM3_PATH, PM3_SNIFF);
    
    FILE* fp = _popen(cmd, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "Rdr")) { // On prend la ligne du Reader
                printf("    [SNIFF] Ligne brute: %s", buffer);
                extract_hex(buffer, captured_hex);
            }
        }
        _pclose(fp);
    }

    // 4. REJEU (PM3_SNIFF devient EMETTEUR)
    if (strlen(captured_hex) > 5) {
        printf("\n[!] TRAME DETECTEE : %s\n", captured_hex);
        printf("[4/4] PM3_2 rejoue la trame maintenant...\n");
        
        // On renvoie exactement ce qu'on a vu, sans recalculer le CRC (-k)
        sprintf(cmd, "%s %s -c \"hf 14a raw -a -k %s\"", PM3_PATH, PM3_SNIFF, captured_hex);
        system(cmd);
        printf("\n[SUCCESS] Sequence terminee.\n");
    } else {
        printf("\n[FAILURE] Rien n'a ete capture. Verifiez l'alignement des antennes.\n");
    }

    printf("\nAppuyez sur Entree pour quitter...");
    getchar();
    return 0;
}
EOF