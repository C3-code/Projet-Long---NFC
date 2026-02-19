cat << 'EOF' > test.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Correction du chemin pour Windows (pas de ./ et double backslash)
    // Si proxmark3.exe est dans le dossier courant, mets juste "proxmark3.exe"
    char *command = "client\\proxmark3.exe -p COM10 -c \"hf 14a info\"";
    
    printf("Execution de la commande via le moteur Proxmark3...\n");
    
    // _popen lance la commande via cmd.exe
    FILE *fp = _popen(command, "r");
    if (fp == NULL) {
        printf("Erreur lors du lancement de l'executable\n");
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("PM3 -> %s", line);
    }

    _pclose(fp);
    return 0;
}
EOF