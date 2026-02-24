cat << 'EOF' > ping.c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define PM3_PORT "COM9"
#define PM3_PATH "client\\proxmark3.exe"

int main() {
    char cmd[512];
    
    printf("=== TEST DE CONNEXION PM3 (SINGLE) ===\n");
    printf("[*] Tentative de raw sur %s...\n\n", PM3_PORT);

    // Construction de la commande : hw ping
    // On ajoute 'exit' pour s'assurer que le client se ferme après la commande
    sprintf(cmd, "%s %s -c \"hf 14a raw -a -k -c 26\" ", PM3_PATH, PM3_PORT);

    // Exécution de la commande
    int result = system(cmd);

    printf("\n-----------------------------------\n");
    if (result == 0) {
        printf("[SUCCESS] Le Proxmark3 sur %s a repondu au raw.\n", PM3_PORT);
    } else {
        printf("[ERROR] Echec du raw (Code retour : %d).\n", result);
        printf("Verifiez que le port %s est correct et non utilise.\n", PM3_PORT);
    }
    

    printf("\nAppuyez sur Entree pour fermer...");
    getchar();

    return 0;
}
EOF