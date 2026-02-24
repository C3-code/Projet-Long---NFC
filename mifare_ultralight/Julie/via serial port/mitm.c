cat << 'EOF' > mitm.c
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include "uart.h"

#define PORT_MOLE  "COM9"
#define PORT_PROXY "COM10"
#define BAUD_RATE  115200

//Besoin de copier là où on execute les fonctions suivantes : 
//comms.h
//pm3_cmd.h 
//util.h


// Commande simplifiée pour passer en mode sniff/relais (exemple générique)
// Note: Dans un vrai environnement PM3, ces commandes sont des paquets USB structurés.
const uint8_t CMD_INIT_MOLE[]  = {0x01, 0x00, 0x0D, 0x00}; // Exemple de paquet PM3
const uint8_t CMD_INIT_PROXY[] = {0x02, 0x00, 0x0D, 0x00}; 

void relay_loop(serial_port sp1, serial_port sp2) {
    uint8_t buffer[2048];
    uint32_t len;
    
    printf("[!] Pont actif. Ctrl+C pour arreter.\n");
    while (1) {
        // Sens : Tag (Mole) -> Lecteur (Proxy)
        if (uart_receive(sp1, buffer, sizeof(buffer), &len) == PM3_SUCCESS && len > 0) {
            uart_send(sp2, buffer, len);
            printf("Tag >> %u octets >> Lecteur\n", len);
        }
        
        // Sens : Lecteur (Proxy) -> Tag (Mole)
        if (uart_receive(sp2, buffer, sizeof(buffer), &len) == PM3_SUCCESS && len > 0) {
            uart_send(sp1, buffer, len);
            printf("Lecteur << %u octets << Tag\n", len);
        }
        
        Sleep(1); // Evite de consommer 100% du CPU
    }
}

int main() {
    serial_port spMole, spProxy;

    printf("--- DEMARRAGE MITM NFC ULTRALIGHT ---\n");

    // Connexion au Mole
    spMole = uart_open(PORT_MOLE, BAUD_RATE, false);
    if (spMole == INVALID_SERIAL_PORT) return printf("Echec COM9\n"), 1;
    
    // Connexion au Proxy
    spProxy = uart_open(PORT_PROXY, BAUD_RATE, false);
    if (spProxy == INVALID_SERIAL_PORT) return printf("Echec COM10\n"), 1;

    printf("[+] Ports ouverts. Initialisation des modes...\n");

    // On envoie les commandes pour mettre les PM3 dans le bon état
    // Ici, on part du principe que tes PM3 ont un firmware capable de streamer le RAW
    uart_send(spMole, CMD_INIT_MOLE, sizeof(CMD_INIT_MOLE));
    uart_send(spProxy, CMD_INIT_PROXY, sizeof(CMD_INIT_PROXY));

    Sleep(500); // Laisse le temps au firmware de changer d'état

    relay_loop(spMole, spProxy);

    uart_close(spMole);
    uart_close(spProxy);
    return 0;
}
EOF