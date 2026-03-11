#include <stdint.h>
#include <stdio.h>
#include "C:\\Users\\cel_l\\Documents\\P_Long\\ProxSpace-3.11\\pm3\\proxmark3\\client\\include\\pm3.h" // Hypothétique header avec SniffMifare et fonctions hardware

// Prototype de la fonction existante
void RAMFUNC SniffMifare(uint8_t param);

// Fonction "main" minimaliste pour lancer le sniffer
int main(void) {
    // Paramètres :
    // bit 0 = trigger sur la première réponse de carte
    // bit 1 = trigger sur la première requête 7-bit du lecteur
    uint8_t sniff_param = 0x03;  // active les deux triggers

    printf("Lancement du sniffer MIFARE...\n");

    // Appel de la fonction du firmware
    SniffMifare(sniff_param);

    // Quand SniffMifare retourne, on sait que l'arrêt a été demandé
    printf("Sniffer terminé.\n");

    return 0;
}