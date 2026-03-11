#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "client/src/uart/uart.h"

int main(void)
{
    // Ouvrir le port série
    serial_port sp = uart_open("COM3", 115200, false);
    if (sp == INVALID_SERIAL_PORT) {
        printf("Erreur ouverture port\n");
        return -1;
    }

    printf("Port ouvert avec succes\n");

    // Trame LED (00010400 en hex)
    uint8_t led_cmd[] = {0x00, 0x01, 0x04, 0x00};

    int res = uart_send(sp, led_cmd, sizeof(led_cmd));
    if (res != PM3_SUCCESS) {
        printf("Erreur envoi\n");
        uart_close(sp);
        return -1;
    }

    printf("Commande envoyee\n");

    // Optionnel : lire une réponse
    uint8_t rxbuf[256];
    uint32_t rxlen = 0;

    res = uart_receive(sp, rxbuf, sizeof(rxbuf), &rxlen);
    if (res == PM3_SUCCESS && rxlen > 0) {
        printf("Recu %u octets:\n", rxlen);
        for (uint32_t i = 0; i < rxlen; i++) {
            printf("%02X ", rxbuf[i]);
        }
        printf("\n");
    } else {
        printf("Pas de reponse\n");
    }

    // Fermer connexion
    uart_close(sp);
    printf("Connexion fermee\n");

    return 0;
}
