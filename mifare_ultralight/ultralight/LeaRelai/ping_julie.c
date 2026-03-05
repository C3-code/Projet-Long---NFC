#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>

int main() {

    int serial_port = open("/dev/ttyACM0", O_RDWR | O_NOCTTY);
    if (serial_port < 0) {
        printf("Erreur %i : %s\n", errno, strerror(errno));
        return 1;
    }

    struct termios tty;
    tcgetattr(serial_port, &tty);
    cfmakeraw(&tty); // Mode brut : pas d'interprétation des caractères
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);

    // Timeout de lecture : attend jusqu'à 100ms (1 déci-seconde) pour au moins 1 octet
    tty.c_cc[VTIME] = 1;
    tty.c_cc[VMIN] = 0;

    tcsetattr(serial_port, TCSANOW, &tty);
    tcflush(serial_port, TCIOFLUSH); // Nettoyage des buffers

    // Paquet PING complet (Standard Proxmark3 NG)
    // Format : [PREAMBLE: 2b] [CMD: 2b] [LEN: 2b] [CRC: 2b] (ici CRC simplifié/absent selon firmware)
    // Pour un Ping simple sur firmware Iceman, on peut souvent utiliser ce format :

    unsigned char ping_cmd[] = {
        0x43, 0x48,             // "CH" Preamble
        0x01, 0x01,             // CMD_PING (0x0101)
        0x00, 0x00,             // Payload Length (0)
        0x00, 0x00              // CRC (Souvent ignoré sur un ping simple, ou 0 pour test)
    };

    printf("Envoi du Ping (Protocole NG)...\n");
    write(serial_port, ping_cmd, sizeof(ping_cmd));

    // Lecture de la réponse
    usleep(50000); // Petit dodo pour laisser le temps au CPU du PM3
    unsigned char buf[256];
    int n = read(serial_port, buf, sizeof(buf));

    if (n > 0) {
        printf("Réponse (%d octets) : ", n);
        for(int i = 0; i < n; i++) printf("%02X ", buf[i]);
        printf("\n");
      
        // Si les premiers octets sont 0x43 0x48, c'est gagné !
        if (buf[0] == 0x43 && buf[1] == 0x48) printf("Statut : Proxmark3 est ALIVE !\n");
    } else {
        printf("Aucune réponse. Vérifiez que le client PM3 n'est pas déjà ouvert.\n");
    }

    close(serial_port);
    return 0;
}