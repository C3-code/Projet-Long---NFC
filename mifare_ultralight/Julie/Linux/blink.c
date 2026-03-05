
#include <stdio.h>

#include <string.h>

#include <fcntl.h>

#include <termios.h>

#include <unistd.h>


// Commande pour les LEDs sur Proxmark3 (CMD_SET_LEDS = 0x0103)

#define CMD_SET_LEDS 0x03, 0x01 


void send_led_cmd(int fd, unsigned char led_mask) {

    unsigned char packet[] = {

        0x43, 0x48,       // Préambule "CH"

        CMD_SET_LEDS,     // Commande 0x0103

        0x08, 0x00,       // Longueur du payload (8 octets pour les LEDs)

        led_mask, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Data (Masque LED)

        0x00, 0x00        // CRC (Optionnel/0 sur beaucoup de versions)

    };

    write(fd, packet, sizeof(packet));

    tcdrain(fd); // Attend que l'envoi soit fini

}


int main() {

    int fd = open("/dev/ttyACM0", O_RDWR | O_NOCTTY);

    if (fd < 0) {

        perror("Erreur ouverture");

        return 1;

    }


    struct termios tty;

    tcgetattr(fd, &tty);

    cfmakeraw(&tty);

    cfsetispeed(&tty, B115200);

    tcsetattr(fd, TCSANOW, &tty);


    printf("Début du clignotement... (Ctrl+C pour arrêter)\n");


    // Boucle de clignotement

    while(1) {

        printf("LEDs ON\n");

        send_led_cmd(fd, 0xFF); // 0xFF allume toutes les LEDs disponibles

        usleep(500000);         // 500ms


        printf("LEDs OFF\n");

        send_led_cmd(fd, 0x00); // 0x00 éteint tout

        usleep(500000);

    }


    close(fd);

    return 0;

}

