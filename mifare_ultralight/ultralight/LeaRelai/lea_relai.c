#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <stdint.h>

typedef enum {
    STATE_IDLE,
    STATE_CL1,
    STATE_CL2,
    STATE_SELECTED
} iso_state_t;


void proxy_emulator(void)
{
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    uint8_t rx[64];
    uint8_t tx[64];
    int len;

    iso_state_t state = STATE_IDLE;

    // UID réel (à synchroniser avec proxmark B)
    uint8_t uid[7] = {0x04,0x59,0x78,0xCA,0x34,0x12,0x90};

    uint8_t bcc1 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2];
    uint8_t bcc2 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6];

    while (1) {
        uint8_t par;
        len = GetIso14443aCommandFromReader(rx, par, sizeof(rx));
        if (len <= 0)
            continue;

        // REQA
        if (rx[0] == 0x26) {
            tx[0] = 0x44;
            tx[1] = 0x00;
            iso14443a_transmit(tx, 2, 0); //répondre ATQA
            state = STATE_CL1;
        }
        /*
        // ANTICOLLISION CL1
        else if (rx[0] == 0x93 && rx[1] == 0x20 && state == STATE_CL1) {
            tx[0] = 0x88;
            tx[1] = uid[0];
            tx[2] = uid[1];
            tx[3] = uid[2];
            tx[4] = bcc1;
            iso14443a_transmit(tx, 5, 0); //répondre CL1
        }

        // SELECT CL1
        else if (rx[0] == 0x93 && rx[1] == 0x70) {
            tx[0] = 0x04;  // SAK cascade bit set
            iso14443a_transmit(tx, 1, ISO14443A_APPEND_CRC);
            state = STATE_CL2;
        }

        // ANTICOLLISION CL2
        else if (rx[0] == 0x95 && rx[1] == 0x20 && state == STATE_CL2) {
            tx[0] = uid[3];
            tx[1] = uid[4];
            tx[2] = uid[5];
            tx[3] = uid[6];
            tx[4] = bcc2;
            iso14443a_transmit(tx, 5, 0); //répondre CL2
        }

        // SELECT CL2
        else if (rx[0] == 0x95 && rx[1] == 0x70) {
            tx[0] = 0x00;  // SAK final
            iso14443a_transmit(tx, 1, ISO14443A_APPEND_CRC);
            state = STATE_SELECTED;
        }
        
        // MITM FORWARD
        else if (state == STATE_SELECTED) {
            // Envoyer commande lecteur → PC
            reply_ng(CMD_USER_1, rx, len);

            // Attendre réponse du PC
            uint8_t usb_buf[64];
            PacketResponseNG resp;
            if (receive_ng(&resp) == PM3_SUCCESS && resp.cmd == CMD_USER_1) {
                iso14443a_transmit(resp.data, resp.length, ISO14443A_APPEND_CRC);
            }
        }*/
    }
}
/*void mole_reader(void)
{
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    uint8_t rx[64];
    uint8_t tx[64];

    while (1) {
        PacketResponseNG resp;

        // Attendre commande venant PC
        if (receive_ng(&resp) != PM3_SUCCESS)
            continue;

        if (resp.cmd != CMD_USER_2)
            continue;

        // Transmettre au vrai tag
        iso14443a_transmit(resp.data, resp.length, ISO14443A_APPEND_CRC);
        int len = iso14443a_receive(rx, sizeof(rx));

        if (len > 0) {
            reply_ng(CMD_USER_2, rx, len);
        }
    }
}


/*cote pc
while (1) {

    // Lire commande venant Proxmark A
    read(serialA, bufferA, ...);

    // Envoyer à Proxmark B
    write(serialB, bufferA, ...);

    // Lire réponse Proxmark B
    read(serialB, bufferB, ...);

    // Renvoyer à Proxmark A
    write(serialA, bufferB, ...);
}*/

int main() {

    int serial_port = open("/dev/ttyACM0", O_RDWR | O_NOCTTY);
    if (serial_port < 0) {
        printf("Erreur %i : %s\n", errno, strerror(errno));
        return 1;
    }

    struct termios tty;
    tcgetattr(serial_port, &tty);
    tty.c_cflag |= (CLOCAL | CREAD);
    cfmakeraw(&tty); // Mode brut : pas d'interprétation des caractères
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);

    // Timeout de lecture : attend jusqu'à 100ms (1 déci-seconde) pour au moins 1 octet
    tty.c_cc[VTIME] = 1;
    tty.c_cc[VMIN] = 5;
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tcsetattr(serial_port, TCSANOW, &tty);
    tcflush(serial_port, TCIOFLUSH); // Nettoyage des buffers

    // Paquet PING complet (Standard Proxmark3 NG)
    // Format : [PREAMBLE: 2b] [CMD: 2b] [LEN: 2b] [CRC: 2b] (ici CRC simplifié/absent selon firmware)
    // Pour un Ping simple sur firmware Iceman, on peut souvent utiliser ce format :
/*
    unsigned char ping_cmd[] = {
        0x43, 0x48,             // "CH" Preamble
        0x01, 0x00,             // CMD_PING (0x0101)
        0x00, 0x00,             // Payload Length (0)
        0x00, 0x00              // CRC (Souvent ignoré sur un ping simple, ou 0 pour test)
    };

    printf("Envoi du Ping (Protocole NG)...\n");
    write(serial_port, ping_cmd, sizeof(ping_cmd));

    // Lecture de la réponse
    usleep(150000); // Petit dodo pour laisser le temps au CPU du PM3
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

    //tag_emulation();


    close(serial_port);
    return 0;

    // -------- Frame PM3a minimale --------

    uint8_t frame[42];

    // Magic
    frame[0] = 0x50;
    frame[1] = 0x4D;
    frame[2] = 0x33;
    frame[3] = 0x61;

    // Flags 0x8020 (little endian)
    frame[4] = 0x20;
    frame[5] = 0x80;

    // Length 0x0109 (little endian)
    frame[6] = 0x09;
    frame[7] = 0x01;

    // Cmd 0x0100 (little endian)
    frame[8] = 0x00;
    frame[9] = 0x01;

    // Payload 32 bytes
    for(int i = 0; i < 32; i++)
        frame[10 + i] = i;

    // Postamble 0x3361 (little endian → 61 33)
    frame[42 - 2] = 0x61;
    frame[42 - 1] = 0x33;

    printf("Envoi Ping PM3a...\n");
    for (int i = 0; i < 42; i++)
            printf("%02X ", frame[i]);
        printf("\n");
    write(serial_port, frame, sizeof(frame));

    // -------- Lecture réponse --------

    uint8_t buf[256];
    int n = read(serial_port, buf, sizeof(buf));

    if (n > 0) {
        printf("Réponse (%d octets):\n", n);
        for (int i = 0; i < n; i++)
            printf("%02X ", buf[i]);
        printf("\n");
    } else {
        printf("Aucune réponse\n");
    }*/
    proxy_emulator();

    close(serial_port);
    return 0;
}