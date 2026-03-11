cat << 'EOF' > test.c
#include "proxmark3.h"
#include "apps.h"
#include "iso14443a.h"
#include "string.h"

void RunIso14443AReader(void) {

    uint8_t atqa[2];
    uint8_t uid[10];
    uint8_t sak;
    uint8_t response[32];
    int len;

    Dbprintf("Initialisation ISO14443A Reader...\n");

    // Initialise le champ RF
    iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);

    // ---- REQA ----
    uint8_t reqa = 0x26;

    len = iso14443a_transceive_bits(&reqa, 7, atqa, sizeof(atqa), NULL);

    if (len <= 0) {
        Dbprintf("Erreur REQA\n");
        return;
    }

    Dbprintf("ATQA: %02x %02x\n", atqa[0], atqa[1]);

    // ---- Anticollision CL1 ----
    uint8_t anticoll[] = {0x93, 0x20};

    len = iso14443a_transceive(anticoll, 2, uid, sizeof(uid), NULL);

    if (len != 5) {
        Dbprintf("Erreur anticollision\n");
        return;
    }

    Dbprintf("UID CL1: %02x %02x %02x %02x\n",
             uid[0], uid[1], uid[2], uid[3]);

    // ---- Select ----
    uint8_t select[9];
    select[0] = 0x93;
    select[1] = 0x70;
    memcpy(&select[2], uid, 5);

    AddCrc14A(select, 7);

    len = iso14443a_transceive(select, 9, &sak, 1, NULL);

    if (len <= 0) {
        Dbprintf("Erreur SELECT\n");
        return;
    }

    Dbprintf("SAK: %02x\n", sak);

    // ---- Lecture page NTAG ----
    uint8_t read_cmd[] = {0x30, 0x04}; // Lire page 4

    AddCrc14A(read_cmd, 2);

    len = iso14443a_transceive(read_cmd, 4, response, sizeof(response), NULL);

    if (len > 0) {
        Dbprintf("Lecture page 4:\n");
        for (int i = 0; i < 16; i++) {
            Dbprintf("%02x ", response[i]);
        }
        Dbprintf("\n");
    }

    iso14443a_cleanup();
}
EOF