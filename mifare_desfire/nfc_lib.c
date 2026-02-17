#include "nfc_lib.h"
#include <nfc/nfc.h>
#include <freefare.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Contexte global */
static nfc_context *ctx = NULL;


static const MifareClassicKey default_key =
    {0xff,0xff,0xff,0xff,0xff,0xff};

static const MifareClassicKey key_a[16] = {
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0x25,0x46,0x85,0x71,0x02,0x36},
    {0x94,0x46,0x27,0x46,0x02,0x15},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff}
};

static const MifareClassicKey key_b[16] = {
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0x48,0x56,0x12,0x84,0x76,0x25},
    {0x15,0x25,0x13,0x49,0x58,0x45},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff},
    {0xff,0xff,0xff,0xff,0xff,0xff}
};


/* ================= INIT ================= */
int nfc_init_context(void) {
    if (ctx) return 0;  // déjà initialisé
    nfc_init(&ctx);
    return ctx ? 0 : -1;
}

void nfc_exit_context(void) {
    if (ctx) {
        nfc_exit(ctx);
        ctx = NULL;
    }
}

/* ================= UTIL ================= */
// Récupère le premier tag Mifare Classic 1K détecté
static MifareTag get_first_classic(nfc_device *dev) {
    MifareTag *tags = freefare_get_tags(dev);
    if (!tags) return NULL;

    MifareTag tag = tags[0];

    return tag;
}

/* ================= GET UID ================= */
int get_uid(char *uid, int uid_len, int *card_detected) {
    *card_detected = 0;
    if (!ctx) return -1;

    nfc_device *dev = nfc_open(ctx, NULL);
    if (!dev) return -1;

    if (nfc_initiator_init(dev) < 0) {
        nfc_close(dev);
        return -1;
    }

    MifareTag tag = get_first_classic(dev);
    if (!tag) {
        nfc_close(dev);
        return 0;
    }

    char *tmp = freefare_get_tag_uid(tag);
    if (tmp) {
        strncpy(uid, tmp, uid_len - 1);
        uid[uid_len - 1] = 0;
        free(tmp);
        *card_detected = 1;
    }

    freefare_free_tag(tag);
    nfc_close(dev);
    return 0;
}


int read_card(uint8_t blocks[64][16], int *card_detected) {
    *card_detected = 0;
    if (!ctx)
        return -1;

    nfc_device *dev = nfc_open(ctx, NULL);
    if (!dev)
        return -1;

    if (nfc_initiator_init(dev) < 0) {
        nfc_close(dev);
        return -1;
    }

    MifareTag *tags = freefare_get_tags(dev);
    if (!tags) { // aucun tag détecté
        nfc_close(dev);
        return 0;
    }

    MifareTag tag = tags[0];
    if (!tag) {  // le premier tag est NULL
        freefare_free_tags(tags);
        nfc_close(dev);
        return 0;
    }

    if (mifare_classic_connect(tag) < 0) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    *card_detected = 1;

    for (int s = 0; s < 16; s++) {
        int first = s * 4;

        if (mifare_classic_authenticate(tag, first, key_a[s], MFC_KEY_A) < 0 &&
            mifare_classic_authenticate(tag, first, default_key, MFC_KEY_A) < 0)
            continue;

        for (int b = first; b < first + 4; b++) {
            MifareClassicBlock data;
            if (mifare_classic_read(tag, b, &data) == 0)
                memcpy(blocks[b], data, 16);
        }
    }

    mifare_classic_disconnect(tag);
    freefare_free_tags(tags); // libère le tableau complet
    nfc_close(dev);
    return 0;
}


/* ================= WRITE ================= */
int write_block(int block, uint8_t data[16], int *card_detected) {
    *card_detected = 0;
    if (!ctx)
        return -1;

    int sector = block / 4;
    if (sector != 1 && sector != 2)  // autorisé seulement secteurs 1 et 2
        return -1;

    nfc_device *dev = nfc_open(ctx, NULL);
    if (!dev)
        return -1;

    if (nfc_initiator_init(dev) < 0) {
        nfc_close(dev);
        return -1;
    }

    MifareTag *tags = freefare_get_tags(dev);
    if (!tags) { // aucun tag détecté
        nfc_close(dev);
        return -1;
    }

    MifareTag tag = tags[0];
    if (!tag) { // premier tag NULL
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    if (mifare_classic_connect(tag) < 0) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    *card_detected = 1;

    // Authentification avec Key B
    int a = mifare_classic_authenticate(tag, block, key_b[sector], MFC_KEY_B);
    printf("a = %d\n", a);
    int b = 1;
    if (a != 0) {
      b = mifare_classic_authenticate(tag, block, default_key, MFC_KEY_B);
    }
      
    printf("b = %d\n", b);
    if (a == 0 || b == 0) {
    // Écriture du bloc
    if (mifare_classic_write(tag, block, data) < 0) {
        printf("Erreur durant l'ecriture du bloc.\n");
        mifare_classic_disconnect(tag);
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

      printf("success\n");
    }
    else {
        printf("Erreur durant l'auth.\n");
        mifare_classic_disconnect(tag);
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    mifare_classic_disconnect(tag);
    freefare_free_tags(tags);
    return 0;
}

int factory_init(int *card_detected) {
    *card_detected = 0;
    if (!ctx)
        return -1;

    nfc_device *dev = nfc_open(ctx, NULL);
    if (!dev)
        return -1;

    if (nfc_initiator_init(dev) < 0) {
        nfc_close(dev);
        return -1;
    }

    MifareTag *tags = freefare_get_tags(dev);
    if (!tags || !tags[0]) {
        nfc_close(dev);
        return 0;
    }

    MifareTag tag = tags[0];

    if (mifare_classic_connect(tag) < 0) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    *card_detected = 1;

    uint8_t trailer[16];
    uint8_t access_bits[4] = {0xFF, 0x07, 0x80, 0x69};

    for (int sector = 1; sector <= 2; sector++) {
        int trailer_block = sector * 4 + 3;

        // Auth avec Key A par défaut
        if (mifare_classic_authenticate(tag, trailer_block,
            default_key, MFC_KEY_A) < 0)
            continue;

        memcpy(trailer, key_a[sector], 6);
        memcpy(trailer + 6, access_bits, 4);
        memcpy(trailer + 10, key_b[sector], 6);

        mifare_classic_write(tag, trailer_block, trailer);
    }

    mifare_classic_disconnect(tag);
    freefare_free_tags(tags);
    nfc_close(dev);
    return 0;
}

