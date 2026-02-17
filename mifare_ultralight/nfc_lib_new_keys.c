#include "nfc_lib.h"
#include <nfc/nfc.h>
#include <freefare.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Contexte global */
static nfc_context *ctx = NULL;

/*
static const MifareDESFireKey default_key =
    {0xff,0xff,0xff,0xff};


static const MifareDESFireKey mfu_key = {
    {0xff,0xff,0xff,0xff}
};*/



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
static MifareTag get_first_ultralight(nfc_device *dev) {
    MifareTag *tags = freefare_get_tags(dev);
    if (!tags) return NULL;

    MifareTag tag = tags[0];
    printf("detected tag = ",tag);
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

    MifareTag tag = get_first_ultralight(dev);
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

    freefare_free_tags(tag);
    nfc_close(dev);
    return 0;
}

/* ================= READ ================= */
// Lecture des 45 pages (4 bytes chacune)
int read_card(uint8_t pages[45][4], int *card_detected) {

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
    if (!tags) {
        nfc_close(dev);
        return 0;
    }


    MifareTag tag = NULL;
    for (int i = 0; tags[i]; i++) {
        if (freefare_get_tag_type(tags[i]) == NTAG_21x) {
            tag = tags[i];
            break;
        }
    }

    if (!tag) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return 0;
    }


    if (mifare_ultralight_connect(tag) < 0) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    *card_detected = 1;

    for (int page = 0; page < 45; page++) {
        MifareUltralightPage data;
        if (mifare_ultralight_read(tag, page, &data) == 0) {
            memcpy(pages[page], data, 4);
        }
    }
    

    mifare_ultralight_disconnect(tag);
    freefare_free_tags(tags);
    nfc_close(dev);
    printf("I'm here...\n");
    return 0;
}



/* ================= WRITE ================= */
// Écriture d'une page (4 bytes)
// ⚠️ Ne pas écrire pages 0–3 (UID + lock)
int write_page(int page, uint8_t data[4], int *card_detected) {

    *card_detected = 0;
    if (!ctx)
        return -1;

    if (page < 4 || page > 45)
        return -1;

    nfc_device *dev = nfc_open(ctx, NULL);
    if (!dev)
        return -1;

    if (nfc_initiator_init(dev) < 0) {
        nfc_close(dev);
        return -1;
    }

    MifareTag *tags = freefare_get_tags(dev);
    if (!tags) {
        nfc_close(dev);
        return -1;
    }

    MifareTag tag = NULL;
    for (int i = 0; tags[i]; i++) {
        if (freefare_get_tag_type(tags[i]) == MIFARE_ULTRALIGHT) {
            tag = tags[i];
            break;
        }
    }

    if (!tag) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    if (mifare_ultralight_connect(tag) < 0) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    *card_detected = 1;

    if (mifare_ultralight_write(tag, page, data) < 0) {
        mifare_ultralight_disconnect(tag);
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    mifare_ultralight_disconnect(tag);
    freefare_free_tags(tags);
    nfc_close(dev);
    return 0;
}