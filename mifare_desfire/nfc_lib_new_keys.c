#include <nfc/nfc.h>
#include <freefare.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nfc_context *ctx = NULL;

/* ================= READ DESFIRE ================= */

int read_card(uint8_t *data_out, size_t *data_len, int *card_detected)
{
    *card_detected = 0;
    *data_len = 0;

    if (!ctx)
        return -1;

    nfc_device *dev = nfc_open(ctx, NULL);
    if (!dev)
        return -1;

    if (nfc_initiator_init(dev) < 0) {
        nfc_close(dev);
        return -1;
    }

    FreefareTag *tags = freefare_get_tags(dev);
    if (!tags || !tags[0]) {
        nfc_close(dev);
        return 0; // aucune carte
    }

    FreefareTag tag = tags[0];

    if (freefare_get_tag_type(tag) != MIFARE_DESFIRE) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    if (mifare_desfire_connect(tag) < 0) {
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    *card_detected = 1;

    /* -------- Sélection Application -------- */
    MifareDESFireAID aid = mifare_desfire_aid_new(0x000001);

    if (mifare_desfire_select_application(tag, aid) < 0) {
        mifare_desfire_disconnect(tag);
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    /* -------- Authentification AES (optionnel) -------- */
    uint8_t aes_key_data[16] = {0x00}; // clé 0 par défaut
    MifareDESFireKey key = mifare_desfire_aes_key_new(aes_key_data);

    if (mifare_desfire_authenticate_aes(tag, 0x00, key) < 0) {
        printf("Auth échouée (peut être non nécessaire)\n");
    }

    /* -------- Lecture fichier -------- */
    int bytes_read = mifare_desfire_read_data(
        tag,
        0x01,        // file ID
        0,           // offset
        0,           // length = 0 → tout lire
        data_out
    );

    if (bytes_read < 0) {
        mifare_desfire_disconnect(tag);
        freefare_free_tags(tags);
        nfc_close(dev);
        return -1;
    }

    *data_len = bytes_read;

    /* -------- Cleanup -------- */
    mifare_desfire_disconnect(tag);
    freefare_free_tags(tags);
    nfc_close(dev);

    return 0;
}
