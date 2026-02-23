//cat << 'EOF' > relai.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nfc/nfc.h>

#define MAX_FRAME_LEN 264

int main() {

    nfc_context *context;
    nfc_device *dev_reader = NULL;   // vers vrai tag
    nfc_device *dev_emulator = NULL; // vers lecteur externe

    nfc_init(&context);
    if (!context) {
        printf("Erreur init libnfc\n");
        return -1;
    }

    nfc_connstring devices[8];
    size_t device_count = nfc_list_devices(context, devices, 8);

    if (device_count < 2) {
        printf("Il faut 2 Proxmark3 connectés\n");
        return -1;
    }

    // Si on a  :
    // devices[0] = Mole (vers vrai tag)
    // devices[1] = Proxy (vers lecteur externe)

    dev_reader = nfc_open(context, devices[0]);
    dev_emulator = nfc_open(context, devices[1]);

    if (!dev_reader || !dev_emulator) {
        printf("Erreur ouverture devices\n");
        return -1;
    }

    if (nfc_initiator_init(dev_reader) < 0) {
        printf("Erreur initiator\n");
        return -1;
    }

    printf("Initiator prêt\n");

    // --- Configuration Target ISO14443A ---
    nfc_target nt;
    memset(&nt, 0, sizeof(nt));

    nt.nm.nmt = NMT_ISO14443A;
    nt.nm.nbr = NBR_106;

    // ATQA
    nt.nti.nai.abtAtqa[0] = 0x04;
    nt.nti.nai.abtAtqa[1] = 0x00;

    // UID (exemple 7 bytes)
    uint8_t uid[7] = {0x04,0x25,0x85,0x93,0x11,0x22,0x33};
    memcpy(nt.nti.nai.abtUid, uid, 7);
    nt.nti.nai.szUidLen = 7;

    nt.nti.nai.btSak = 0x00;

    uint8_t init_rx[MAX_FRAME_LEN];

    if (nfc_target_init(dev_emulator, &nt, init_rx, sizeof(init_rx), 0) < 0) {
        printf("Erreur init target\n");
        return -1;
    }

    printf("Target prêt (émulation)\n");

    uint8_t rx_from_reader[MAX_FRAME_LEN];
    uint8_t rx_from_tag[MAX_FRAME_LEN];

    while (1) {

        // 1 recevoir commande du lecteur externe
        int reader_len = nfc_target_receive_bytes(dev_emulator,
                                                  rx_from_reader,
                                                  sizeof(rx_from_reader),
                                                  0);

        if (reader_len > 0) {

            printf("Lecteur -> %d bytes\n", reader_len);

            // 2️ envoyer au vrai tag
            int tag_len = nfc_initiator_transceive_bytes(dev_reader,
                                                         rx_from_reader,
                                                         reader_len,
                                                         rx_from_tag,
                                                         sizeof(rx_from_tag),
                                                         0);

            if (tag_len >= 0) {

                printf("Tag -> %d bytes\n", tag_len);

                // 3️ renvoyer réponse au lecteur
                nfc_target_send_bytes(dev_emulator,
                                      rx_from_tag,
                                      tag_len,
                                      0);
            }
        }
    }

    nfc_close(dev_reader);
    nfc_close(dev_emulator);
    nfc_exit(context);

    return 0;
}
//EOF