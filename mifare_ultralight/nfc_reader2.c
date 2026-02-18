#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nfc/nfc.h>

#include <err.h>
#include <freefare.h>

int main() {
    nfc_context *context;
    nfc_device *device;
    nfc_init(&context);
    if (!context) {
        fprintf(stderr, "Impossible d'initialiser libnfc\n");
        exit(EXIT_FAILURE);
    }

    nfc_connstring devices[8];
    size_t device_count = nfc_list_devices(context, devices, 8);
    if (device_count <= 0) {
        fprintf(stderr, "Aucun lecteur NFC détecté\n");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    device = nfc_open(context, devices[0]);
    if (!device) {
        fprintf(stderr, "Impossible d'ouvrir le lecteur\n");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (nfc_initiator_init(device) < 0) {
        nfc_perror(device, "nfc_initiator_init");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    printf("Lecteur NFC prêt\n");

    // Mettre CRC et parité à OFF pour REQA/WUPA
    nfc_device_set_property_bool(device, NP_HANDLE_CRC, false);
    nfc_device_set_property_bool(device, NP_HANDLE_PARITY, false);

    uint8_t reqa = 0x26;  // REQA = 7 bits
    uint8_t atqa[2];
    size_t atqa_bits;

    // Envoyer REQA
    int res = nfc_initiator_transceive_bits(device, &reqa, 7, NULL, atqa, sizeof(atqa), &atqa_bits);
    if (res > 0) {
        printf("REQA envoyé -> ATQA reçu: %02x %02x (%zu bits)\n", atqa[0], atqa[1], atqa_bits);
    } else {
        printf("Erreur REQA: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Anticollision CL1
    uint8_t anticoll_cl1[] = {0x93, 0x20};
    uint8_t uid_cl1[5]; // 4 octets UID + 1 BCC
    nfc_device_set_property_bool(device, NP_HANDLE_PARITY, true);
    nfc_device_set_property_bool(device, NP_HANDLE_CRC, true);
    res = nfc_initiator_transceive_bytes(device, anticoll_cl1, sizeof(anticoll_cl1), uid_cl1, sizeof(uid_cl1), -1);
    if (res > 0) {
        printf("Anticollision CL1 -> UID: ");
        for (int i = 0; i < 5; i++)
            printf("%02x ", uid_cl1[i]);
        printf("\n");
    } else {
        printf("Erreur anticollision CL1: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Sélection CL1
    uint8_t select_cl1[7] = {0x93, 0x70};
    memcpy(&select_cl1[2], uid_cl1, 5);
     // Activer CRC pour select
    uint8_t sak;
    res = nfc_initiator_transceive_bytes(device, select_cl1, sizeof(select_cl1), &sak, 1, -1);
    if (res > 0) {
        printf("Select CL1 -> SAK: %02x\n", sak);
    } else {
        printf("Erreur select CL1: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Vérifier si le tag a CL2 (UID > 4 octets)
    if (sak & 0x04) { 
        // Anticollision CL2
        uint8_t anticoll_cl2[] = {0x95, 0x20};
        uint8_t uid_cl2[5];
        res = nfc_initiator_transceive_bytes(device, anticoll_cl2, sizeof(anticoll_cl2), uid_cl2, sizeof(uid_cl2), -1);
        if (res > 0) {
            printf("Anticollision CL2 -> UID: ");
            for (int i = 0; i < 5; i++)
                printf("%02x ", uid_cl2[i]);
            printf("\n");
        }

        // Sélection CL2
        uint8_t select_cl2[7] = {0x95, 0x70};
        memcpy(&select_cl2[2], uid_cl2, 5);
        res = nfc_initiator_transceive_bytes(device, select_cl2, sizeof(select_cl2), &sak, 1, -1);
        if (res > 0) {
            printf("Select CL2 -> SAK final: %02x\n", sak);
        }
    } else {
        printf("Tag UID complet en CL1, pas de CL2\n");
    }

    printf("Dialogue bas niveau terminé. UID final: ");
    for (int i = 0; i < 4; i++)
        printf("%02x ", uid_cl1[i]); // UID complet si pas CL2
    printf("\n");

    nfc_close(device);
    nfc_exit(context);
    return 0;
}
