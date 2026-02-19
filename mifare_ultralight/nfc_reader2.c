#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nfc/nfc.h>
#include <err.h>
#include <freefare.h>

//========================= READ ==========================
int reader_read(nfc_context * context, nfc_device * device, int res, uint8_t page){
    uint8_t read[] = {0x30, page};
    uint8_t read_data[16];

    res = nfc_initiator_transceive_bytes(device, read, sizeof(read), read_data, sizeof(read_data), -1);
    if (res > 0) {
        printf("READ -> DATA: ");
        for (int i = 0; i < 16; i++)
            printf("%02x ", read_data[i]);
        printf("\n");
    } else {
        printf("Erreur READ: %s\n", nfc_strerror(device));
        return -1;
        //nfc_close(device);
        //nfc_exit(context);
        //exit(EXIT_FAILURE);
    }
    return res;
}

//========================= WRITE ==========================
int reader_write(nfc_context * context, nfc_device * device, int res, uint8_t page, uint8_t * data){
    uint8_t write[6];
    write[0] = 0xa2;
    write[1] = page;
    for (int i=0; i<4; i++){
        write[i+2] = data[i];
    }
    uint8_t ret_data[1];

    res = nfc_initiator_transceive_bytes(device, write, sizeof(write), ret_data, sizeof(ret_data), -1);
    if (res == 1 && ret_data[0] == 0x0A) {
        printf("WRITE OK\n");
        return 0;
    } else {
        printf("Erreur WRITE (res=%d, ret=0x%02X)\n", res, (res > 0) ? ret_data[0] : 0);
        return -1;
    }

}







//====================== READ_SIG ======================
int read_sig(nfc_context * context, nfc_device * device, int res){
    uint8_t read_sig[] = {0x3c, 0x00};
    uint8_t sig[32];

    res = nfc_initiator_transceive_bytes(device, read_sig, sizeof(read_sig), sig, sizeof(sig), -1);
    if (res > 0) {
        printf("READ_SIG -> SIG: ");
        for (int i = 0; i < 32; i++)
            printf("%02x ", sig[i]);
        printf("\n");
    } else {
        printf("Erreur READ_SIG: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    return res;
}


//====================== GET_VERSION ======================
int get_version(nfc_context * context, nfc_device * device, int res){
    uint8_t get_version[] = {0x60};
    uint8_t version[8];

    res = nfc_initiator_transceive_bytes(device, get_version, sizeof(get_version), version, sizeof(version), -1);
    if (res > 0) {
        printf("GET_VERSION -> VERSION: ");
        for (int i = 0; i < 8; i++)
            printf("%02x ", version[i]);
        printf("\n");
    } else {
        printf("Erreur GET_VERSION: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    return res;
}











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

    //======================= REQA / WUPA ========================

    // Enelver crc et parite pour REQA/WUPA
    nfc_device_set_property_bool(device, NP_EASY_FRAMING, false);
    nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, false);
    nfc_device_set_property_bool(device, NP_HANDLE_CRC, false);

    uint8_t reqa = 0x26; 
    uint8_t atqa[2];
    uint8_t atqa_bits;

    // Envoyer REQA
    int res = nfc_initiator_transceive_bits(device, &reqa, 7, NULL, atqa, sizeof(atqa), &atqa_bits);
    if (res > 0) {
        printf("REQA envoyé -> ATQA reçu: %02x %02x\n", atqa[0], atqa[1]);
    } else {
        printf("Erreur REQA: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }


    //========================== ANTICOLLISION 1 ============================

    // Anticollision CL1
    uint8_t anticoll_cl1[] = {0x93, 0x20};
    uint8_t uid_cl1[5]; // 4 octets UID + 1 BCC

    res = nfc_initiator_transceive_bytes(device, anticoll_cl1, sizeof(anticoll_cl1), uid_cl1, sizeof(uid_cl1), -1);
    if (res > 0) {
        printf("ANTICOLLISION CL1 -> UID: ");
        for (int i = 0; i < 5; i++)
            printf("%02x ", uid_cl1[i]);
        printf("\n");
    } else {
        printf("Erreur ANTICOLLISION CL1: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Sélection CL1
    uint8_t select_cl1[7] = {0x93, 0x70};
    memcpy(&select_cl1[2], uid_cl1, 5);
    uint8_t sak;
    // Activer CRC pour select
    nfc_device_set_property_bool(device, NP_HANDLE_CRC, true);
    res = nfc_initiator_transceive_bytes(device, select_cl1, sizeof(select_cl1), &sak, 1, -1);
    if (res > 0) {
        printf("SELECT CL1 -> SAK: %02x\n", sak);
    } else {
        printf("Erreur SELECT CL1: %s\n", nfc_strerror(device));
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }



    //========================== ANTICOLLISION 2 ===========================

    uint8_t anticoll_cl2[] = {0x95, 0x20};
    uint8_t uid_cl2[5];


    // Vérifier si le tag a CL2 (UID > 4 octets)
    if (sak == 0x04) { 
        // Anticollision CL2
        
        nfc_device_set_property_bool(device, NP_HANDLE_CRC, false);
        res = nfc_initiator_transceive_bytes(device, anticoll_cl2, sizeof(anticoll_cl2), uid_cl2, sizeof(uid_cl2), -1);
        if (res > 0) {
            printf("ANTICOLLISION CL2 -> UID: ");
            for (int i = 0; i < 5; i++)
                printf("%02x ", uid_cl2[i]);
            printf("\n");
        }

        // Sélection CL2
        uint8_t select_cl2[7] = {0x95, 0x70};
        memcpy(&select_cl2[2], uid_cl2, 5);
        nfc_device_set_property_bool(device, NP_HANDLE_CRC, true);
        res = nfc_initiator_transceive_bytes(device, select_cl2, sizeof(select_cl2), &sak, 1, -1);
        if (res < 0) {
			printf("Erreur: %s %d\n", nfc_strerror(device), res);
		}
        if (res > 0) {
            printf("SELECT CL2 -> SAK final: %02x\n", sak);
        }
    } else {
        printf("Tag UID complet en CL1, pas de CL2\n");
    }


    //========================= UID ==========================

    printf("UID final: ");
    uint8_t uid[7];
    for (int i = 0; i < 3; i++)
        uid[i] = uid_cl1[i+1]; 
    
    for (int i = 0 ; i< 4; i++)
        uid[i+3] = uid_cl2[i];
    for (int i = 0; i < 7; i++)
        printf("%02X ", uid[i]);
    printf("\n");

    uint8_t data [4] = {0xaa, 0xaa, 0xff, 0xff};
    reader_read(context, device, res, 0x05);
    reader_write(context, device, res, 0x05, data);
    reader_read(context, device, res, 0x05);
    get_version(context, device, res);
    read_sig(context, device, res);



    nfc_close(device);
    nfc_exit(context);
    return 0;
}