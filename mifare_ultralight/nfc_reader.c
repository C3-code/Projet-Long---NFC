#include <err.h>
#include <stdlib.h>
#include <nfc/nfc.h>
#include <freefare.h>
#include <unistd.h> 
#include <string.h>

int main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

    if (argc > 1)
	errx(EXIT_FAILURE, "usage: %s", argv[0]);

    nfc_connstring devices[8];
    size_t device_count;

    nfc_context *context;
    nfc_init(&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices(context, devices, sizeof(devices) / sizeof(*devices));
    if (device_count <= 0)
	errx(EXIT_FAILURE, "No NFC device found");

    for (size_t d = 0; d < device_count; d++) {
	if (!(device = nfc_open(context, devices[d]))) {
	    warnx("nfc_open() failed.");
	    error = EXIT_FAILURE;
	    continue;
	}
	
	//Initialize reader

	if (nfc_initiator_init(device) < 0) {
		nfc_perror(device, "nfc_initiator_init");
		exit(EXIT_FAILURE);
	}

	//Deactivate CRC for REQA and WUPA

	nfc_device_set_property_bool(device, NP_HANDLE_CRC, false);
	nfc_device_set_property_bool(device, NP_HANDLE_PARITY, false);
	nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, false);


	uint8_t wupa = 0x52;   // Wake Up
	uint8_t reqa = 0x26;   // Request
	uint8_t atqa[2];
	uint8_t atqa_bits;

	while (1) {
		// Send WUPA
		int res = nfc_initiator_transceive_bits(device, &wupa, 7, NULL, atqa, sizeof(atqa),	&atqa_bits);
		if (res < 0) {
			printf("Erreur: %s\n", nfc_strerror(device));
		}
		if (res >= 0) {
			printf("Réveil OK via WUPA. ATQA: %02x %02x\n", atqa[0], atqa[1]);
			break;
		}

		// Send REQA
		res = nfc_initiator_transceive_bits(device, &reqa, 7, NULL, atqa, sizeof(atqa), &atqa_bits);
		if (res < 0) {
			printf("Erreur: %s\n", nfc_strerror(device));
		}
		if (res >= 0) {
			printf("Détection via REQA. ATQA: %02x %02x\n", atqa[0], atqa[1]);
			break;
		}

		usleep(50000); // 50ms pour éviter surcharge RF
	}

	printf("In Ready 1 state \n");

	//Activate CRC 

	nfc_device_set_property_bool(device, NP_HANDLE_CRC, true);
	nfc_device_set_property_bool(device, NP_HANDLE_PARITY, true);

	if (!nfc_device_set_property_bool(device, NP_HANDLE_CRC, true))
	    printf("CRC set failed\n");


	//Send Anticollision CL1
	uint8_t anticoll_cl1[] = { 0x93, 0x20 };
	uint8_t uid_cl1[5]; // 4 bytes UID + 1 BCC

	int res = nfc_initiator_transceive_bytes(device, anticoll_cl1, sizeof(anticoll_cl1), uid_cl1, sizeof(uid_cl1), -1);
	if (res == 5) {
		printf("ok\n");
	} else {
		printf("Recu %d bytes\n", res);
	}

	if (res >= 0) {
		printf("UID CL1: ");
		for (int i = 0; i < 5; i++)
			printf("%02x ", uid_cl1[i]);
		printf("\n");
	} 
	else {
		printf("Erreur anticollision: %s\n", nfc_strerror(device));
	}

	//Select CL1

	uint8_t select_cl1[7];

	select_cl1[0] = 0x93;
	select_cl1[1] = 0x70;
	memcpy(&select_cl1[2], uid_cl1, 5);

	uint8_t sak;

	res = nfc_initiator_transceive_bytes(
		device,
		select_cl1,
		sizeof(select_cl1),
		&sak,
		1,
		-1
	);

	if (res >= 0) {
		printf("SAK CL1: %02x\n", sak);
	}

	//Anticollision CL2

	uint8_t anticoll_cl2[] = { 0x95, 0x20 };
	uint8_t uid_cl2[5];

	res = nfc_initiator_transceive_bytes(
		device,
		anticoll_cl2,
		sizeof(anticoll_cl2),
		uid_cl2,
		sizeof(uid_cl2),
		-1
	);

	if (res >= 0) {
		printf("UID CL2: ");
		for (int i = 0; i < 5; i++)
			printf("%02x ", uid_cl2[i]);
		printf("\n");
	}

	//Select CL2

	uint8_t select_cl2[7];

	select_cl2[0] = 0x95;
	select_cl2[1] = 0x70;
	memcpy(&select_cl2[2], uid_cl2, 5);

	res = nfc_initiator_transceive_bytes(
		device,
		select_cl2,
		sizeof(select_cl2),
		&sak,
		1,
		-1
	);

	if (res >= 0) {
		printf("SAK final: %02x\n", sak);
	}




	if (!(tags = freefare_get_tags(device))) {
	    nfc_close(device);
	    errx(EXIT_FAILURE, "Error listing tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    switch (freefare_get_tag_type(tags[i])) {
	    case MIFARE_ULTRALIGHT:
            printf("MIFARE_ULTRALIGHT\n");
            break;
	    case MIFARE_ULTRALIGHT_C:
            printf("MIFARE_ULTRALIGHT_C\n");
            break;
        case MIFARE_CLASSIC_1K:
            printf("MIFARE_CLASSIC_1K\n");
            break;
        case MIFARE_DESFIRE:
            printf("MIFARE_DESFIRE\n");
            break;
        case NTAG_21x:
            printf("NTAG_21x\n");
            break;
	    default:
            printf("OTHER\n");
		continue;
	    }

	    char *tag_uid = freefare_get_tag_uid(tags[i]);
	    printf("Tag with UID %s is a %s\n", tag_uid, freefare_get_tag_friendly_name(tags[i]));
	    FreefareTag tag = tags[i];
	    int res;

	    if (ntag21x_connect(tag) < 0)
		errx(EXIT_FAILURE, "Error connecting to tag.");

	    uint8_t data [4] = {0xfa, 0xca, 0xac, 0xad}; // Data to write on tag
	    uint8_t read[4]; // Buffer for reading data from tag

	    bool flag_match = true;
	    switch (true) {
	    case true:
		/*
		   Get information about tag
		   MUST do, because here we are recognizing tag subtype (NTAG213,NTAG215,NTAG216), and gathering all parameters
		   */
		res = ntag21x_get_info(tag); //COMMAND 60h = GET_VERSION
		if (res < 0) {
		    printf("Error getting info from tag\n");
		    break;
		}

        enum ntag_tag_subtype subtype = ntag21x_get_subtype(tag);

        switch (subtype) {
        case NTAG_213:
            printf("Subtype: NTAG213\n");
            break;
        case NTAG_215:
            printf("Subtype: NTAG215\n");
            break;
        case NTAG_216:
            printf("Subtype: NTAG216\n");
            break;
        default:
            printf("Subtype inconnu\n");
            break;
    }


		// writing to tag 4 bytes on page 0x27 (check specs for NTAG21x before changing page number !!!)
		res = ntag21x_write(tag, 0x27, data);
		if (res < 0) {
		    printf("Error writing to tag\n");
		    break;
		}
		res = ntag21x_fast_read4(tag, 0x27, read); // Reading page from tag (4 bytes), you can also use ntag21x_read4 or ntag21x_read (16 bytes) or ntag21x_fast_read (start_page to end_page)
		if (res < 0) {
		    printf("Error reading tag\n");
		    break;
		}
		for (int i = 0; i < 4; i++) // Checking if we can read what we have written earlyer
		    if (data[i] != read[i]) {
			flag_match = false;
			break;
		    }
		if (!flag_match)
		    printf("Data don't match\n");
		else
		    printf("Data match\n");
	    }
	    ntag21x_disconnect(tag);
	    free(tag_uid);
	}

	freefare_free_tags(tags);
	nfc_close(device);
    }

    nfc_exit(context);
    printf("End ...\n");
    exit(error);
}