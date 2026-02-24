cat << 'EOF' > test.c
// #include <stdio.h>
// #include <stdlib.h>

// int main() {
//     // Correction du chemin pour Windows (pas de ./ et double backslash)
//     // Si proxmark3.exe est dans le dossier courant, mets juste "proxmark3.exe"
//     char *command = "client\\proxmark3.exe -p COM10 -c \"hf 14a info\"";
    
//     printf("Execution de la commande via le moteur Proxmark3...\n");
    
//     // _popen lance la commande via cmd.exe
//     FILE *fp = _popen(command, "r");
//     if (fp == NULL) {
//         printf("Erreur lors du lancement de l'executable\n");
//         return 1;
//     }

//     char line[256];
//     while (fgets(line, sizeof(line), fp)) {
//         printf("PM3 -> %s", line);
//     }

//     _pclose(fp);
//     return 0;
// }

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define DEVICE_PORT "\\\\.\\COM10"

// Calcul du CRC-CCITT (XModem) requis pour Iceman NG
uint16_t iceman_crc(uint8_t *data, int len) {
    uint16_t crc = 0x6363; 
    for (int i = 0; i < len; i++) {
        uint8_t ch = data[i] ^ (uint8_t)(crc & 0x00FF);
        ch = ch ^ (ch << 4);
        crc = (crc >> 8) ^ ((uint16_t)ch << 8) ^ ((uint16_t)ch << 3) ^ ((uint16_t)ch >> 4);
    }
    return crc;
}

int main() {
    HANDLE h = CreateFile(DEVICE_PORT, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Erreur : Ferme d'abord le client Proxmark officiel !\n");
        return 1;
    }

    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    GetCommState(h, &dcb);
    dcb.BaudRate = 460800; // Vitesse v4.20728
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    SetCommState(h, &dcb);

    // Structure NG d'après ton image
    // Magic(4) + Len(2 avec bit NG) + Cmd(2) + CRC(2)
    uint8_t pkt[10] = {
        0x50, 0x4D, 0x33, 0x61, // 'P','M','3','a'
        0x00, 0x80,             // Length=0, NG-flag=1 (le bit 15 est le bit 7 de pkt[5])
        0x00, 0x01              // Commande PING 0x0100 (Little Endian)
    };

    uint16_t crc = iceman_crc(pkt, 8);
    pkt[8] = (uint8_t)(crc & 0xFF);
    pkt[9] = (uint8_t)((crc >> 8) & 0xFF);

    DWORD written;
    printf("[*] Envoi PING NG sur %s...\n", DEVICE_PORT);
    
    if(WriteFile(h, pkt, 10, &written, NULL)) {
        FlushFileBuffers(h);
        
        // On attend la réponse "PM3b" (0x50 0x4D 0x33 0x62)
        uint8_t response[64] = {0};
        DWORD read;
        Sleep(200); 
        if (ReadFile(h, response, sizeof(response), &read, NULL) && read > 0) {
            printf("[+] REPONSE RECUE (%lu octets) !\n", read);
            for(int i=0; i<(int)read; i++) printf("%02X ", response[i]);
            printf("\n");
        } else {
            printf("[!] Le matériel ne répond pas. Vérifie l'ID de commande.\n");
        }
    }

    CloseHandle(h);
    return 0;
}

EOF