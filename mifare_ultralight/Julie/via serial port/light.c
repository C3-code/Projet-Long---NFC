cat << 'EOF' > light.c
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Structure d'un paquet Proxmark3 NG simplifié
typedef struct {
    uint16_t magic;     // 0x4342 ('BC')
    uint16_t length;    // Longueur du payload
    uint16_t cmd;       // La commande
    uint8_t  data[8];   // Data optionnelle
} pm3_packet;

void setup_port(HANDLE h) {
    DCB dcb = {0};
    dcb.DCBlength = sizeof(DCB);
    GetCommState(h, &dcb);
    // On utilise la vitesse max supportée par le driver CDC
    dcb.BaudRate = CBR_115200; 
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity   = NOPARITY;
    SetCommState(h, &dcb);
}

int main() {
    printf("--- MITM PROXMARK3 EASY (ICEMAN 2026) ---\n");

    HANDLE hMole = CreateFileA("\\\\.\\COM9", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hProxy = CreateFileA("\\\\.\\COM10", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hMole == INVALID_HANDLE_VALUE || hProxy == INVALID_HANDLE_VALUE) {
        printf("[!] Fermez le client pm3 avant de lancer ce script !\n");
        return 1;
    }

    setup_port(hMole);
    setup_port(hProxy);

    // Commande Identification (NG) pour vérifier la liaison
    // Les octets sont en Little Endian
    uint8_t cmd_identify[] = {0x42, 0x43, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00};

    printf("[*] Envoi 'Identify' pour reveiller les LEDs...\n");
    DWORD written;
    WriteFile(hMole, cmd_identify, sizeof(cmd_identify), &written, NULL);
    WriteFile(hProxy, cmd_identify, sizeof(cmd_identify), &written, NULL);

    printf("[+] Relai actif. Observez les LEDs et le trafic serie...\n");

    uint8_t buf[2048];
    DWORD read;
    while(1) {
        // Relai bidirectionnel pur
        if (ReadFile(hMole, buf, sizeof(buf), &read, NULL) && read > 0) {
            WriteFile(hProxy, buf, read, &written, NULL);
            printf("MOLE -> %d bytes -> PROXY\n", (int)read);
        }
        if (ReadFile(hProxy, buf, sizeof(buf), &read, NULL) && read > 0) {
            WriteFile(hMole, buf, read, &written, NULL);
            printf("PROXY -> %d bytes -> MOLE\n", (int)read);
        }
        Sleep(1);
    }

    return 0;
}
EOF