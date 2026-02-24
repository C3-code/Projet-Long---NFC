cat << 'EOF' > mitm_alone.c
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define PM3_SUCCESS 0
#define INVALID_SERIAL_PORT NULL

typedef HANDLE serial_port;

// --- FONCTION D'AFFICHAGE HEXADECIMAL ---
void print_hex(const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 16) {
        printf("  %04x: ", i); // Offset
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", data[i + j]);
            else printf("   ");
        }
        printf(" | ");
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char c = data[i + j];
                printf("%c", isprint(c) ? c : '.');
            }
        }
        printf("\n");
    }
}

// --- FONCTION OPEN (Initialisation brute sans dépendances) ---
serial_port uart_open(const char *pcPortName) {
    char acPortName[64];
    snprintf(acPortName, sizeof(acPortName), "\\\\.\\%s", pcPortName);

    serial_port hPort = CreateFileA(acPortName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPort == INVALID_HANDLE_VALUE) return INVALID_SERIAL_PORT;

    DCB dcb = {0};
    dcb.DCBlength = sizeof(DCB);
    if (!GetCommState(hPort, &dcb)) return INVALID_SERIAL_PORT;

    dcb.BaudRate = CBR_115200;
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity   = NOPARITY;
    
    if (!SetCommState(hPort, &dcb)) return INVALID_SERIAL_PORT;

    COMMTIMEOUTS ct = {0};
    ct.ReadIntervalTimeout         = 1; // Ultra-rapide pour le relay
    ct.ReadTotalTimeoutConstant    = 1;
    ct.ReadTotalTimeoutMultiplier  = 1;
    ct.WriteTotalTimeoutConstant   = 1;
    ct.WriteTotalTimeoutMultiplier = 1;
    SetCommTimeouts(hPort, &ct);

    return hPort;
}

int uart_receive(serial_port sp, uint8_t *pbtRx, uint32_t pszMaxRxLen, uint32_t *pszRxLen) {
    if (ReadFile(sp, pbtRx, pszMaxRxLen, (LPDWORD)pszRxLen, NULL)) return PM3_SUCCESS;
    return -1;
}

int uart_send(serial_port sp, const uint8_t *p_tx, uint32_t len) {
    DWORD txlen = 0;
    if (WriteFile(sp, p_tx, len, &txlen, NULL)) return PM3_SUCCESS;
    return -1;
}

// Paquet "Ping" ou "Get Version" pour réveiller le PM3 (Protocole NG)
// Format : Magic (2b), Payload Len (2b), Command (2b), Checksum...
const uint8_t PM3_WAKEUP[] = {0x01, 0x00, 0x01, 0x00, 0x00, 0x00};

int main() {
    serial_port spMole, spProxy;
    uint8_t buffer[2048];
    uint32_t bytesRead;

    printf("=== RELAI MAN-IN-THE-MIDDLE PROXMARK3 (NFC ULTRALIGHT) ===\n");
    printf("[*] Ouverture COM9 (Mole) et COM10 (Proxy)...\n");

    spMole = uart_open("COM9");
    spProxy = uart_open("COM10");

    if (!spMole || !spProxy) {
        printf("[!] Erreur fatale : Verifiez que les PM3 sont branches sur COM9 et COM10.\n");
        return 1;
    }

    

    printf("[+] Relai actif. En attente de donnees...\n\n");

    while (1) {
        // Relai MOLE -> PROXY
        if (uart_receive(spMole, buffer, sizeof(buffer), &bytesRead) == PM3_SUCCESS && bytesRead > 0) {
            uart_send(spProxy, buffer, bytesRead);
            printf("\x1b[32m[MOLE >> PROXY] (%u octets)\x1b[0m\n", bytesRead);
            print_hex(buffer, bytesRead);
            printf("\n");
        }

        // Relai PROXY -> MOLE
        if (uart_receive(spProxy, buffer, sizeof(buffer), &bytesRead) == PM3_SUCCESS && bytesRead > 0) {
            uart_send(spMole, buffer, bytesRead);
            printf("\x1b[34m[PROXY >> MOLE] (%u octets)\x1b[0m\n", bytesRead);
            print_hex(buffer, bytesRead);
            printf("\n");
        }

        // Temps d'attente minimal pour ne pas saturer le CPU mais rester réactif
        Sleep(1); 
    }

    return 0;
}
EOF