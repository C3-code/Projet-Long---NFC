cat << 'EOF' > mark.c
#include <stdio.h>
#include <windows.h>
#include <string.h>

int main() {
    HANDLE hSerial;
    hSerial = CreateFile(
        "\\\\.\\COM10",             
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hSerial == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            printf("Port COM non trouvé\n");
        } else {
            printf("Erreur lors de l'ouverture du port COM\n");
        }
        return 1;
    }

    // Configuration du port série
    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    if (!GetCommState(hSerial, &dcbSerialParams)) {
        printf("Erreur GetCommState\n");
        CloseHandle(hSerial);
        return 1;
    }

    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity   = NOPARITY;

    if (!SetCommState(hSerial, &dcbSerialParams)) {
        printf("Erreur SetCommState\n");
        CloseHandle(hSerial);
        return 1;
    }

    // Configuration des Timeouts
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout         = 50;
    timeouts.ReadTotalTimeoutConstant    = 500; // Attendre jusqu'à 500ms
    timeouts.ReadTotalTimeoutMultiplier  = 10;
    timeouts.WriteTotalTimeoutConstant   = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (!SetCommTimeouts(hSerial, &timeouts)) {
        printf("Erreur SetCommTimeouts\n");
        CloseHandle(hSerial);
        return 1;
    }

    // Envoi de la commande
    char *cmd = "hw version\r\n"; // Ajout du \r
    DWORD bytesWritten;
    WriteFile(hSerial, cmd, strlen(cmd), &bytesWritten, NULL);
    
    printf("Commande envoyée, attente de la réponse...\n");
    Sleep(500); // On laisse 0.5 seconde au Proxmark pour travailler

    // Lecture de la réponse
    char buffer[2048]; // Buffer un peu plus grand
    DWORD bytesRead;
    memset(buffer, 0, sizeof(buffer));

    if (ReadFile(hSerial, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        printf("Recu (%lu octets):\n%s\n", bytesRead, buffer);
    } else {
        printf("Aucune réponse reçue ou erreur ReadFile. Code: %lu\n", GetLastError());
    }

    CloseHandle(hSerial);
    return 0;
}
EOF

