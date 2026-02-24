cat << 'EOF' > mitm.c
#include <windows.h>
#include <stdio.h>

// Structure pour passer les handles aux threads
typedef struct {
    HANDLE hInput;
    HANDLE hOutput;
    const char* direction;
} BridgeData;

// Fonction de configuration des ports
void setupPort(HANDLE hSerial) {
    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    GetCommState(hSerial, &dcb);
    dcb.BaudRate = CBR_9600; // À ajuster selon tes besoins
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity = NOPARITY;
    SetCommState(hSerial, &dcb);

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 1;
    timeouts.ReadTotalTimeoutConstant = 1;
    SetCommTimeouts(hSerial, &timeouts);
}

// Routine du thread qui lit sur un port et écrit sur l'autre
DWORD WINAPI relay(LPVOID lpParam) {
    BridgeData* data = (BridgeData*)lpParam;
    char buffer[256];
    DWORD bytesRead, bytesWritten;

    while (1) {
        if (ReadFile(data->hInput, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            WriteFile(data->hOutput, buffer, bytesRead, &bytesWritten, NULL);
            printf("[%s] : %d octets translatés\n", data->direction, (int)bytesRead);
        }
    }
    return 0;
}

int main() {
    // Utilisation du préfixe \\\\.\\ indispensable pour les ports au-delà de COM9
    HANDLE hCom9 = CreateFile("\\\\.\\COM9", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hCom10 = CreateFile("\\\\.\\COM10", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hCom9 == INVALID_HANDLE_VALUE || hCom10 == INVALID_HANDLE_VALUE) {
        printf("Erreur : Impossible d'ouvrir les ports. Verifie qu'ils ne sont pas deja utilises.\n");
        return 1;
    }

    setupPort(hCom9);
    setupPort(hCom10);

    BridgeData d1 = {hCom9, hCom10, "COM9 -> COM10"};
    BridgeData d2 = {hCom10, hCom9, "COM10 -> COM9"};

    printf("Pont bidirectionnel actif. Appuyez sur Ctrl+C pour arreter.\n---\n");

    // Création des deux threads pour la bidirectionnalité
    CreateThread(NULL, 0, relay, &d1, 0, NULL);
    relay(&d2); // Le thread principal s'occupe du second flux

    CloseHandle(hCom9);
    CloseHandle(hCom10);
    return 0;
}
EOF