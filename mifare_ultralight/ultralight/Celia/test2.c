#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE h = CreateFileA("\\\\.\\COM3",
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Impossible d'ouvrir COM3\n");
        return 1;
    }

    EscapeCommFunction(h, CLRDTR); // Désactive DTR
    EscapeCommFunction(h, CLRRTS); // Désactive RTS

    CloseHandle(h);
    printf("DTR et RTS remis à OFF\n");
    return 0;
}
