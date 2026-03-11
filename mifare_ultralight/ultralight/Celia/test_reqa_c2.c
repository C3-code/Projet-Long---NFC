#include "iso14443a.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "ticks.h"
#include "fpgaloader.h"

#include <stdio.h>
#include <string.h>

static char* hex_text(uint8_t* buf, int len){
    static char hex[512];
    memset(hex, 0, sizeof(hex));
    char *tmp = hex;

    for(int i=0; i<len; i++, tmp+=3){
        sprintf(tmp, "%02X ", buf[i]);
    }

    return hex;
}

void RunMod(void) {

    printf("Sniffer lecteur NFC ISO14443A...\n");

    iso14443a_setup(FPGA_HF_ISO14443A_LISTEN);

    iso14a_set_timeout(201400);

    clear_trace();
    set_tracing(true);

    printf("En attente REQA/WUPA...\n");

    while(1) {

        uint16_t traceLen = BigBuf_get_traceLen();

        if(traceLen > 0){

            uint8_t *trace = BigBuf_get_addr();

            printf("Frame : %s\n", hex_text(trace, traceLen));

            if(trace[0] == 0x26)
                printf("REQA detecte\n");

            if(trace[0] == 0x52)
                printf("WUPA detecte\n");

            break;
        }
    }

    set_tracing(false);

    printf("Sniffer stop\n");
}
// #include "iso14443a.h"
// #include "proxmark3_arm.h"
// #include "BigBuf.h"
// #include "ticks.h"

// #include <stdio.h>
// #include <string.h>


// static char* hex_text(uint8_t* buf, int len){
//     static char hex[512];
//     memset(hex, 0, sizeof(hex));
//     char *tmp = hex;
//     for(int i=0; i<len; i++, tmp+=3){
//         sprintf(tmp, "%02X ", buf[i]);
//     }
//     return hex;
// }

// #define FPGA_HF_ISO14443A_TAGSIM_LISTEN (1)

// int main(void) {
//     printf("Sniffer lecteur NFC ISO14443A...\n");

//     iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN); // mode écoute de burja
//     iso14a_set_timeout(201400);                        // timeout par défaut
//     clear_trace();
//     set_tracing(true);

//     printf("En attente d'une commande du lecteur (REQA/WUPA)...\n");

//     while (1) {
//         uint8_t *trace = BigBuf_get_addr();
//         uint16_t traceLen = BigBuf_get_traceLen();

//         if(traceLen > 0){
//             printf("Commande détectée (len=%u) : %s\n", traceLen, hex_text(trace, traceLen));

//             // Filtrer seulement REQA/WUPA si besoin
//             if(trace[0] == 0x26){
//                 printf("=> REQA détecté !\n");
//             } else if(trace[0] == 0x52){
//                 printf("=> WUPA détecté !\n");
//             }

//             break; // on sort après la première commande
//         }
//     }

//     set_tracing(false);
//     printf("Sniffer arrêté.\n");
//     return 0;
// }