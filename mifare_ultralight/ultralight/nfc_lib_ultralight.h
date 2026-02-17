#ifndef NFC_CARD_LIB_H
#define NFC_CARD_LIB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise le contexte NFC (à appeler UNE fois avant tout) */
int nfc_init_context(void);

/* Récupère l'UID de la carte.
 * uid : buffer pour l'UID
 * uid_len : taille du buffer
 * card_detected : renvoie 1 si carte détectée, 0 sinon
 * Retourne 0 en succès, -1 en erreur */
int get_uid(char *uid, int uid_len, int *card_detected);

int read_card(int pages[45][4], int *card_detected);

/* Libération du contexte NFC */
void nfc_exit_context(void);

#ifdef __cplusplus
}
#endif

#endif /* NFC_CARD_LIB_H */

