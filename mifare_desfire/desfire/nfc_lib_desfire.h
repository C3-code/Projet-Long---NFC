#ifndef NFC_CARD_DES_LIB_H
#define NFC_CARD_DES_LIB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int read_card(uint8_t *data_out, size_t *data_len, int *card_detected)

#ifdef __cplusplus
}
#endif

#endif /* NFC_CARD_DES_LIB_H */

