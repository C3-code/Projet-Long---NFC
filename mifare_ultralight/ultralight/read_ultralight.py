# test_read.py
from ctypes import *
import nfc_wrapper_ultralight

# ---------- Définition types C (si pas déjà dans nfc_wrapper) ----------
# Une page de 4 octets
Page = c_ubyte * 4

# 45 pages
Pages45 = Page * 45

# Allocation
pages = Pages45()


def main():
    # Initialisation du lecteur NFC
    if nfc_wrapper_ultralight.nfc_init() != 0:
        print("Erreur: impossible d'initialiser le lecteur NFC")
        return

    try:
        # Préparer le buffer pour 64 blocs de 16 bytes
        detected = c_int(0)
        res = nfc_wrapper_ultralight.lib.read_card(pages, byref(detected))

        if not detected.value:
            print("Aucune carte détectée.")
            return

        print(f"Carte détectée. Résultat C: {res}\n")
        print("Dump de la carte :")
        for page_num in enumerate(pages):
            hex_data = " ".join(f"{b:02X}" for b in page_num)
            ascii_data = "".join(chr(b) if 32 <= b < 127 else "." for b in page_num)
            print(f"Page {page_num:02d}: {hex_data}  | {ascii_data}")

    finally:
        nfc_wrapper_ultralight.nfc_exit()

if __name__ == "__main__":
    main()

