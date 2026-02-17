# test_read.py
from ctypes import *
import nfc_wrapper

# ---------- Définition types C (si pas déjà dans nfc_wrapper) ----------
Block = c_ubyte * 16       # un bloc de 16 bytes
Blocks64 = Block * 64      # 64 blocs

def main():
    # Initialisation du lecteur NFC
    if nfc_wrapper.nfc_init() != 0:
        print("Erreur: impossible d'initialiser le lecteur NFC")
        return

    try:
        # Préparer le buffer pour 64 blocs de 16 bytes
        blocks = Blocks64()                # <- buffer C
        detected = c_int(0)
        res = nfc_wrapper.lib.read_card(blocks, byref(detected))

        if not detected.value:
            print("Aucune carte détectée.")
            return

        print(f"Carte détectée. Résultat C: {res}\n")
        print("Dump de la carte :")
        for blk_num, blk_data in enumerate(blocks):
            hex_data = " ".join(f"{b:02X}" for b in blk_data)
            ascii_data = "".join(chr(b) if 32 <= b < 127 else "." for b in blk_data)
            print(f"Bloc {blk_num:02d}: {hex_data}  | {ascii_data}")

    finally:
        nfc_wrapper.nfc_exit()

if __name__ == "__main__":
    main()

