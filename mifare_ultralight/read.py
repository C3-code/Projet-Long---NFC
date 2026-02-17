# test_read.py
import nfc_wrapper

def main():
    # Initialisation du lecteur NFC
    if nfc_wrapper.nfc_init() != 0:
        print("Erreur: impossible d'initialiser le lecteur NFC")
        return

    try:
        res, pages, detected = nfc_wrapper.read_card()

        if not detected:
            print("Aucune carte détectée.")
            return

        print(f"Carte détectée. Résultat C: {res}\n")
        print("Dump de la carte Ultralight :\n")

        for page_num, page_data in enumerate(pages):
            hex_data = " ".join(f"{b:02X}" for b in page_data)
            ascii_data = "".join(chr(b) if 32 <= b < 127 else "." for b in page_data)
            print(f"Page {page_num:02d}: {hex_data}  | {ascii_data}")

    finally:
        nfc_wrapper.nfc_exit()

if __name__ == "__main__":
    main()
