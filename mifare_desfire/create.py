import sys
from nfc_wrapper import nfc_init, nfc_exit, get_uid, write_block
from bdd_utils import get_info_from_bdd, create_blocks_from_bdd

# ---------- Utils ----------
def dump_block(block, data):
    hexdata = " ".join(f"{b:02X}" for b in data)
    asciidata = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
    print(f"Bloc {block:02d} | {hexdata} | {asciidata}")

# ---------- Main ----------
def main():
    if nfc_init() != 0:
        return

    try:
        res, uid, detected = get_uid()
        print("Detected uid: ", uid)
        if res != 0 or not detected:
            return

        info = get_info_from_bdd(uid)
        if not info:
            print("Carte inconnue en BDD, on ne fait rien.")
            return

        print(info)
        blocks = create_blocks_from_bdd(info)
        print(blocks)
        
        print("=== DUMP À ÉCRIRE ===")
        for b, data in blocks.items():
            dump_block(b, data)

        print("=== ÉCRITURE ===")
        for block_num, data in blocks.items():
            res, detected = write_block(block_num, data)
            if res != 0:# or not detected:
                print(f"Erreur à l'écriture du bloc {block_num}, on stop.")
                return
            print(f"Bloc {block_num} écrit.")

        print("Carte écrite avec succès.")

    finally:
        nfc_exit()

# ---------- Entry ----------
if __name__ == "__main__":
    main()

