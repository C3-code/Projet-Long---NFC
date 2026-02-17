# test_write.py
from ctypes import *

# Charger la lib
lib = CDLL("./libnfccard.so")

# Types C
Block = c_ubyte * 16
Blocks64 = Block * 64

# Prototypes
lib.nfc_init_context.restype = c_int
lib.nfc_exit_context.restype = None
lib.get_uid.argtypes = [c_char_p, c_int, POINTER(c_int)]
lib.get_uid.restype = c_int
lib.read_card.argtypes = [Blocks64, POINTER(c_int)]
lib.read_card.restype = c_int
lib.write_block.argtypes = [c_int, Block, POINTER(c_int)]
lib.write_block.restype = c_int

# ---------- API Python ----------
def nfc_init():
    return lib.nfc_init_context()

def nfc_exit():
    lib.nfc_exit_context()

def get_uid():
    uid_buf = create_string_buffer(32)
    detected = c_int(0)
    res = lib.get_uid(uid_buf, 32, byref(detected))
    return res, uid_buf.value.decode(), bool(detected)

def read_card():
    blocks = Blocks64()
    detected = c_int(0)
    res = lib.read_card(blocks, byref(detected))
    py_blocks = [bytes(blocks[i]) for i in range(64)]
    return res, bool(detected), py_blocks

def write_block(block_num, data_bytes):
    if len(data_bytes) != 16:
        raise ValueError("Le bloc doit faire exactement 16 bytes")
    buf = Block(*data_bytes)
    detected = c_int(0)
    res = lib.write_block(block_num, buf, byref(detected))
    return res, bool(detected)


# ---------- Exemple d'utilisation ----------
if __name__ == "__main__":
    nfc_init()

    # UID
    res, uid, detected = get_uid()
    print("UID:", uid, "Detected:", detected)

    if detected:
        # Lecture d'un bloc
        _, _, blocks = read_card()
        print("Bloc 4 avant écriture:", blocks[4])

        # Écriture sur le bloc 4 (secteur 1)
        data_to_write = b"HelloWorld123456"  # 16 bytes
        res, ok = write_block(4, data_to_write)
        print("Écriture bloc 4:", "OK" if ok else "Erreur", "Res =", res)

        # Relire pour vérifier
        _, _, blocks_after = read_card()
        print("Bloc 4 après écriture:", blocks_after[4])

    nfc_exit()

