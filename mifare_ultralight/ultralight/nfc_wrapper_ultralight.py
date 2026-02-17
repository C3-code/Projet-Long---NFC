from ctypes import *

# Charger la librairie C
lib = CDLL("./libnfccard.so")

# ---------- Types et prototypes C ----------
# Init / exit
lib.nfc_init_context.restype = c_int
lib.nfc_exit_context.restype = None

# get_uid
lib.get_uid.argtypes = [c_char_p, c_int, POINTER(c_int)]
lib.get_uid.restype = c_int

# read_card
Pages45 = c_uint8 * 4 * 45 
lib.read_card.argtypes = [POINTER(Pages45), POINTER(c_int)]
lib.read_card.restype = c_int

'''
# write_block 
Block16 = c_uint8 * 16
lib.write_block.argtypes = [c_int, POINTER(Block16), POINTER(c_int)]
lib.write_block.restype = c_int

lib.factory_init.argtypes = [POINTER(c_int)]
lib.factory_init.restype = c_int

def factory_init():
    detected = c_int(0)
    res = lib.factory_init(byref(detected))
    return res, bool(detected)
'''
# ---------- API Python ----------
def nfc_init():
    """Initialise le contexte NFC"""
    return lib.nfc_init_context()

def nfc_exit():
    """Libère le contexte NFC"""
    lib.nfc_exit_context()

def get_uid():
    """Retourne (res, uid_str, detected)"""
    uid_buf = create_string_buffer(32)
    detected = c_int(0)
    res = lib.get_uid(uid_buf, 32, byref(detected))
    return res, uid_buf.value.decode(), bool(detected)

def read_card():
    """Retourne (res, blocks[64][16], detected)"""
    pages = Pages45()
    detected = c_int(0)
    res = lib.read_card(byref(pages), byref(detected))
    # Conversion en liste Python
    py_blocks = [[pages[b][i] for i in range(4)] for b in range(45)]
    return res, py_blocks, bool(detected)

def write_block(block_num, data):
    """
    Écrit un bloc Mifare Classic (Key B fallback default_key)
    block_num: int
    data: iterable de 16 bytes
    Retourne (res, detected)
    """
    if len(data) != 16:
        raise ValueError("data must be 16 bytes")
    arr = Block16(*data)
    detected = c_int(0)
    res = lib.write_block(block_num, byref(arr), byref(detected))
    return res, bool(detected)
