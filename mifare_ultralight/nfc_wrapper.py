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

# ===== ULTRALIGHT =====

# 45 pages de 4 bytes
Pages45 = (c_uint8 * 4) * 45

lib.read_card.argtypes = [POINTER(Pages45), POINTER(c_int)]
lib.read_card.restype = c_int

# write_page
Page4 = c_uint8 * 4
lib.write_page.argtypes = [c_int, POINTER(Page4), POINTER(c_int)]
lib.write_page.restype = c_int


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
    """
    Retourne (res, pages[45][4], detected)
    """
    pages = Pages45()
    detected = c_int(0)
    print("detected before = ", detected.value)

    res = lib.read_card(byref(pages), byref(detected))

    print("detected after = ", detected.value)

    # Conversion en liste Python
    py_pages = [[pages[p][i] for i in range(4)] for p in range(45)]

    return res, py_pages, bool(detected.value)


def write_page(page_num, data):
    """
    Écrit une page Ultralight (4 bytes)
    page_num: int
    data: iterable de 4 bytes
    Retourne (res, detected)
    """
    if len(data) != 4:
        raise ValueError("data must be 4 bytes")

    arr = Page4(*data)
    detected = c_int(0)

    res = lib.write_page(page_num, byref(arr), byref(detected))
    return res, bool(detected)
