import ctypes
from ctypes import *

# Chargement des librairies
libnfc = ctypes.CDLL("libnfc.so")
libfreefare = ctypes.CDLL("libfreefare.so")

# ================= INIT NFC =================

context = c_void_p()
libnfc.nfc_init(byref(context))

if not context:
    print("Erreur init NFC")
    exit(1)

device = libnfc.nfc_open(context, None)
if not device:
    print("Impossible d'ouvrir le lecteur NFC")
    exit(1)

if libnfc.nfc_initiator_init(device) < 0:
    print("Erreur initiateur")
    exit(1)

print("Lecteur NFC prêt")

# ================= DETECTION TAG =================

libfreefare.freefare_get_tags.restype = POINTER(c_void_p)
tags = libfreefare.freefare_get_tags(device)

if not tags or not tags[0]:
    print("Aucune carte détectée")
    libnfc.nfc_close(device)
    libnfc.nfc_exit(context)
    exit(0)

tag = tags[0]

libfreefare.freefare_get_tag_type.restype = c_int
tag_type = libfreefare.freefare_get_tag_type(tag)

MIFARE_DESFIRE = 4
print("tag_type", tag_type)
if tag_type != MIFARE_DESFIRE:
    print("Ce n'est pas une carte DESFire")
    libfreefare.freefare_free_tags(tags)
    libnfc.nfc_close(device)
    libnfc.nfc_exit(context)
    exit(1)

print("Carte DESFire détectée")

# ================= CONNECT =================

if libfreefare.mifare_desfire_connect(tag) < 0:
    print("Erreur connexion DESFire")
    exit(1)

# ================= SELECT APPLICATION =================

libfreefare.mifare_desfire_aid_new.restype = c_void_p
aid = libfreefare.mifare_desfire_aid_new(0xF20530)

if libfreefare.mifare_desfire_select_application(tag, aid) < 0:
    print("Erreur sélection application")
    exit(1)

print("Application sélectionnée")

# ================= AUTH AES (optionnel) =================

key_data = (c_uint8 * 16)(*([0x00] * 16))
libfreefare.mifare_desfire_aes_key_new.restype = c_void_p
key = libfreefare.mifare_desfire_aes_key_new(key_data)

auth_result = libfreefare.mifare_desfire_authenticate_aes(tag, c_uint8(0x00), key)

if auth_result < 0:
    print("Authentification AES échouée (peut être non nécessaire)")
else:
    print("Authentification AES OK")

# ================= READ FILE =================

buffer_size = 4096
buffer = (c_uint8 * buffer_size)()

libfreefare.mifare_desfire_read_data.restype = c_int
bytes_read = libfreefare.mifare_desfire_read_data(
    tag,
    c_uint8(0x01),  # File ID
    c_int(0),       # offset
    c_int(0),       # length = 0 -> tout lire
    buffer
)

if bytes_read < 0:
    print("Erreur lecture fichier")
else:
    data = bytes(buffer[:bytes_read])
    print(f"Données lues ({bytes_read} octets):")
    print(data.hex())

# ================= CLEANUP =================

libfreefare.mifare_desfire_disconnect(tag)
libfreefare.freefare_free_tags(tags)
libnfc.nfc_close(device)
libnfc.nfc_exit(context)

print("Terminé")




