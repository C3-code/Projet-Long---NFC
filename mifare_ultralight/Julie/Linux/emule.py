import serial
import struct
import time

COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_HF_ISO14443A_SIMULATE = 0x0384

# Flags UID (depuis pm3_cmd.h)
FLAG_4B_UID_IN_DATA  = 0x0010
FLAG_7B_UID_IN_DATA  = 0x0020
FLAG_10B_UID_IN_DATA = 0x0030

# Types de cartes
TAG_MIFARE_CLASSIC_1K = 1
TAG_MIFARE_ULTRALIGHT = 2
TAG_MIFARE_DESFIRE    = 3
TAG_ISO14443_4        = 4
TAG_MIFARE_CLASSIC_4K = 8
TAG_NTAG215_AMIIBO    = 7

def send_ng(ser, cmd, data=b''):
    length = len(data)
    length_ng = (length & 0x7FFF) | (1 << 15)  # ng=1
    preamble  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    postamble = struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    packet = preamble + data + postamble
    print(f"Envoi ({len(packet)} bytes): {packet.hex()}")
    ser.write(packet)
    ser.flush()

def simulate_card(ser, tagtype, uid_hex):
    uid = bytes.fromhex(uid_hex)
    uid_len = len(uid)
    assert uid_len in (4, 7, 10), "UID doit être 4, 7 ou 10 bytes"

    # Flags selon longueur UID
    if uid_len == 4:
        flags = FLAG_4B_UID_IN_DATA
    elif uid_len == 7:
        flags = FLAG_7B_UID_IN_DATA
    else:
        flags = FLAG_10B_UID_IN_DATA

    # struct payload PACKED :
    # uint8_t  tagtype        (1)
    # uint16_t flags          (2)
    # uint8_t  uid[10]        (10)
    # uint8_t  exitAfter      (1)
    # uint8_t  rats[20]       (20)
    # uint8_t  ulauth_1a1_len (1)
    # uint8_t  ulauth_1a2_len (1)
    # uint8_t  ulauth_1a1[16] (16)
    # uint8_t  ulauth_1a2[16] (16)
    # Total = 68 bytes

    uid_padded = uid + b'\x00' * (10 - uid_len)

    payload = struct.pack('<BH', tagtype, flags)   # tagtype + flags
    payload += uid_padded                           # uid[10]
    payload += struct.pack('<B', 0)                 # exitAfter = 0 (infini)
    payload += b'\x00' * 20                         # rats[20]
    payload += struct.pack('<BB', 0, 0)             # ulauth lens
    payload += b'\x00' * 16                         # ulauth_1a1
    payload += b'\x00' * 16                         # ulauth_1a2

    print(f"Simulation type={tagtype} UID={uid_hex} flags=0x{flags:04X}")
    send_ng(ser, CMD_HF_ISO14443A_SIMULATE, payload)

# ---- Main ----
ser = serial.Serial('/dev/ttyACM0', baudrate=115200, timeout=1)
ser.reset_input_buffer()
ser.reset_output_buffer()
time.sleep(0.1)

# Exemple : émuler un Mifare Classic 1K avec UID 11223344
simulate_card(ser, TAG_MIFARE_CLASSIC_1K, "11223344")

print("Simulation en cours... (Ctrl+C pour stopper)")
try:
    while True:
        data = ser.read(256)
        if data:
            print(f"Reçu: {data.hex()}")
        time.sleep(0.1)
except KeyboardInterrupt:
    print("Arrêt")

ser.close()