#!/usr/bin/env python3
"""
Debug : teste différentes combinaisons de flags pour détecter un tag
sur /dev/ttyACM1 (mole)
"""

import serial
import struct
import time

COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_PING                = 0x0109
CMD_HF_ISO14443A_READER = 0x0385


def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b''):
    payload   = struct.pack('<QQQ', arg0, arg1, arg2) + data
    length_ng = len(payload) & 0x7FFF   # ng_bit = 0
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += payload
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    print(f"  >> cmd=0x{cmd:04X} arg0=0x{arg0:08X} payload={payload[:8].hex()}...")
    ser.write(pkt)
    ser.flush()


def send_ng(ser, cmd, data=b''):
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += data
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    ser.write(pkt)
    ser.flush()


def read_all(ser, timeout=5.0):
    """Lire tout ce qui arrive pendant `timeout` secondes."""
    deadline = time.time() + timeout
    buf = b''
    while time.time() < deadline:
        c = ser.read(256)
        if c:
            buf += c
            deadline = time.time() + 0.5  # reset si on reçoit des données
    return buf


def read_response(ser, timeout=5.0):
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10:
        if time.time() > deadline:
            print(f"  << TIMEOUT ({len(raw)}/10 bytes reçus)")
            # Vider le buffer et afficher ce qu'on a eu
            leftover = ser.read(256)
            if raw or leftover:
                print(f"  << Bytes reçus: {(raw+leftover).hex()}")
            return None
        c = ser.read(10 - len(raw))
        if c:
            raw += c

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1

    print(f"  << magic=0x{magic:08X} cmd=0x{cmd:04X} st={status} ng={ng_bit} len={length}")

    if magic != RESPONSENG_PREAMBLE_MAGIC:
        print(f"  << BAD MAGIC (attendu 0x{RESPONSENG_PREAMBLE_MAGIC:08X})")
        ser.reset_input_buffer()
        return None

    payload = b''
    if length > 0:
        dl = time.time() + 3.0
        while len(payload) < length and time.time() < dl:
            payload += ser.read(length - len(payload))

    ser.read(2)  # postamble

    args = (0, 0, 0)
    data_out = payload
    if not ng_bit and len(payload) >= 24:
        args = struct.unpack('<QQQ', payload[:24])
        data_out = payload[24:]

    print(f"  << args=({args[0]}, {args[1]}, {args[2]})")
    print(f"  << data ({len(data_out)} bytes): {data_out[:40].hex()}")

    return {'cmd': cmd, 'status': status, 'ng': ng_bit, 'args': args, 'data': data_out}


PORT = '/dev/ttyACM1'
print(f"Ouverture {PORT}...")
ser = serial.Serial(PORT, baudrate=115200, timeout=0.1)
time.sleep(0.3)
ser.reset_input_buffer()
ser.reset_output_buffer()

# ── 1. Ping ──────────────────────────────────────────────────────────────────
print("\n=== TEST 1 : PING ===")
d = bytes(range(32))
send_ng(ser, CMD_PING, d)
r = read_response(ser, timeout=3.0)
if r and r['data'] == d:
    print("  PING OK ✓")
else:
    print("  PING FAILED ✗")
    ser.close()
    exit(1)

# ── 2. Tests connect tag avec différents flags ────────────────────────────────
ISO14A_CONNECT      = (1 << 0)
ISO14A_NO_DISCONNECT= (1 << 1)
ISO14A_RAW          = (1 << 3)
ISO14A_APPEND_CRC   = (1 << 4)
ISO14A_NO_RATS      = (1 << 7)

tests = [
    ("CONNECT seul",                    ISO14A_CONNECT),
    ("CONNECT + NO_DISCONNECT",         ISO14A_CONNECT | ISO14A_NO_DISCONNECT),
    ("CONNECT + NO_DISCONNECT + NO_RATS", ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS),
    ("CONNECT + NO_RATS",               ISO14A_CONNECT | ISO14A_NO_RATS),
]

for name, flags in tests:
    print(f"\n=== TEST : {name} (flags=0x{flags:04X}) ===")
    print("  Place le tag sur le lecteur maintenant...")
    time.sleep(1.0)
    ser.reset_input_buffer()
    send_mix(ser, CMD_HF_ISO14443A_READER, arg0=flags)
    r = read_response(ser, timeout=5.0)
    if r:
        print(f"  => Réponse reçue ! status={r['status']}")
        if r['data'] and len(r['data']) >= 14:
            uid_raw = r['data'][0:10]
            uid_len = r['data'][10]
            atqa    = r['data'][11:13]
            sak     = r['data'][13]
            uid     = uid_raw[:uid_len]
            print(f"  => UID={uid.hex()}  ATQA={atqa.hex()}  SAK={sak:02X}")
        break
    else:
        print(f"  => Pas de réponse avec ces flags")

ser.close()
print("\nFin du test.")