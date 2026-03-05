#!/usr/bin/env python3
"""
PM3 NFC Relay — NTAG213 / ISO 14443-A
======================================
Approche : utilise le client PM3 (pm3) via subprocess pour les commandes
qui nécessitent une séquence correcte (hf 14a info, hf mfu sim),
et du raw USB pour le relay APDU temps-réel.

Usage :
  python3 pm3_relay.py --mole /dev/ttyACM0 --proxy /dev/ttyACM1
  python3 pm3_relay.py --ping-only
  python3 pm3_relay.py --discover-only   # juste lire le tag et afficher UID/ATQA/SAK
"""

import serial
import struct
import subprocess
import re
import time
import argparse
import sys
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d [%(threadName)-10s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)

# ─── Constantes protocole PM3 NG ─────────────────────────────────────────────

COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_PING                  = 0x0109
CMD_HF_ISO14443A_READER   = 0x0385
CMD_HF_ISO14443A_SIMULATE = 0x0388
CMD_HF_DROPFIELD          = 0x0430
CMD_BREAK_LOOP            = 0x0113
CMD_ACK                   = 0xFF00

ISO14A_CONNECT       = (1 << 0)
ISO14A_NO_DISCONNECT = (1 << 1)
ISO14A_RAW           = (1 << 2)
ISO14A_APPEND_CRC    = (1 << 3)
ISO14A_NO_RATS       = (1 << 7)

MFEMUL_NTAG213 = 7
WTX_APDU       = bytes([0xF2, 0x01])

CARD_UID_OFF    = 0
CARD_UIDLEN_OFF = 10
CARD_ATQA_OFF   = 11
CARD_SAK_OFF    = 13
CARD_MIN_SIZE   = 14


def _reader_payload(flags: int, raw_data: bytes = b'', timeout_us: int = 0) -> bytes:
    return struct.pack('<QQQ', flags, len(raw_data), timeout_us) + raw_data


# ─── Helpers bas niveau ───────────────────────────────────────────────────────

def build_cmd(cmd: int, data: bytes = b'') -> bytes:
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pre  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    post = struct.pack('<H',   COMMANDNG_POSTAMBLE_MAGIC)
    return pre + data + post


def _read_exact(ser: serial.Serial, n: int, deadline: float) -> bytes | None:
    buf = b''
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        ser.timeout = min(left, 0.1)
        chunk = ser.read(n - len(buf))
        if chunk:
            buf += chunk
    return buf


def read_resp(ser: serial.Serial, timeout: float = 3.0) -> dict | None:
    deadline = time.monotonic() + timeout
    target   = struct.pack('<I', RESPONSENG_PREAMBLE_MAGIC)
    buf = b''
    while time.monotonic() < deadline:
        ser.timeout = 0.05
        b = ser.read(1)
        if not b:
            continue
        buf = (buf + b)[-4:]
        if buf == target:
            break
    else:
        return None

    rest = _read_exact(ser, 6, deadline)
    if rest is None:
        return None

    length_ng, cmd, status, reason = struct.unpack('<HHBB', rest)
    length = length_ng & 0x7FFF
    data   = b''
    if length > 0:
        data = _read_exact(ser, length, deadline) or b''

    ser.timeout = 0.05
    ser.read(2)
    print("Recu --> ", data)
    return {'cmd': cmd, 'status': status, 'reason': reason, 'data': data}


# ─── Classe PM3 ───────────────────────────────────────────────────────────────

class PM3:
    def __init__(self, port: str, baud: int = 115200, name: str = 'PM3'):
        self.name = name
        self.port = port
        self.ser  = serial.Serial(port, baudrate=baud, timeout=1)
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        time.sleep(0.15)
        log.info("[%s] Ouvert sur %s", self.name, port)

    def send(self, cmd: int, data: bytes = b''):
        print("Abut t be sent -->", data)
        pkt = build_cmd(cmd, data)
        log.debug("[%s] TX cmd=0x%04X len=%d", self.name, cmd, len(data))
        self.ser.write(pkt)
        self.ser.flush()

    def recv(self, timeout: float = 3.0) -> dict | None:
        r = read_resp(self.ser, timeout=timeout)
        if r:
            preview = r['data'][:40].hex().upper()
            suffix  = '...' if len(r['data']) > 40 else ''
            log.debug("[%s] RX cmd=0x%04X status=%d len=%d  data=%s%s",
                      self.name, r['cmd'], r['status'], len(r['data']), preview, suffix)
        return r

    def recv_until(self, wanted_cmd: int, timeout: float = 5.0) -> dict | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            left = deadline - time.monotonic()
            r    = self.recv(timeout=max(left, 0.1))
            if r is None:
                return None
            if r['cmd'] == wanted_cmd:
                return r
            log.debug("[%s] recv_until: ignoré cmd=0x%04X", self.name, r['cmd'])
        return None

    def drain(self, duration: float = 0.1):
        self.ser.timeout = 0.02
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            if not self.ser.read(256):
                break

    def ping(self) -> bool:
        payload = bytes(range(32))
        self.send(CMD_PING, payload)
        r = self.recv(timeout=3)
        ok = r is not None and r['data'] == payload
        log.info("[%s] PING %s", self.name, "OK ✓" if ok else "ÉCHEC ✗")
        return ok

    def field_off(self):
        try:
            self.send(CMD_HF_DROPFIELD)
            self.drain(0.1)
        except Exception:
            pass

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass


# ─── Découverte via client PM3 (subprocess) ───────────────────────────────────

class TagInfo:
    def __init__(self, uid: bytes, atqa: bytes, sak: int):
        self.uid  = uid
        self.atqa = atqa
        self.sak  = sak

    def __str__(self):
        return (f"UID={self.uid.hex().upper()}  "
                f"ATQA={self.atqa.hex().upper()}  "
                f"SAK=0x{self.sak:02X}")


def _run_pm3_client(port: str, command: str, timeout: int = 10) -> str:
    """
    Lance le client pm3 sur *port*, exécute *command*, retourne la sortie.
    Le client pm3 doit être dans le PATH (ou ajuster PM3_BIN ci-dessous).
    """
    PM3_BIN = '/home/julieb/Desktop/nfc_project/proxmark3/pm3'   # ou '/chemin/vers/proxmark3/pm3'

    cmd = [PM3_BIN, '-p', port, '-c', command]
    log.debug("Subprocess: %s", ' '.join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout + result.stderr
        log.debug("PM3 client output:\n%s", output)
        return output
    except FileNotFoundError:
        raise RuntimeError(
            f"Client PM3 '{PM3_BIN}' introuvable dans le PATH.\n"
            "→ Ajouter le répertoire proxmark3/ au PATH ou modifier PM3_BIN dans le script."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Timeout client PM3 sur commande: {command}")


def discover_tag_via_client(port: str) -> TagInfo:
    """
    Utilise `hf 14a info` via le client PM3 pour lire UID/ATQA/SAK.
    Parse la sortie texte du client.
    """
    log.info("[MOLE] Découverte tag via client PM3 (hf 14a info)...")
    output = _run_pm3_client(port, 'hf 14a info')

    # Parser UID
    uid_match = re.search(r'UID\s*[:\|]\s*([0-9A-Fa-f\s]{6,30})', output)
    if not uid_match:
        # Autre format possible
        uid_match = re.search(r'uid[:\s]+([0-9a-fA-F]{8,20})', output, re.IGNORECASE)

    # Parser ATQA
    atqa_match = re.search(r'ATQA\s*[:\|]\s*([0-9A-Fa-f\s]{4,6})', output)
    if not atqa_match:
        atqa_match = re.search(r'atqa[:\s]+([0-9a-fA-F]{4})', output, re.IGNORECASE)

    # Parser SAK
    sak_match = re.search(r'SAK\s*[:\|]\s*([0-9A-Fa-f]{2})', output)
    if not sak_match:
        sak_match = re.search(r'sak[:\s]+([0-9a-fA-F]{2})', output, re.IGNORECASE)

    if not uid_match:
        log.error("Sortie client PM3:\n%s", output)
        raise RuntimeError(
            "Impossible de parser l'UID depuis la sortie de 'hf 14a info'.\n"
            "→ Vérifier que le tag est posé sur le MOLE.\n"
            "→ Lancer manuellement: pm3 -p %s -c 'hf 14a info'" % port
        )

    uid_str  = uid_match.group(1).replace(' ', '').strip()
    atqa_str = atqa_match.group(1).replace(' ', '').strip() if atqa_match else '0000'
    sak_str  = sak_match.group(1).strip() if sak_match else '00'

    uid  = bytes.fromhex(uid_str)
    atqa = bytes.fromhex(atqa_str.zfill(4))
    sak  = int(sak_str, 16)

    info = TagInfo(uid, atqa, sak)
    log.info("[MOLE] ✓ Tag découvert : %s", info)
    return info


def discover_tag_raw(mole: PM3, retries: int = 5) -> TagInfo:
    """
    Tentative de découverte via raw USB.
    Utilisé comme fallback si le client PM3 n'est pas disponible.
    """
    log.info("[MOLE] Découverte raw USB...")

    # Dans iceman, pour allumer le champ il faut envoyer ISO14A_CONNECT
    # avec arg2 (timeout) = 0x493E0 (300000 µs = 300ms)
    # C'est la valeur utilisée dans hf_iclass.c et iso14443a.c
    TIMEOUT_US = 0x493E0

    flags   = ISO14A_CONNECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS
    payload = _reader_payload(flags, timeout_us=TIMEOUT_US)

    for attempt in range(1, retries + 1):
        log.debug("[MOLE] Raw tentative %d/%d", attempt, retries)
        mole.ser.reset_input_buffer()
        mole.send(CMD_HF_ISO14443A_READER, payload)

        resp = mole.recv_until(CMD_ACK, timeout=4)
        if resp is None:
            log.warning("[MOLE] Pas de réponse")
            time.sleep(0.3)
            continue

        d = resp['data']
        log.debug("[MOLE] Raw payload (%d bytes): %s", len(d), d.hex())

        if resp['status'] == 0:
            msg = d[2:].decode('ascii', errors='replace') if len(d) > 2 else repr(d)
            log.warning("[MOLE] status=0: %r", msg)
            time.sleep(0.3)
            continue

        if len(d) < CARD_MIN_SIZE:
            log.warning("[MOLE] Payload trop court: %d", len(d))
            continue

        uid_len = d[CARD_UIDLEN_OFF]
        if uid_len == 0 or uid_len > 10:
            log.warning("[MOLE] uid_len invalide: %d", uid_len)
            continue

        uid  = bytes(d[CARD_UID_OFF  : CARD_UID_OFF + uid_len])
        atqa = bytes(d[CARD_ATQA_OFF : CARD_ATQA_OFF + 2])
        sak  = d[CARD_SAK_OFF]

        info = TagInfo(uid, atqa, sak)
        log.info("[MOLE] ✓ Tag trouvé (raw): %s", info)
        return info

    raise RuntimeError("Découverte raw échouée après %d essais." % retries)


def discover_tag(mole: PM3, port: str) -> TagInfo:
    """
    Essaie d'abord via le client PM3, sinon fallback sur raw USB.
    """
    # Fermer le port série pour que le client PM3 puisse l'ouvrir
    mole.close()
    time.sleep(0.2)

    try:
        info = discover_tag_via_client(port)
        print(info)
        # Rouvrir le port série
        mole.ser = serial.Serial(port, baudrate=115200, timeout=1)
        mole.ser.reset_input_buffer()
        mole.ser.reset_output_buffer()
        time.sleep(0.15)
        log.info("[MOLE] Port réouvert après client PM3")
        return info
    except RuntimeError as e:
        log.warning("Client PM3 indispo (%s), fallback raw USB", e)
        # Rouvrir et essayer en raw
        mole.ser = serial.Serial(port, baudrate=115200, timeout=1)
        mole.ser.reset_input_buffer()
        mole.ser.reset_output_buffer()
        time.sleep(0.15)
        return discover_tag_raw(mole)


# ─── Simulation PROXY ─────────────────────────────────────────────────────────

def start_proxy_sim(proxy: PM3, tag: TagInfo):
    """Lance hf mfu sim sur le PROXY via client PM3."""
    log.info("[PROXY] Démarrage simulation via client PM3...")

    uid_hex = tag.uid.hex()
    proxy.close()
    time.sleep(0.2)

    # hf mfu sim -t 7 -u <uid>  (type 7 = NTAG213)
    cmd = f'hf mfu sim -t 7 -u {uid_hex}'
    try:
        # On lance en background car hf mfu sim est bloquant
        PM3_BIN = '/home/julieb/Desktop/nfc_project/proxmark3/pm3'
        proc = subprocess.Popen(
            [PM3_BIN, '-p', proxy.port, '-c', cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(1.0)  # laisser le sim démarrer
        log.info("[PROXY] ✓ Simulation démarrée (pid=%d)", proc.pid)

        # Rouvrir pour le relay
        proxy.ser = serial.Serial(proxy.port, baudrate=115200, timeout=1)
        proxy.ser.reset_input_buffer()
        proxy.ser.reset_output_buffer()
        time.sleep(0.15)
        return proc

    except FileNotFoundError:
        log.warning("Client PM3 indispo pour sim, fallback raw USB")
        proxy.ser = serial.Serial(proxy.port, baudrate=115200, timeout=1)
        proxy.ser.reset_input_buffer()
        proxy.ser.reset_output_buffer()
        time.sleep(0.15)
        _start_proxy_sim_raw(proxy, tag)
        return None


def _start_proxy_sim_raw(proxy: PM3, tag: TagInfo):
    """Fallback : lance la simulation via raw USB."""
    log.info("[PROXY] Simulation raw avec %s", tag)
    uid_padded = (tag.uid + b'\x00' * 10)[:10]
    payload = (
        struct.pack('<BB', MFEMUL_NTAG213, 0x00) +
        uid_padded +
        tag.atqa +
        struct.pack('<B', tag.sak)
    )
    proxy.send(CMD_HF_ISO14443A_SIMULATE, payload)
    time.sleep(0.5)
    log.info("[PROXY] ✓ Simulation raw active")


# ─── Relay APDU ───────────────────────────────────────────────────────────────

class APDURelay:

    def __init__(self, mole: PM3, proxy: PM3, tag: TagInfo):
        self.mole     = mole
        self.proxy    = proxy
        self.tag      = tag
        self._running = True

    def _send_wtx(self):
        flags   = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
        payload = _reader_payload(flags, WTX_APDU)
        self.proxy.send(CMD_HF_ISO14443A_READER, payload)
        log.debug("[PROXY→READER] S(WTX)")

    def _relay_to_tag(self, apdu: bytes) -> bytes:
        flags   = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
        payload = _reader_payload(flags, apdu)
        print("reay t tag --> ", payload)
        self.mole.send(CMD_HF_ISO14443A_READER, payload)
        resp = self.mole.recv_until(CMD_ACK, timeout=1.5)
        print("repnse du tag --> ", resp)
        if resp is None or not resp['data']:
            log.warning("[MOLE] Pas de réponse → 6A82")
            return bytes([0x6A, 0x82])
        return resp['data']

    def _forward_to_reader(self, data: bytes):
        flags   = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
        payload = _reader_payload(flags, data)
        print("reay t reader --> ", payload)
        self.proxy.send(CMD_HF_ISO14443A_READER, payload)

    def run(self):
        log.info("══════════════════════════════════════════════")
        log.info("  Relay APDU actif")
        log.info("  READER ──> PROXY ──> [PC] ──> MOLE ──> TAG")
        log.info("  Ctrl+C pour arrêter")
        log.info("══════════════════════════════════════════════")

        exchange = 0
        while self._running:
            print("hey")
            resp = self.proxy.recv_until(CMD_ACK, timeout=1.0)
            print("recu -->", resp)
            if resp is None or not resp['data']:
                continue

            apdu = resp['data']
            exchange += 1
            log.info("── Exchange #%d ──", exchange)
            log.info("[READER→PROXY] %d bytes : %s", len(apdu), apdu.hex().upper())

            self._send_wtx()
            print("wtx just sent")

            tag_resp = self._relay_to_tag(apdu)
            log.info("[TAG→MOLE]     %d bytes : %s", len(tag_resp), tag_resp.hex().upper())

            self._forward_to_reader(tag_resp)
            log.info("[PROXY→READER] ✓")

    def stop(self):
        self._running = False


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='PM3 relay NTAG213')
    p.add_argument('--mole',           default='/dev/ttyACM0')
    p.add_argument('--proxy',          default='/dev/ttyACM1')
    p.add_argument('--baud',           type=int, default=115200)
    p.add_argument('--ping-only',      action='store_true')
    p.add_argument('--discover-only',  action='store_true',
                   help='Lire le tag et afficher UID/ATQA/SAK puis quitter')
    return p.parse_args()


def main():
    args = parse_args()

    log.info("══════════════════════════════════════════")
    log.info("  PM3 NFC Relay — NTAG213")
    log.info("  MOLE  : %s  (côté TAG)",    args.mole)
    log.info("  PROXY : %s  (côté READER)", args.proxy)
    log.info("══════════════════════════════════════════")

    mole  = PM3(args.mole,  baud=args.baud, name='MOLE ')
    proxy = PM3(args.proxy, baud=args.baud, name='PROXY')
    relay = None
    sim_proc = None

    try:
        # 1. Ping (raw USB, toujours ok)
        if not mole.ping() or not proxy.ping():
            log.error("Ping échoué")
            sys.exit(1)

        if args.ping_only:
            log.info("Ping OK ✓")
            sys.exit(0)

        # 2. Découverte UID/ATQA/SAK
        tag = discover_tag(mole, args.mole)
        log.info("══ Tag : %s", tag)

        if args.discover_only:
            log.info("--discover-only : on s'arrête ici")
            sys.exit(0)

        # 3. Simulation PROXY
        #sim_proc = start_proxy_sim(proxy, tag)

        # 4. Relay
        relay = APDURelay(mole, proxy, tag)
        relay.run()

    except RuntimeError as e:
        log.error("ERREUR FATALE :\n%s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interruption (Ctrl+C)")
    finally:
        if relay:
            relay.stop()
        if sim_proc:
            sim_proc.terminate()
        log.info("Arrêt propre...")
        for pm3 in (mole, proxy):
            try:
                pm3.send(CMD_BREAK_LOOP)
                pm3.drain(0.3)
            except Exception:
                pass
            pm3.field_off()
            pm3.close()
        log.info("Done ✓")


if __name__ == '__main__':
    main()