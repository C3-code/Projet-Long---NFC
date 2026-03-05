import serial
import struct
import time

# --- Constantes Protocole (Iceman) ---
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50
CMD_HF_ISO14443A_READER   = 0x0385

# Flags : bit 1 (No Disc) + bit 3 (Raw) + bit 6 (Active Snoop)
FLAGS_LISTEN = (1 << 1) | (1 << 3) | (1 << 6)
# Flags pour le tag : on ajoute bit 4 (Append CRC)
FLAGS_TAG    = (1 << 1) | (1 << 3) | (1 << 4)

def build_raw_payload(flags, data=b''):
    # Structure MIX : 3 args uint64 (24 octets) + data
    return struct.pack('<QQQ', flags, len(data), 0) + data

def build_cmd(cmd, data=b''):
    # On utilise le bit NG (bit 15) pour les commandes data
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    pre = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    return pre + data + struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)

def read_resp(ser, timeout=0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ser.in_waiting >= 10:
            head = ser.read(10)
            magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', head)
            if magic != RESPONSENG_PREAMBLE_MAGIC: continue
            
            length = length_ng & 0x7FFF
            payload = ser.read(length)
            ser.read(2) # Postamble
            # En mode MIX, les data utiles sont après les 24 octets d'args
            return payload[24:] if len(payload) >= 24 else payload
    return None


def read_hf_air(ser, timeout=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ser.in_waiting >= 10:
            # On cherche le MAGIC de réponse
            head = ser.read(10)
            magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', head)
            
            if magic != RESPONSENG_PREAMBLE_MAGIC:
                continue # On ignore le texte de debug/bruit
            
            length = length_ng & 0x7FFF
            payload = ser.read(length)
            ser.read(2) # Postamble
            
            # CRUCIAL : On vérifie s'il y a de la donnée APRES les 24 octets MIX
            if len(payload) > 24:
                hf_data = payload[24:]
                # On retourne la trame brute capturée dans l'air
                return hf_data 
    return None

# --- Exécution ---
#ser = serial.Serial('/dev/ttyACM0', 460800, timeout=0.1)

# --- Nouveau setup de connexion ---
import serial

ser = serial.Serial()
ser.port = '/dev/ttyACM0'
ser.baudrate = 115200 
ser.timeout = 0.1
ser.write_timeout = 1.0 # Empeche le blocage infini sur ser.write()
ser.exclusive = True    # Demande l'accès exclusif au port

try:
    ser.open()
    ser.reset_input_buffer()
    ser.reset_output_buffer()
except Exception as e:
    print(f"[-] Impossible d'ouvrir le port : {e}")
    exit()


# --- Nouveau setup de connexion ---
import serial

ser = serial.Serial()
ser.port = '/dev/ttyACM0'
ser.baudrate = 115200 # Plus stable pour le debug
ser.timeout = 0.1
ser.write_timeout = 1.0 # Empeche le blocage infini sur ser.write()
ser.exclusive = True    # Demande l'accès exclusif au port

try:
    ser.open()
    ser.reset_input_buffer()
    ser.reset_output_buffer()
except Exception as e:
    print(f"[-] Impossible d'ouvrir le port : {e}")
    exit()

print("[*] START : Écoute active du lecteur...")


# NETTOYAGE DES BUFFERS
ser.reset_input_buffer()
ser.reset_output_buffer()
time.sleep(0.2) # Pause pour laisser le hardware respirer

print("[*] START : Écoute active du lecteur...")



try:
    reqa = None
    while not reqa:
        print("in whie")
        # ÉTAPE CRUCIALE : On "pousse" le PM3 à écouter le champ
        payload = build_raw_payload(FLAGS_LISTEN)
        packet = build_cmd(CMD_HF_ISO14443A_READER, payload)
        
        # ENVOI FORCE
        ser.write(packet)
        ser.flush() # CRUCIAL : Force l'envoi physique sur le câble
        
        print("Commande partie, attente réponse...")
        # On check la réponse
        reqa = read_hf_air(ser, timeout=0.05)
        print("requa -->",reqa)
        
        if reqa:
            # Filtrage des messages système type "on: -8 PM3_EIO"
            if b'PM3' in reqa or b'on:' in reqa or len(reqa) < 1:
                reqa = None
                continue
            print(f"[+] REQA Capturé ! Data: {reqa.hex().upper()}")

    print("\n[!] PHASE 2 : Capture réussie.")
    input("Pose le PM3 sur le TAG et appuie sur ENTREE...")

    print(f"[*] Envoi de {reqa.hex()} au tag...")
    ser.write(build_cmd(CMD_HF_ISO14443A_READER, build_raw_payload(FLAGS_TAG, reqa)))
    
    time.sleep(0.1)
    atqa = read_resp(ser, timeout=0.5)
    
    if atqa:
        print(f"[SUCCESS] ATQA reçu du tag : {atqa.hex().upper()}")
    else:
        print("[-] Pas de réponse du tag. Vérifie le placement de l'antenne.")

except KeyboardInterrupt:
    print("\nArrêt.")
finally:
    ser.close()