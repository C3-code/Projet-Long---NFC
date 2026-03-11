import serial
import struct
import time

# --- Constantes ---
CMD_HF_ISO14443A_READER = 0x0385
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

ISO14A_CONNECT       = (1 << 0)
ISO14A_NO_DISCONNECT = (1 << 1)
ISO14A_RAW           = (1 << 2)
ISO14A_LISTEN        = (1 << 6)  # sniff mode

# --- Helpers ---
def build_payload(flags, timeout_us=500_000, data=b''):
    return struct.pack('<QQQ', flags, len(data), timeout_us) + data

def build_cmd(cmd, data=b''):
    length_ng = (len(data) & 0x7FFF) | (1 << 15)
    return struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd) + data + struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)

def read_resp(ser, timeout=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ser.in_waiting >= 10:
            head = ser.read(10)
            magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', head)
            if magic != RESPONSENG_PREAMBLE_MAGIC:
                continue
            length = length_ng & 0x7FFF
            payload = ser.read(length)
            ser.read(2)  # postamble
            return payload[24:]  # data utile
    return None

# --- Setup ---
ser = serial.Serial('COM3', 115200, timeout=0.1)
ser.reset_input_buffer()
ser.reset_output_buffer()

# --- Allumer champ + sniff ---
flags = ISO14A_CONNECT | ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_LISTEN
payload = build_payload(flags)
ser.write(build_cmd(CMD_HF_ISO14443A_READER, payload))
ser.flush()

print("[*] Écoute du READER pour REQA... (timeout 0.5s)")

resp = read_resp(ser, timeout=1.0)
if resp:
    print(f"[+] REQA détecté : {resp.hex().upper()}")
else:
    print("[-] Aucun REQA reçu, vérifie placement antenne / lecteur")