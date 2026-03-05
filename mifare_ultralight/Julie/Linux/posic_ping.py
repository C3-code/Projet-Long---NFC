import serial
import struct
import time

# Constantes tirées directement du code source
COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50  # "PM3a"
COMMANDNG_POSTAMBLE_MAGIC = 0x3361      # "a3" - utilisé quand pas de CRC (USB)
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50  # "PM3b"

CMD_PING = 0x0109

def send_ng(ser, cmd, data=b''):
    length = len(data)
    # length sur 15 bits, ng bit = 1 (bit 15)
    length_ng = (length & 0x7FFF) | (1 << 15)

    # Preamble : magic(4) + length_ng(2) + cmd(2)
    preamble = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    # Postamble : magic fixe car send_with_crc_on_usb = false
    postamble = struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)

    packet = preamble + data + postamble
    print(f"Envoi ({len(packet)} bytes): {packet.hex()}")
    ser.write(packet)
    ser.flush()

def read_ng(ser, timeout=3):
    # PacketResponseNGPreamble :
    # magic(4) + length_ng(2) + cmd(2) + status(1) + reason(1) = 10 bytes
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10 and time.time() < deadline:
        chunk = ser.read(10 - len(raw))
        raw += chunk

    if len(raw) < 10:
        print(f"Timeout preamble, reçu {len(raw)} bytes: {raw.hex()}")
        return None

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1

    print(f"magic=0x{magic:08X} cmd=0x{cmd:04X} length={length} ng={ng_bit} status={status} reason={reason}")

    if magic != RESPONSENG_PREAMBLE_MAGIC:
        print(f"Mauvais magic! Attendu 0x{RESPONSENG_PREAMBLE_MAGIC:08X}")
        return None

    # Lire les données variables
    data = b''
    if length > 0:
        deadline2 = time.time() + 2
        while len(data) < length and time.time() < deadline2:
            data += ser.read(length - len(data))

    # Lire postamble (2 bytes CRC/magic)
    postamble = ser.read(2)
    crc = struct.unpack('<H', postamble)[0] if len(postamble) == 2 else 0
    print(f"postamble=0x{crc:04X} data={data.hex()}")

    return {'cmd': cmd, 'status': status, 'reason': reason, 'data': data}

# ---- Main ----
ser = serial.Serial('/dev/ttyACM0', baudrate=115200, timeout=1)
ser.reset_input_buffer()
ser.reset_output_buffer()
time.sleep(0.1)

# Ping avec 32 bytes de données (comme TestProxmark dans le source)
ping_data = bytes(range(32))
send_ng(ser, CMD_PING, ping_data)

resp = read_ng(ser)
if resp:
    print(f"\nSUCCES! Réponse ping reçue")
    print(f"  cmd=0x{resp['cmd']:04X} status={resp['status']}")
    print(f"  data={resp['data'].hex()}")
    if resp['data'] == ping_data:
        print("  Données ping identiques ✓")
else:
    print("\nÉCHEC: pas de réponse")

ser.close()
