import serial
import struct
import time

COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_HF_ISO14443A_READER = 0x0385

# Flags depuis mifare.h
ISO14A_CONNECT = (1 << 0)  # 0x001

def send_mix(ser, cmd, arg0=0, arg1=0, arg2=0, data=b''):
    """SendCommandMIX = NG frame mais avec args oldstyle au début des data"""
    args = struct.pack('<QQQ', arg0, arg1, arg2)  # 3x uint64
    payload = args + data

    length = len(payload)
    length_ng = (length & 0x7FFF) | (0 << 15)  # ng bit = 0 pour MIX

    preamble  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    postamble = struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)

    packet = preamble + payload + postamble
    print(f"Envoi ({len(packet)} bytes): {packet.hex()}")
    ser.write(packet)
    ser.flush()

def read_ng(ser, timeout=5):
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10 and time.time() < deadline:
        raw += ser.read(10 - len(raw))

    if len(raw) < 10:
        print(f"Timeout, reçu {len(raw)} bytes: {raw.hex()}")
        return None

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1
    print(f"magic=0x{magic:08X} cmd=0x{cmd:04X} length={length} ng={ng_bit} status={status}")

    data = b''
    if length > 0:
        deadline2 = time.time() + 3
        while len(data) < length and time.time() < deadline2:
            data += ser.read(length - len(data))

    ser.read(2)  # postamble
    return {'cmd': cmd, 'status': status, 'ng': ng_bit, 'data': data}

def parse_card(resp):
    """Parse la réponse ISO14443A"""
    d = resp['data']
    if resp['ng']:
        # NG frame : données directes
        print(f"Raw data: {d.hex()}")
    else:
        # MIX frame : oldarg[0,1,2] + data
        if len(d) >= 24:
            arg0, arg1, arg2 = struct.unpack('<QQQ', d[:24])
            rest = d[24:]
            print(f"arg0={arg0} arg1={arg1} arg2={arg2}")
            print(f"card data: {rest.hex()}")
            # ATQA = 2 bytes, SAK = 1 byte, UID variable
            if len(rest) >= 3:
                atqa = rest[0:2]
                sak  = rest[2]
                uid  = rest[3:3+arg0] if arg0 <= 10 else rest[3:10]
                print(f"ATQA: {atqa.hex()}")
                print(f"SAK:  {sak:02X}")
                print(f"UID:  {uid.hex()}")

# ---- Main ----
ser = serial.Serial('/dev/ttyACM0', baudrate=115200, timeout=1)
ser.reset_input_buffer()
ser.reset_output_buffer()
time.sleep(0.1)

print("Place une carte sur le lecteur...")
send_mix(ser, CMD_HF_ISO14443A_READER, arg0=ISO14A_CONNECT)

resp = read_ng(ser)
if resp:
    parse_card(resp)
else:
    print("Pas de réponse")

ser.close()