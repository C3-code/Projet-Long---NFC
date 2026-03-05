import serial
import struct

# CRC16 Proxmark (CRC_CCITT)
def crc16(data):
    crc = 0x6363
    for b in data:
        b ^= crc & 0xFF
        b ^= (b << 4) & 0xFF
        crc = (b << 8) ^ (crc >> 8) ^ (b << 3) ^ (b >> 4)
        crc &= 0xFFFF
    return crc

def send_ng(ser, cmd, data=b''):
    MAGIC = 0x61334d50  # PM3a
    
    length = len(data)
    # length:15 bits + ng:1 bit (set to 1 = NG format)
    length_ng = (length & 0x7FFF) | (1 << 15)
    
    preamble = struct.pack('<IHH', MAGIC, length_ng, cmd)
    payload = preamble + data
    
    crc = crc16(payload)
    postamble = struct.pack('<H', crc)
    
    packet = payload + postamble
    print(f"Envoi ({len(packet)} bytes): {packet.hex()}")
    ser.write(packet)
    ser.flush()

def read_ng(ser):
    # Lire preamble : magic(4) + length_ng(2) + cmd(2) + status(1) + reason(1) = 10 bytes
    header = ser.read(10)
    if len(header) < 10:
        print(f"Timeout, reçu seulement {len(header)} bytes: {header.hex()}")
        return None
    
    magic, length_ng, cmd, status, reason = struct.unpack('<IHBBB', header[:11])
    # En fait : magic(4) + length_ng(2) + cmd(2) + status(1) + reason(1) = 10
    magic, length_ng, cmd = struct.unpack('<IHH', header[:8])
    status = header[8]
    reason = header[9]
    
    length = length_ng & 0x7FFF
    ng_bit = (length_ng >> 15) & 1
    
    print(f"magic=0x{magic:08X}, cmd=0x{cmd:04X}, length={length}, ng={ng_bit}, status={status}")
    
    data = ser.read(length) if length > 0 else b''
    crc_bytes = ser.read(2)
    
    return {'cmd': cmd, 'status': status, 'data': data}

# ---- Main ----
ser = serial.Serial('/dev/ttyACM0', baudrate=115200, timeout=3)
ser.reset_input_buffer()
ser.reset_output_buffer()

CMD_PING = 0x0109
send_ng(ser, CMD_PING)

resp = read_ng(ser)
if resp:
    print(f"Réponse: cmd=0x{resp['cmd']:04X} status={resp['status']} data={resp['data'].hex()}")

ser.close()
