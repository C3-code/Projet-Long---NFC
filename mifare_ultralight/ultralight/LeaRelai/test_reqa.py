#!/usr/bin/env python3

import serial
import struct
import time

COMMANDNG_PREAMBLE_MAGIC  = 0x61334d50
COMMANDNG_POSTAMBLE_MAGIC = 0x3361
RESPONSENG_PREAMBLE_MAGIC = 0x62334d50

CMD_PING                     = 0x0109
CMD_HF_ISO14443A_SNIFF       = 0x0392
CMD_HF_ISO14443A_GET_TRACE   = 0x0393

PORT = "/dev/ttyACM0"

def send_ng(ser, cmd, data=b''):
    length_ng = (len(data) & 0x7FFF) | (1 << 15)

    pkt  = struct.pack('<IHH', COMMANDNG_PREAMBLE_MAGIC, length_ng, cmd)
    pkt += data
    pkt += struct.pack('<H', COMMANDNG_POSTAMBLE_MAGIC)

    ser.write(pkt)
    ser.flush()

def read_resp(ser, timeout=2):
    deadline = time.time() + timeout
    raw = b''
    while len(raw) < 10:
        if time.time() > deadline:
            return None
        raw += ser.read(10 - len(raw))

    magic, length_ng, cmd, status, reason = struct.unpack('<IHHBB', raw)
    length = length_ng & 0x7FFF
    payload = b''

    while len(payload) < length:
        payload += ser.read(length - len(payload))
    ser.read(2)
    return payload

def ping(ser):
    data = bytes(range(16))
    send_ng(ser, CMD_PING, data)
    resp = read_resp(ser)
    if resp == data:
        print("PING OK")
        return True

    print("PING FAIL")
    return False

def decode_frames(trace):
    i = 0
    while i < len(trace):
        if i + 4 > len(trace):
            break

        length = trace[i]
        direction = trace[i+1]
        frame = trace[i+2:i+2+length]
        i += 2 + length

        if not frame:
            continue
        if direction == 0:
            side = "RDR -> TAG"
        else:
            side = "TAG -> RDR"
        print(f"{side} : {frame.hex()}")

        if frame == b"\x26":
            print(">>> REQA détecté")

        if frame == b"\x52":
            print(">>> WUPA détecté")


def main():
    ser = serial.Serial(PORT,115200,timeout=0.1)
    time.sleep(0.3)
    if not ping(ser):
        return
    print("Starting sniff...")
    send_ng(ser, CMD_HF_ISO14443A_SNIFF)

    try:
        while True:
            time.sleep(0.5)
            send_ng(ser, CMD_HF_ISO14443A_GET_TRACE)
            trace = read_resp(ser)
            if not trace:
                continue
            decode_frames(trace)

    except KeyboardInterrupt:
        print("\nStopped")

if __name__ == "__main__":
    main()