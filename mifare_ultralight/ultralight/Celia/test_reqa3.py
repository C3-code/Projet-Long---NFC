#!/usr/bin/env python3
import serial

ser = serial.Serial('COM4', 115200, timeout=1)

def pd(data):
    return list(data) #pour 0x26 retourne 38

print('Waiting for REQA (0x26)...')
compteur =0
# -----------------------------
# Attente d'une trame REQA
# -----------------------------
while True and compteur<20 :
    data = ser.read(1) #retourne des bytes
    if not data:
        print("Je ne vois rien \n")
        compteur+=1
        continue

    byte = data[0]

    if byte == 0x26:
        print("REQA detected (0x26)")
        break
    else:
        print("Received:", byte)

#print("Reader requested card activation")
#list
# -----------------------------
# Lecture du paquet suivant
# -----------------------------
# lenpk = ser.read(1)
# if not lenpk:
#     print("No response length received")
#     ser.close()
#     exit()

# bufferlen = lenpk[0]
# buffer = ser.read(bufferlen)

# ping = pd(buffer)

# if len(ping) == 7:
#     print('UID:', toHexString(ping[:4]))
#     print('ATQA:', toHexString(ping[4:-1]))
#     print('SAK:', toHexString(ping[-1:]))

# elif len(ping) == 10:
#     print('UID:', toHexString(ping[:7]))
#     print('ATQA:', toHexString(ping[7:-1]))
#     print('SAK:', toHexString(ping[-1:]))

# else:
#     print('Unknown packet:', ping)

ser.close()