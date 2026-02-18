cat << 'EOF' > emule.py
import subprocess
import re
import time

# --- CONFIGURATION ---
PM3_PATH = "./client/proxmark3.exe"
PORT_READER = "COM10" 

def pm3_exec(cmd):
    # On utilise -c pour passer la commande au client
    return subprocess.run([PM3_PATH, PORT_READER, "-c", cmd], capture_output=True, text=True).stdout

def start_iso14443_init():
    print(f"[*] Démarrage de la séquence d'initialisation sur {PORT_READER}...")
    
    try:
        while True:
            print("\n--- NOUVELLE TENTATIVE D'INITIALISATION ---")
            
            # 1. REQA (Request A) - 7 bits, commande 26
            # On utilise hf 14a raw avec l'option -s (send 7-bit) ou la commande dédiée
            print("[Lecteur >] REQA (0x26)")
            res_reqa = pm3_exec("hf 14a raw -s -k 26")
            
            # 2. ANTICOLLISION (Cascade Level 1)
            # Commande standard : 93 20
            print("[Lecteur >] ANTICOLLISION (93 20)")
            res_anti = pm3_exec("hf 14a raw -c -k 9320")
            
            #anti collision etape 2 : 95 20
            #signal pour réveiller les autres (wupa) : 52
            
            # Extraction de l'UID pour le SELECT
            uid = ""
            for line in res_anti.split('\n'):
                if "received" in line.lower():
                    uid = line.split(":")[-1].strip().replace(" ", "")
                    break
            
            if uid:
                print(f"[Lecteur <] UID reçu : {uid}")
                
                # 3. SELECT (Cascade Level 1)
                # Commande : 93 70 + UID + BCC
                # Note: hf 14a raw -c calcule automatiquement le CRC (70)
                print(f"[Lecteur >] SELECT (93 70 {uid})")
                res_sel = pm3_exec(f"hf 14a raw -c -k 9370{uid}")
                
                for line in res_sel.split('\n'):
                    if "received" in line.lower():
                        sak = line.split(":")[-1].strip().replace(" ", "")
                        print(f"[Lecteur <] SAK reçu : {sak} (Carte en état ACTIVE)")
            else:
                print("[Lecteur <] Aucune réponse à l'anticollision.")

            # Pause avant de recommencer la séquence
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[*] Arrêt du lecteur.")

if __name__ == "__main__":
    start_iso14443_init()
EOF