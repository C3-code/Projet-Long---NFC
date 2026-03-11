import subprocess

# --- CONFIG --- #
PM3_BIN = r"C:\\Users\\cel_l\\Documents\\P_Long\\ProxSpace-3.11\\pm3\\proxmark3\\client\\proxmark3.exe"
PORT    = "COM4"  # Remplace par le port correct de ton PM3
CMD     = "hf 14a sniff"  # Commande sniff du lecteur

# --- Lancement du client Proxmark --- #
try:
    proc = subprocess.Popen(
        [PM3_BIN, "-p", PORT, "-c", CMD],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
except FileNotFoundError:
    print("[-] Proxmark3 client introuvable, vérifie PM3_BIN")
    exit(1)

print("[*] Sniff en cours, prêt à détecter les REQA (CTRL+C pour arrêter)...\n")

# --- Lecture ligne par ligne et détection REQA --- #
try:
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        # Affiche toutes les lignes du sniff pour debug
        print(line)

        # Détection d'une REQA (0x26)
        if "REQA" in line or "0x26" in line:
            print("[!] REQA détecté !")

except KeyboardInterrupt:
    print("\n[*] Arrêt du sniff.")
    proc.terminate()
    proc.wait()