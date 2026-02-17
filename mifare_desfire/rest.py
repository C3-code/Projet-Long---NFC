#!/usr/bin/env python3
import json
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from nfc_wrapper import nfc_init, nfc_exit, get_uid, read_card, write_block
from bdd_utils import get_info_from_bdd, create_blocks_from_bdd

from datetime import datetime, date
from collections import deque
import threading
import time



# Buffer circulaire des logs (ex: 200 derniers messages)
log_buffer = deque(maxlen=200)
log_lock = threading.Lock()

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with log_lock:
        log_buffer.append(line)
        
        
def parse_nfc_date(date_str):
    """
    Parse une date NFC vers un objet date.
    Retourne None si invalide.
    """
    if not date_str:
        return None

    try:
        return datetime.strptime(date_str.strip(), "%Y%m%d").date()
    except ValueError:
        return None
        
# Verrou global pour éviter les accès NFC concurrents
nfc_lock = threading.Lock()

# Flag pour arrêter proprement le thread si besoin
background_running = True

def background_nfc_monitor(interval=2):
    """
    Thread de lecture NFC en arrière-plan.
    Vérifie périodiquement la présence d'un badge.
    """
    print("🟡 NFC background monitor started")

    last_uid = None

    while background_running:
        time.sleep(interval)

        # Si une requête HTTP utilise déjà le NFC, on saute ce cycle
        if not nfc_lock.acquire(blocking=False):
            continue

        try:
            nfc_init()

            res, uid, detected = get_uid()

            if detected:
                log(f"");
                log(f"🟢 Badge détecté (background): {uid}")


                # Exemple : vérification BDD locale
                info = get_info_from_bdd(uid)
                if len(info) > 0:
                    log(f"   ↳ Utilisateur existant")
                    if (info[0]['access_rights'] & 0x02) > 0:
                        log(f"   ↳ Utilisateur disposant des droits d'accès physique")
                                
                        res, blocks, detected2 = read_card()
                        
                        if detected2:
                            last_name_nfc = bytes_to_str(blocks[4])
                            first_name_nfc = bytes_to_str(blocks[5])
                            entry_date_nfc = bytes_to_str(blocks[8])
                            exit_date_nfc = bytes_to_str(blocks[9])

                            log(f"   ↳ Lecture badge...")
                            log(f"         ↳ date d'entrée: " + str(entry_date_nfc) + " - date de sortie: " + str(exit_date_nfc))
                            
                            today = date.today()

                            start_date = parse_nfc_date(entry_date_nfc)
                            end_date = parse_nfc_date(exit_date_nfc)

                            if not start_date or not end_date:
                                log("   ↳ ⚠️ Dates NFC invalides → badge refusé")
                            elif today < start_date:
                                log("   ↳ ⏳ Badge pas encore valide")
                            elif today > end_date:
                                log("   ↳ ⛔ Badge expiré")
                            else:
                                log("   ↳ ✅ Badge valide (période OK)")
                    else:
                        log(f"Utilisateur sans accès physique autorisé.")
                else:
                    log("Badge inconnu")

            if not detected:
                last_uid = None

        except Exception as e:
            print("❌ Background NFC error:", e)

        finally:
            try:
                nfc_exit()
            except:
                pass
            nfc_lock.release()


HOST = 'localhost'
PORT = 5000

def safe_ascii(block):
    try:
        s = block.rstrip(b'\x00').decode('ascii', errors='ignore')
        return s if s.strip() else None
    except Exception:
        return None


def block_to_bytes(b):
    return bytes(b) if isinstance(b, list) else b


def bytes_to_str(b):
    return block_to_bytes(b).rstrip(b'\x00').decode('ascii', errors='ignore')


class NFCHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        try:
            # ---------- /getuid ----------
            if parsed.path == '/getuid':
                with nfc_lock:
                    nfc_init()
                    res, uid, detected = get_uid()
                    nfc_exit()
                    self._send_json({
                        "res": res,
                        "uid": uid,
                        "detected": detected
                    })
                    return

            # ---------- /read ----------
            elif parsed.path == '/read':
                with nfc_lock:
                    nfc_init()

                    res, uid, detected = get_uid()
                    if not detected:
                        nfc_exit()
                        self._send_json({"error": "No card detected"}, 200)
                        return

                    res, blocks, detected2 = read_card()
                    nfc_exit()
                    print(res)
                    if not detected2:
                        self._send_json({"error": "Read failed"}, 200)
                        return
                    try:
                        self._send_json({
                            "uid": uid,
                            "last_name": bytes_to_str(blocks[4]),
                            "first_name": bytes_to_str(blocks[5]),
                            "entry_date": bytes_to_str(blocks[8]),
                            "exit_date": bytes_to_str(blocks[9])
                        })
                        return
                    except Exception as e:
                        self._send_json({"error": "Read failed"}, 200)
                        return
            # ---------- /create ----------
            if parsed.path == "/create":
                with nfc_lock:
                    if nfc_init() != 0:
                        self._send_json({"error": "NFC init failed"}, 200)
                        return

                    try:
                        # Détection carte
                        res, uid, detected = get_uid()
                        if res != 0 or not detected:
                            self._send_json({"error": "No card detected"}, 200)
                            return

                        # BDD
                        info = get_info_from_bdd(uid)
                        if not info:
                            self._send_json({
                                "error": "Card not found in DB",
                                "uid": uid
                            }, 404)
                            return

                        blocks = create_blocks_from_bdd(info)

                        # Écriture
                        for block_num, data in blocks.items():
                            if len(data) != 16:
                                self._send_json({
                                    "error": f"Invalid block size {block_num}"
                                }, 500)
                                return

                            res, detected = write_block(block_num, data)
                            if res != 0 or not detected:
                                self._send_json({
                                    "error": f"Write failed at block {block_num}"
                                }, 500)
                                return

                        self._send_json({
                            "status": "ok",
                            "uid": uid,
                            "written_blocks": list(blocks.keys())
                        })

                    finally:
                        nfc_exit()
                    return
            elif parsed.path == "/logs":
                with log_lock:
                    self._send_json({
                        "logs": list(log_buffer)
                    })
                return
            # ---------- unknown ----------
            self._send_json({"error": "Unknown endpoint"}, 200)

        except Exception as e:
            traceback.print_exc()
            try:
                nfc_exit()
            except:
                pass
            self._send_json({"error": str(e)}, 200)

def run():
    # Thread background NFC
    t = threading.Thread(
        target=background_nfc_monitor,
        args=(0.2,),  # intervalle en secondes
        daemon=True
    )
    t.start()

    server = HTTPServer((HOST, PORT), NFCHandler)
    print(f"🟢 NFC REST API listening on {HOST}:{PORT}")
    server.serve_forever()

    
    
if __name__ == '__main__':
    run()

