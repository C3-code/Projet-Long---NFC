/*
 * pm3_relay.c — Serveur relay ISO 14443-4A
 * Architecture : tag <-HF-> PM3-MOLE <-USB-> PC <-USB-> PM3-PROXY <-HF-> reader
 *
 * Compatible avec le firmware burja8x (relay_mole.c / relay_proxy.c)
 *
 * Compilation : gcc -O2 -o pm3_relay pm3_relay.c
 * Usage       : ./pm3_relay
 *
 * Protocole pipe.c burja8x :
 *   Le client PM3 ouvre ces chemins hardcodés :
 *     /tmp/proxmark_relay_read  → il LIT  depuis ce fichier (server écrit ici)
 *     /tmp/proxmark_relay_write → il ÉCRIT dans ce fichier  (server lit ici)
 */


 
/* iens uties --> https://github.com/burja8x/relay/blob/main/proxmark3-relay/client/src/relay_mole.c
// https://github.com/burja8x/relay/blob/main/proxmark3-relay/client/src/relay_proxy.c */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>

/* ─── CONFIG ──────────────────────────────────────────────────────────────── */
#define PM3_BIN     "./pm3"          /* adapter selon votre chemin */
#define MOLE_PORT   "/dev/ttyACM0"
#define PROXY_PORT  "/dev/ttyACM1"

/* Chemins hardcodés dans pipe.c burja8x */
#define FIFO_DEFAULT_R  "/tmp/proxmark_relay_read"
#define FIFO_DEFAULT_W  "/tmp/proxmark_relay_write"

/* FIFOs custom pour chaque client */
#define FIFO_MOLE_R     "/tmp/pm3_mole_r"   /* server écrit → mole lit   */
#define FIFO_MOLE_W     "/tmp/pm3_mole_w"   /* mole écrit  → server lit  */
#define FIFO_PROXY_R    "/tmp/pm3_proxy_r"  /* server écrit → proxy lit  */
#define FIFO_PROXY_W    "/tmp/pm3_proxy_w"  /* proxy écrit → server lit  */

#define MAX_PKT  4096

/* ─── PROTOCOLE PacketToPipe (burja8x pipe.c) ─────────────────────────────── */
/* Commandes principales */
#define P_PING        0x00
#define P_RELAY       0x01
#define P_KILL        0x03
#define P_INFO        0x04
#define P_LOG         0x05
#define P_SEND_BACK   0x06
#define P_SEND_BACK_2 0x07

/*
 * Sous-commandes P_RELAY — data[0]
 * Telles qu'utilisées dans relay_mole.c et relay_proxy.c
 */
#define RELAY_TAG_INFO          0x01  /* MOLE→SERVER : infos carte (UID/ATQA/SAK/ATS) */
#define RELAY_RAW               0x02  /* PROXY→SERVER: commande brute du reader        */
#define RELAY_REPLY_RAW         0x03  /* MOLE→SERVER : réponse brute du tag            */
#define RELAY_START             0x04  /* SERVER→MOLE : démarrer la sélection           */
#define RELAY_SET_INSERT        0x05  /* SERVER→MOLE : règle d'insertion MITM          */
#define RELAY_SET_CHANGE        0x06  /* SERVER→PROXY: règle de modification MITM      */
#define RELAY_SET_QUICK_REPLY   0x08
#define RELAY_SET_TEST_TIME     0x09
#define RELAY_SET_TEST_TIME4    0x0A
#define RELAY_PROXY_END         0x0B  /* fin du proxy                                  */
#define RELAY_PROXY_TRACE       0x0C  /* trace packet depuis proxy                     */

/* ─── GLOBALS ─────────────────────────────────────────────────────────────── */
static pid_t pid_mole  = -1;
static pid_t pid_proxy = -1;

/* Descripteurs FIFOs */
static int fd_mr = -1;  /* server lit  ← mole  écrit (FIFO_MOLE_W)  */
static int fd_mw = -1;  /* server écrit→ mole  lit   (FIFO_MOLE_R)  */
static int fd_pr = -1;  /* server lit  ← proxy écrit (FIFO_PROXY_W) */
static int fd_pw = -1;  /* server écrit→ proxy lit   (FIFO_PROXY_R) */

static int  apdu_count = 0;
static double t0_ms    = 0.0;

/* ─── TIMING / LOG ────────────────────────────────────────────────────────── */
static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void logf_(const char *pfx, const char *fmt, ...) {
    printf("[%10.2f ms] %s ", now_ms() - t0_ms, pfx);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static void log_hex(const char *tag, const uint8_t *d, int n) {
    printf("[%10.2f ms] %-36s (%3dB): ", now_ms() - t0_ms, tag, n);
    int s = n > 48 ? 48 : n;
    for (int i = 0; i < s; i++) printf("%02X ", d[i]);
    if (n > 48) printf("...(+%dB)", n - 48);
    printf("\n");
    fflush(stdout);
}

#define INFO(...) logf_("[INFO] ", __VA_ARGS__)
#define WARN(...) logf_("[WARN] ", __VA_ARGS__)
#define ERR(...)  logf_("[ERR]  ", __VA_ARGS__)

/* ─── FIFO ────────────────────────────────────────────────────────────────── */
static void make_fifo(const char *p) {
    unlink(p);
    if (mkfifo(p, 0666) < 0) { perror(p); exit(1); }
}

static void set_symlinks(const char *fifo_r, const char *fifo_w) {
    unlink(FIFO_DEFAULT_R);
    unlink(FIFO_DEFAULT_W);
    if (symlink(fifo_r, FIFO_DEFAULT_R) < 0) { perror("symlink R"); exit(1); }
    if (symlink(fifo_w, FIFO_DEFAULT_W) < 0) { perror("symlink W"); exit(1); }
    INFO("symlinks: READ→%s  WRITE→%s", fifo_r, fifo_w);
}

static void del_all(void) {
    unlink(FIFO_MOLE_R);  unlink(FIFO_MOLE_W);
    unlink(FIFO_PROXY_R); unlink(FIFO_PROXY_W);
    unlink(FIFO_DEFAULT_R); unlink(FIFO_DEFAULT_W);
}

/* ─── LECTURE FIABLE ──────────────────────────────────────────────────────── */
static int read_n(int fd, uint8_t *buf, int n, int tms) {
    int got = 0;
    double dl = now_ms() + tms;
    while (got < n) {
        double rem = dl - now_ms();
        if (rem <= 0) return got;
        fd_set r;
        FD_ZERO(&r);
        FD_SET(fd, &r);
        struct timeval tv = { (int)(rem / 1000), (long)((int)rem % 1000) * 1000 };
        if (select(fd + 1, &r, NULL, NULL, &tv) <= 0) return got;
        int k = read(fd, buf + got, n - got);
        if (k <= 0) return got;
        got += k;
    }
    return got;
}

/* ─── PAQUET PacketToPipe ─────────────────────────────────────────────────── */
/*
 * Format sur le fil (pipe.c burja8x) :
 *   [length_lo][length_hi][cmd][data × length]
 *
 * Note : 'length' dans le paquet = longueur des données SEULEMENT (sans les 3 octets d'en-tête).
 * Attention : dans relay_mole.c on voit parfois length = payload+2 (inclut cmd+status),
 * parfois payload seul. On lit exactement ce qu'indique le champ length.
 */
typedef struct {
    uint16_t length;
    uint8_t  cmd;
    uint8_t  data[MAX_PKT];
} ptp_t;

static int ptp_recv(int fd, ptp_t *p, int tms) {
    uint8_t hdr[3];
    if (read_n(fd, hdr, 3, tms) != 3) return -1;
    p->length = hdr[0] | ((uint16_t)hdr[1] << 8);
    p->cmd    = hdr[2];
    if (p->length > MAX_PKT) { ERR("paquet trop grand %u", p->length); return -1; }
    if (p->length > 0 && read_n(fd, p->data, p->length, 3000) != (int)p->length) return -1;
    return 0;
}

static int ptp_send(int fd, uint8_t cmd, const uint8_t *data, uint16_t len) {
    uint8_t buf[MAX_PKT + 3];
    buf[0] = len & 0xFF;
    buf[1] = len >> 8;
    buf[2] = cmd;
    if (len > 0 && data) memcpy(buf + 3, data, len);
    int w = write(fd, buf, len + 3);
    return (w == (int)(len + 3)) ? 0 : -1;
}

/* Envoie un texte brut (handshake "--START MOLE--" etc.) */
static int send_txt(int fd, const char *txt) {
    uint16_t len = strlen(txt);
    uint8_t buf[MAX_PKT + 3];
    buf[0] = len & 0xFF;
    buf[1] = len >> 8;
    buf[2] = P_INFO;
    memcpy(buf + 3, txt, len);
    int w = write(fd, buf, len + 3);
    return (w == (int)(len + 3)) ? 0 : -1;
}

/* ─── LANCEMENT CLIENT PM3 ────────────────────────────────────────────────── */
static pid_t launch_pm3(const char *port, const char *relay_cmd) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) return pid;
    /* Enfant */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s -p %s -c '%s'", PM3_BIN, port, relay_cmd);
    INFO("Lancement: %s", cmd);
    execl("/bin/sh", "sh", "-c", cmd, NULL);
    perror("execl");
    _exit(1);
}

/* ─── CLEANUP ─────────────────────────────────────────────────────────────── */
static void cleanup(void) {
    INFO("Arrêt...");
    if (fd_mw >= 0) ptp_send(fd_mw, P_KILL, NULL, 0);
    if (fd_pw >= 0) ptp_send(fd_pw, P_KILL, NULL, 0);
    usleep(400000);
    if (pid_mole  > 0) { kill(pid_mole,  SIGTERM); waitpid(pid_mole,  NULL, WNOHANG); }
    if (pid_proxy > 0) { kill(pid_proxy, SIGTERM); waitpid(pid_proxy, NULL, WNOHANG); }
    if (fd_mr >= 0) close(fd_mr);
    if (fd_mw >= 0) close(fd_mw);
    if (fd_pr >= 0) close(fd_pr);
    if (fd_pw >= 0) close(fd_pw);
    del_all();
}

static void sighandler(int s) { (void)s; cleanup(); exit(0); }

/* ─── HANDSHAKE avec un client PM3 ────────────────────────────────────────── */
/*
 * relay_mole.c  envoie "--START MOLE--"  et attend une réponse quelconque.
 * relay_proxy.c envoie "--START RELAY--" et attend "--START RELAY--" en retour.
 *
 * Le serveur doit donc :
 *   1. Lire le message d'intro du client
 *   2. Répondre (écho ou acquittement) pour débloquer le client
 */
static bool handshake(int fd_r, int fd_w, const char *expected, const char *reply, const char *name) {
    ptp_t pkt;
    INFO("[%s] En attente du handshake '%s'...", name, expected);

    /* Tentatives : le client peut envoyer plusieurs paquets avant */
    for (int attempt = 0; attempt < 20; attempt++) {
        if (ptp_recv(fd_r, &pkt, 1000) < 0) {
            WARN("[%s] Pas de paquet (tentative %d)", name, attempt + 1);
            continue;
        }
        /* Le texte est dans data, parfois avec P_INFO ou P_LOG */
        char buf[MAX_PKT + 1] = {0};
        memcpy(buf, pkt.data, pkt.length < MAX_PKT ? pkt.length : MAX_PKT);
        INFO("[%s] Reçu cmd=0x%02X len=%u : '%s'", name, pkt.cmd, pkt.length, buf);

        if (strstr(buf, expected) != NULL || pkt.cmd == P_PING) {
            /* Répondre */
            uint16_t rlen = strlen(reply);
            ptp_send(fd_w, P_INFO, (const uint8_t *)reply, rlen);
            INFO("[%s] Handshake OK, répondu '%s'", name, reply);
            return true;
        }
    }
    ERR("[%s] Handshake échoué !", name);
    return false;
}

/* ─── RELAY LOOP ──────────────────────────────────────────────────────────── */
static void relay_loop(void) {
    printf("\n");
    printf("══════════════════════════════════════════════════════════════\n");
    printf("  RELAY ACTIF\n");
    printf("  tag <-HF-> MOLE(%s) <-USB-> PC <-USB-> PROXY(%s) <-HF-> reader\n",
           MOLE_PORT, PROXY_PORT);
    printf("  Ctrl+C pour arrêter\n");
    printf("══════════════════════════════════════════════════════════════\n\n");

    ptp_t pkt;
    double t_cmd = 0.0;

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        if (fd_mr >= 0) FD_SET(fd_mr, &rfds);
        if (fd_pr >= 0) FD_SET(fd_pr, &rfds);
        int mfd = fd_mr > fd_pr ? fd_mr : fd_pr;

        struct timeval tv = { 30, 0 };
        int r = select(mfd + 1, &rfds, NULL, NULL, &tv);
        if (r == 0) { ERR("Timeout 30s — tag et reader sont-ils présents ?"); break; }
        if (r < 0)  { ERR("select: %s", strerror(errno)); break; }

        /* ════════════════════════════════════════════════════════
         * MESSAGES VENANT DU MOLE
         * (réponses du tag ou informations de connexion)
         * ════════════════════════════════════════════════════════ */
        if (fd_mr >= 0 && FD_ISSET(fd_mr, &rfds)) {
            if (ptp_recv(fd_mr, &pkt, 2000) < 0) {
                ERR("Lecture MOLE KO — FIFO fermée ?");
                break;
            }

            if (pkt.cmd == P_PING) {
                /* Le mole ping le serveur → on répond (on forward aussi au proxy) */
                INFO("MOLE→ PING, réponse...");
                ptp_send(fd_mw, P_PING, pkt.data, pkt.length);

            } else if (pkt.cmd == P_KILL) {
                INFO("MOLE→ KILL reçu, arrêt.");
                ptp_send(fd_pw, P_KILL, NULL, 0);
                goto end;

            } else if (pkt.cmd == P_RELAY) {
                uint8_t  sub    = pkt.data[0];
                uint8_t *pl     = pkt.data + 1;        /* payload après la sous-commande */
                uint16_t pl_len = pkt.length > 0 ? pkt.length - 1 : 0;

                if (sub == RELAY_TAG_INFO) {
                    /*
                     * Le MOLE a sélectionné le tag → forwarder les infos carte au PROXY
                     * pour qu'il démarre l'émulation.
                     */
                    log_hex("TAG→MOLE→PC   [TAG_INFO]", pl, pl_len);
                    INFO("Tag détecté ! Forwarding au PROXY → il va émuler le tag.");
                    ptp_send(fd_pw, P_RELAY, pkt.data, pkt.length);
                    INFO("Approchez le PROXY(%s) du reader.", PROXY_PORT);

                } else if (sub == RELAY_REPLY_RAW) {
                    /*
                     * Réponse du tag → à transmettre au proxy qui la renvoie au reader.
                     */
                    log_hex("TAG→MOLE→PC   [RSP]", pl, pl_len);
                    ptp_send(fd_pw, P_RELAY, pkt.data, pkt.length);
                    log_hex("PC→PROXY→READ [RSP]", pl, pl_len);
                    printf("  ↳ Latence cmd→rsp : %.1f ms\n\n", now_ms() - t_cmd);

                } else if (sub == RELAY_PROXY_TRACE) {
                    /* Trace du mole → on forward au proxy */
                    ptp_send(fd_pw, P_RELAY, pkt.data, pkt.length);

                } else {
                    INFO("MOLE→ P_RELAY sub=0x%02X len=%u (ignoré)", sub, pkt.length);
                }

            } else if (pkt.cmd == P_LOG || pkt.cmd == P_INFO) {
                char buf[MAX_PKT + 1] = {0};
                int n = pkt.length < MAX_PKT ? pkt.length : MAX_PKT;
                memcpy(buf, pkt.data, n);
                printf("  [LOG/MOLE]  %s\n", buf);
                fflush(stdout);

            } else {
                INFO("MOLE→ cmd=0x%02X len=%u (ignoré)", pkt.cmd, pkt.length);
            }
        }

        /* ════════════════════════════════════════════════════════
         * MESSAGES VENANT DU PROXY
         * (commandes du reader à relayer vers le tag)
         * ════════════════════════════════════════════════════════ */
        if (fd_pr >= 0 && FD_ISSET(fd_pr, &rfds)) {
            if (ptp_recv(fd_pr, &pkt, 2000) < 0) {
                ERR("Lecture PROXY KO — FIFO fermée ?");
                break;
            }

            if (pkt.cmd == P_PING) {
                /* Le proxy nous ping → on répond */
                INFO("PROXY→ PING, réponse...");
                ptp_send(fd_pw, P_PING, pkt.data, pkt.length);

            } else if (pkt.cmd == P_KILL) {
                INFO("PROXY→ KILL reçu, arrêt.");
                ptp_send(fd_mw, P_KILL, NULL, 0);
                goto end;

            } else if (pkt.cmd == P_RELAY) {
                uint8_t  sub    = pkt.data[0];
                uint8_t *pl     = pkt.data + 1;
                uint16_t pl_len = pkt.length > 0 ? pkt.length - 1 : 0;

                if (sub == RELAY_RAW) {
                    /*
                     * Commande brute venant du reader (via proxy) → à envoyer au mole
                     * qui la transmettra au tag réel.
                     */
                    apdu_count++;
                    t_cmd = now_ms();
                    printf("── APDU #%d ─────────────────────────────────────────────\n", apdu_count);
                    log_hex("READ→PROXY→PC [CMD]", pl, pl_len);
                    ptp_send(fd_mw, P_RELAY, pkt.data, pkt.length);
                    log_hex("PC→MOLE→TAG   [CMD]", pl, pl_len);

                } else if (sub == RELAY_PROXY_END) {
                    INFO("PROXY→ PROXY_END, arrêt relay.");
                    ptp_send(fd_mw, P_RELAY, pkt.data, pkt.length);
                    goto end;

                } else {
                    INFO("PROXY→ P_RELAY sub=0x%02X len=%u (ignoré)", sub, pkt.length);
                }

            } else if (pkt.cmd == P_LOG || pkt.cmd == P_INFO) {
                char buf[MAX_PKT + 1] = {0};
                int n = pkt.length < MAX_PKT ? pkt.length : MAX_PKT;
                memcpy(buf, pkt.data, n);
                printf("  [LOG/PROXY] %s\n", buf);
                fflush(stdout);

            } else {
                INFO("PROXY→ cmd=0x%02X len=%u (ignoré)", pkt.cmd, pkt.length);
            }
        }
    }

end:
    printf("\n[RELAY] Terminé. %d APDUs relayés.\n", apdu_count);
}

/* ─── OUVERTURE FIFO + HANDSHAKE pour un client ───────────────────────────── */
/*
 * pipe.c burja8x :
 *   fdr = open(proxmark_relay_READ,  O_RDONLY)  → client LIT (= notre écriture)
 *   fdw = open(proxmark_relay_WRITE, O_WRONLY)  → client ÉCRIT (= notre lecture)
 *
 * Donc les symlinks doivent pointer :
 *   proxmark_relay_READ  → FIFO_XXX_R  (que le server ouvre en écriture)
 *   proxmark_relay_WRITE → FIFO_XXX_W  (que le server ouvre en lecture)
 *
 * Pour éviter le deadlock open() bloquant sur FIFO sans l'autre bout :
 *   1. On ouvre notre côté lecture (fd_Xr) en O_NONBLOCK avant le fork
 *   2. On lance le client (fork)
 *   3. On attend que le client ait ouvert ses FDs (sleep)
 *   4. On ouvre notre côté écriture (fd_Xw) — débloque le open(READ) du client
 *   5. On attend le handshake
 */
static bool setup_client(
        const char *fifo_r,   /* FIFO que client lit  / server écrit */
        const char *fifo_w,   /* FIFO que client écrit/ server lit   */
        int *out_fd_r,        /* descripteur server lecture  (←client) */
        int *out_fd_w,        /* descripteur server écriture (→client) */
        const char *port,
        const char *cmd,
        pid_t *out_pid,
        const char *name,
        const char *handshake_expect,
        const char *handshake_reply)
{
    INFO("[%s] Ouverture côté lecture (FIFO_W=%s)...", name, fifo_w);

    /* Ouvrir côté lecture en non-bloquant pour ne pas se bloquer avant le fork */
    *out_fd_r = open(fifo_w, O_RDONLY | O_NONBLOCK);
    if (*out_fd_r < 0) { ERR("open %s (rd): %s", fifo_w, strerror(errno)); return false; }

    /* Pointer les symlinks */
    set_symlinks(fifo_r, fifo_w);

    /* Lancer le client PM3 */
    INFO("[%s] Lancement du client PM3 sur %s avec commande '%s'...", name, port, cmd);
    *out_pid = launch_pm3(port, cmd);

    /* Laisser le client s'initialiser et ouvrir ses FDs */
    sleep(3);

    /* Ouvrir notre côté écriture → débloque le open(READ) côté client */
    INFO("[%s] Ouverture côté écriture (FIFO_R=%s)...", name, fifo_r);
    *out_fd_w = open(fifo_r, O_WRONLY | O_NONBLOCK);
    if (*out_fd_w < 0) { ERR("open %s (wr): %s", fifo_r, strerror(errno)); return false; }

    /* Repasser en mode bloquant pour le relay */
    int fl;
    fl = fcntl(*out_fd_r, F_GETFL, 0); fcntl(*out_fd_r, F_SETFL, fl & ~O_NONBLOCK);
    fl = fcntl(*out_fd_w, F_GETFL, 0); fcntl(*out_fd_w, F_SETFL, fl & ~O_NONBLOCK);

    INFO("[%s] FIFOs OK (fd_r=%d fd_w=%d)", name, *out_fd_r, *out_fd_w);

    /* Handshake */
    if (!handshake(*out_fd_r, *out_fd_w, handshake_expect, handshake_reply, name)) {
        ERR("[%s] Handshake échoué, vérifiez le firmware burja8x et les ports.", name);
        return false;
    }

    return true;
}

/* ─── MAIN ────────────────────────────────────────────────────────────────── */
int main(void) {
    t0_ms = now_ms();
    signal(SIGINT,  sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  PM3 Relay — ISO 14443-4A — 1 PC / 2 PM3 — burja8x         ║\n");
    printf("║  tag<->MOLE(%s)<->PC<->PROXY(%s)<->reader  ║\n", MOLE_PORT, PROXY_PORT);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* 1. Créer les 4 FIFOs */
    INFO("Création des FIFOs...");
    make_fifo(FIFO_MOLE_R);
    make_fifo(FIFO_MOLE_W);
    make_fifo(FIFO_PROXY_R);
    make_fifo(FIFO_PROXY_W);

    /* 2. Lancer et synchroniser le client MOLE */
    printf("\n");
    INFO("═══ DÉMARRAGE MOLE (%s) ═══", MOLE_PORT);
    if (!setup_client(
            FIFO_MOLE_R, FIFO_MOLE_W,
            &fd_mr, &fd_mw,
            MOLE_PORT, "hf 14a relay_mole",
            &pid_mole,
            "MOLE",
            "--START MOLE--",
            "--START MOLE--"   /* on renvoie le même message pour débloquer WaitPipeDate */
    )) {
        cleanup();
        return 1;
    }

    /* 3. Lancer et synchroniser le client PROXY */
    printf("\n");
    INFO("═══ DÉMARRAGE PROXY (%s) ═══", PROXY_PORT);
    if (!setup_client(
            FIFO_PROXY_R, FIFO_PROXY_W,
            &fd_pr, &fd_pw,
            PROXY_PORT, "hf 14a relay",
            &pid_proxy,
            "PROXY",
            "--START RELAY--",
            "--START RELAY--"   /* relay_proxy.c attend de voir "--START RELAY--" en retour */
    )) {
        cleanup();
        return 1;
    }

    /* 4. Relay */
    printf("\n");
    INFO("Prêt !");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  1. Approchez votre TAG du MOLE  (%s)             ║\n", MOLE_PORT);
    printf("║  2. Dès détection → approchez PROXY (%s) du READER║\n", PROXY_PORT);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    relay_loop();

    cleanup();
    return 0;
}