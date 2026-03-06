/*
 * pm3_relay.c — Serveur relay ISO 14443-4A
 * Architecture : tag <-HF-> PM3-MOLE <-USB-> PC <-USB-> PM3-PROXY <-HF-> reader
 *
 * Compilation : gcc -O2 -o pm3_relay pm3_relay.c
 * Usage       : ./pm3_relay
 */

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
#define PM3_BIN     "./pm3"
#define MOLE_PORT   "/dev/ttyACM0"
#define PROXY_PORT  "/dev/ttyACM1"

#define FIFO_DEFAULT_R  "/tmp/proxmark_relay_read"
#define FIFO_DEFAULT_W  "/tmp/proxmark_relay_write"

#define FIFO_MOLE_R     "/tmp/pm3_mole_r"
#define FIFO_MOLE_W     "/tmp/pm3_mole_w"
#define FIFO_PROXY_R    "/tmp/pm3_proxy_r"
#define FIFO_PROXY_W    "/tmp/pm3_proxy_w"

#define MAX_PKT  4096

/* ─── PROTOCOLE — valeurs RÉELLES de pipe.h burja8x ──────────────────────── */
#define P_INFO              1
#define P_SNIFF             2
#define P_RELAY             3
#define P_PING              4
#define P_SEND_BACK         5
#define P_SEND_BACK_2       6
#define P_KILL              7
#define P_LOG               8
#define P_RELAY_PROXY_TRACE 9
#define P_RELAY_MOLE_TRACE  10

/* Sous-commandes P_RELAY — valeurs RÉELLES de relay_proxy.h burja8x */
#define RELAY_START             1
#define RELAY_TAG_INFO          3
#define RELAY_RAW               4
#define RELAY_REPLY_RAW         5
#define RELAY_PROXY_END         7
#define RELAY_PROXY_TRACE       9
#define RELAY_SET_INSERT        12
#define RELAY_SET_CHANGE        13
#define RELAY_SET_QUICK_REPLY   14
#define RELAY_SET_TEST_TIME4    15
#define RELAY_SET_TEST_TIME     16

/* ─── GLOBALS ─────────────────────────────────────────────────────────────── */
static pid_t pid_mole  = -1;
static pid_t pid_proxy = -1;
static int fd_mr = -1;
static int fd_mw = -1;
static int fd_pr = -1;
static int fd_pw = -1;
static int    apdu_count = 0;
static double t0_ms      = 0.0;

/* ─── LOG ─────────────────────────────────────────────────────────────────── */
static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}
static void logf_(const char *pfx, const char *fmt, ...) {
    printf("[%10.2f ms] %s ", now_ms() - t0_ms, pfx);
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n"); fflush(stdout);
}
static void log_hex(const char *tag, const uint8_t *d, int n) {
    printf("[%10.2f ms] %-34s (%3dB): ", now_ms() - t0_ms, tag, n);
    int s = n > 32 ? 32 : n;
    for (int i = 0; i < s; i++) printf("%02X ", d[i]);
    if (n > 32) printf("...(+%dB)", n-32);
    printf("\n"); fflush(stdout);
}
#define INFO(...) logf_("[INFO] ", __VA_ARGS__)
#define WARN(...) logf_("[WARN] ", __VA_ARGS__)
#define ERR(...)  logf_("[ERR]  ", __VA_ARGS__)

/* ─── FIFO ────────────────────────────────────────────────────────────────── */
static void make_fifo(const char *p) {
    unlink(p);
    if (mkfifo(p, 0666) < 0) { perror(p); exit(1); }
}
static void set_symlinks(const char *r, const char *w) {
    unlink(FIFO_DEFAULT_R); unlink(FIFO_DEFAULT_W);
    if (symlink(r, FIFO_DEFAULT_R) < 0) { perror("symlink R"); exit(1); }
    if (symlink(w, FIFO_DEFAULT_W) < 0) { perror("symlink W"); exit(1); }
    INFO("symlinks: READ→%s  WRITE→%s", r, w);
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
        fd_set r; FD_ZERO(&r); FD_SET(fd, &r);
        struct timeval tv = { (int)(rem/1000), (long)((int)rem%1000)*1000 };
        if (select(fd+1, &r, NULL, NULL, &tv) <= 0) return got;
        int k = read(fd, buf+got, n-got);
        if (k <= 0) return got;
        got += k;
    }
    return got;
}

/* ─── PAQUET PacketToPipe ─────────────────────────────────────────────────── */
/*
 * Format exact pipe.h :
 *   [length_lo][length_hi][cmd][data x length]
 *   total = length + 3
 *
 * Pour P_RELAY :
 *   data[0] = sous-commande (RELAY_TAG_INFO=3, RELAY_RAW=4, RELAY_REPLY_RAW=5...)
 *   data[1] = status/flags
 *   data[2..] = payload réel
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
    uint8_t buf[MAX_PKT+3];
    buf[0] = len & 0xFF; buf[1] = len >> 8; buf[2] = cmd;
    if (len > 0 && data) memcpy(buf+3, data, len);
    int w = write(fd, buf, len+3);
    return (w == (int)(len+3)) ? 0 : -1;
}

/* ─── LANCEMENT PM3 ───────────────────────────────────────────────────────── */
static pid_t launch_pm3(const char *port, const char *relay_cmd) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) return pid;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s -p %s -c '%s'", PM3_BIN, port, relay_cmd);
    execl("/bin/sh", "sh", "-c", cmd, NULL);
    perror("execl"); _exit(1);
}

/* ─── CLEANUP ─────────────────────────────────────────────────────────────── */
static void cleanup(void) {
    INFO("Arrêt...");
    if (fd_mw >= 0) ptp_send(fd_mw, P_KILL, NULL, 0);
    if (fd_pw >= 0) ptp_send(fd_pw, P_KILL, NULL, 0);
    usleep(400000);
    if (pid_mole  > 0) { kill(pid_mole,  SIGTERM); waitpid(pid_mole,  NULL, WNOHANG); }
    if (pid_proxy > 0) { kill(pid_proxy, SIGTERM); waitpid(pid_proxy, NULL, WNOHANG); }
    if (fd_mr >= 0) close(fd_mr); if (fd_mw >= 0) close(fd_mw);
    if (fd_pr >= 0) close(fd_pr); if (fd_pw >= 0) close(fd_pw);
    del_all();
}
static void sighandler(int s) { (void)s; cleanup(); exit(0); }

/* ─── SETUP CLIENT ────────────────────────────────────────────────────────── */
/*
 * pipe.c OpenPipe() côté client :
 *   fdw = open("/tmp/proxmark_relay_write", O_WRONLY|O_NONBLOCK)  client ÉCRIT
 *   fdr = open("/tmp/proxmark_relay_read",  O_RDONLY|O_NONBLOCK)  client LIT
 *
 * Nos symlinks :
 *   proxmark_relay_read  → fifo_r  (server écrit, client lit)
 *   proxmark_relay_write → fifo_w  (client écrit, server lit)
 */
static bool setup_client(
    const char *fifo_r, const char *fifo_w,
    int *out_fd_r, int *out_fd_w,
    const char *port, const char *pm3_cmd,
    pid_t *out_pid, const char *name,
    const char *expect, const char *reply)
{
    /* Ouvrir côté lecture avant le fork (non-bloquant) */
    *out_fd_r = open(fifo_w, O_RDONLY | O_NONBLOCK);
    if (*out_fd_r < 0) { ERR("[%s] open %s: %s", name, fifo_w, strerror(errno)); return false; }
    INFO("[%s] fd_r=%d sur %s", name, *out_fd_r, fifo_w);

    set_symlinks(fifo_r, fifo_w);

    INFO("[%s] Lancement pm3 %s → '%s'", name, port, pm3_cmd);
    *out_pid = launch_pm3(port, pm3_cmd);


    *out_fd_w = open(fifo_r, O_WRONLY | O_NONBLOCK);
    if (*out_fd_w < 0) { ERR("[%s] open %s: %s", name, fifo_r, strerror(errno)); return false; }
    INFO("[%s] fd_w=%d sur %s", name, *out_fd_w, fifo_r);

    int fl;
    fl = fcntl(*out_fd_r, F_GETFL, 0); fcntl(*out_fd_r, F_SETFL, fl & ~O_NONBLOCK);
    fl = fcntl(*out_fd_w, F_GETFL, 0); fcntl(*out_fd_w, F_SETFL, fl & ~O_NONBLOCK);

    /* Handshake :
     * relay_mole.c  : SendTxtToPipe("--START MOLE--")  puis WaitPipeDate(500)
     * relay_proxy.c : SendTxtToPipe("--START RELAY--") puis cherche "--START RELAY--" en retour
     * → on lit le paquet P_INFO et on répond avec le même texte
     */
    INFO("[%s] Attente handshake '%s'...", name, expect);
    ptp_t pkt;
    for (int i = 0; i < 30; i++) {
        if (ptp_recv(*out_fd_r, &pkt, 1000) < 0) {
            WARN("[%s] pas de paquet (%d)", name, i+1);
            continue;
        }
        char buf[MAX_PKT+1] = {0};
        memcpy(buf, pkt.data, pkt.length < MAX_PKT ? pkt.length : MAX_PKT);
        INFO("[%s] reçu cmd=%u len=%u : '%s'", name, pkt.cmd, pkt.length, buf);

        if (pkt.cmd == P_PING) {
            ptp_send(*out_fd_w, P_PING, pkt.data, pkt.length);
            continue;
        }
        if (pkt.cmd == P_INFO && strstr(buf, expect)) {
            uint16_t rlen = strlen(reply);
            ptp_send(*out_fd_w, P_INFO, (const uint8_t *)reply, rlen);
            INFO("[%s] Handshake OK ✓", name);
            return true;
        }
    }
    ERR("[%s] Handshake échoué !", name);
    return false;
}

/* ─── RELAY LOOP ──────────────────────────────────────────────────────────── */
static void relay_loop(void) {
    printf("\n══════════════════════════════════════════\n");
    printf("  RELAY ACTIF  —  Ctrl+C pour arrêter\n");
    printf("══════════════════════════════════════════\n\n");

    ptp_t pkt;
    double t_cmd = 0.0;

    while (1) {
        fd_set rfds; FD_ZERO(&rfds);
        if (fd_mr >= 0) FD_SET(fd_mr, &rfds);
        if (fd_pr >= 0) FD_SET(fd_pr, &rfds);
        int mfd = fd_mr > fd_pr ? fd_mr : fd_pr;
        struct timeval tv = { 30, 0 };
        int r = select(mfd+1, &rfds, NULL, NULL, &tv);
        if (r == 0) { ERR("Timeout 30s"); break; }
        if (r <  0) { ERR("select: %s", strerror(errno)); break; }

        /* ── Messages venant du MOLE ── */
        if (fd_mr >= 0 && FD_ISSET(fd_mr, &rfds)) {
            if (ptp_recv(fd_mr, &pkt, 2000) < 0) { ERR("Lecture MOLE KO"); break; }

            if (pkt.cmd == P_PING) {
                ptp_send(fd_mw, P_PING, pkt.data, pkt.length);

            } else if (pkt.cmd == P_KILL) {
                INFO("MOLE KILL"); ptp_send(fd_pw, P_KILL, NULL, 0); goto end;

            } else if (pkt.cmd == P_INFO || pkt.cmd == P_LOG) {
                char buf[MAX_PKT+1] = {0};
                memcpy(buf, pkt.data, pkt.length < MAX_PKT ? pkt.length : MAX_PKT);
                printf("  [MOLE] %s\n", buf); fflush(stdout);

            } else if (pkt.cmd == P_RELAY_MOLE_TRACE) {
                /* Trace mole → forward au proxy */
                ptp_send(fd_pw, P_RELAY_MOLE_TRACE, pkt.data, pkt.length);

            } else if (pkt.cmd == P_RELAY) {
                uint8_t sub = pkt.data[0];

                if (sub == RELAY_TAG_INFO) {
                    log_hex("TAG→MOLE [TAG_INFO]", pkt.data+2, pkt.length > 2 ? pkt.length-2 : 0);
                    INFO("Tag détecté → forwarding au PROXY");
                    ptp_send(fd_pw, P_RELAY, pkt.data, pkt.length);

                } else if (sub == RELAY_REPLY_RAW) {
                    log_hex("TAG→MOLE [RSP]", pkt.data+2, pkt.length > 2 ? pkt.length-2 : 0);
                    ptp_send(fd_pw, P_RELAY, pkt.data, pkt.length);
                    printf("  ↳ Latence : %.1f ms\n\n", now_ms() - t_cmd);

                } else {
                    INFO("MOLE P_RELAY sub=%u len=%u (ignoré)", sub, pkt.length);
                }
            } else {
                INFO("MOLE cmd=%u len=%u (ignoré)", pkt.cmd, pkt.length);
            }
        }

        /* ── Messages venant du PROXY ── */
        if (fd_pr >= 0 && FD_ISSET(fd_pr, &rfds)) {
            if (ptp_recv(fd_pr, &pkt, 2000) < 0) { ERR("Lecture PROXY KO"); break; }

            if (pkt.cmd == P_PING) {
                ptp_send(fd_pw, P_PING, pkt.data, pkt.length);

            } else if (pkt.cmd == P_KILL) {
                INFO("PROXY KILL"); ptp_send(fd_mw, P_KILL, NULL, 0); goto end;

            } else if (pkt.cmd == P_INFO || pkt.cmd == P_LOG) {
                char buf[MAX_PKT+1] = {0};
                memcpy(buf, pkt.data, pkt.length < MAX_PKT ? pkt.length : MAX_PKT);
                printf("  [PROXY] %s\n", buf); fflush(stdout);

            } else if (pkt.cmd == P_RELAY) {
                uint8_t sub = pkt.data[0];

                if (sub == RELAY_RAW) {
                    apdu_count++;
                    t_cmd = now_ms();
                    printf("── APDU #%d ────────────────────────────────\n", apdu_count);
                    log_hex("RDR→PROXY [CMD]", pkt.data+2, pkt.length > 2 ? pkt.length-2 : 0);
                    ptp_send(fd_mw, P_RELAY, pkt.data, pkt.length);

                } else if (sub == RELAY_PROXY_END) {
                    INFO("PROXY_END"); ptp_send(fd_mw, P_RELAY, pkt.data, pkt.length); goto end;

                } else {
                    INFO("PROXY P_RELAY sub=%u len=%u (ignoré)", sub, pkt.length);
                }
            } else {
                INFO("PROXY cmd=%u len=%u (ignoré)", pkt.cmd, pkt.length);
            }
        }
    }
end:
    printf("\n[RELAY] Terminé. %d APDUs relayés.\n", apdu_count);
}

/* ─── MAIN ────────────────────────────────────────────────────────────────── */
int main(void) {
    t0_ms = now_ms();
    signal(SIGINT,  sighandler); signal(SIGTERM, sighandler); signal(SIGPIPE, SIG_IGN);

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  PM3 Relay — ISO 14443-4A — 1 PC / 2 PM3 — burja8x         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    INFO("Création des FIFOs...");
    make_fifo(FIFO_MOLE_R); make_fifo(FIFO_MOLE_W);
    make_fifo(FIFO_PROXY_R); make_fifo(FIFO_PROXY_W);

    INFO("═══ DÉMARRAGE MOLE (%s) ═══", MOLE_PORT);
    if (!setup_client(FIFO_MOLE_R, FIFO_MOLE_W, &fd_mr, &fd_mw,
                      MOLE_PORT, "hf 14a relay_mole",
                      &pid_mole, "MOLE",
                      "--START MOLE--", "--START MOLE--")) {
        cleanup(); return 1;
    }

    INFO("═══ DÉMARRAGE PROXY (%s) ═══", PROXY_PORT);
    if (!setup_client(FIFO_PROXY_R, FIFO_PROXY_W, &fd_pr, &fd_pw,
                      PROXY_PORT, "hf 14a relay",
                      &pid_proxy, "PROXY",
                      "--START RELAY--", "--START RELAY--")) {
        cleanup(); return 1;
    }

    INFO("Prêt !");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  1. Approchez votre TAG du MOLE  (%s)             ║\n", MOLE_PORT);
    printf("║  2. Dès détection → approchez PROXY (%s) du READER║\n", PROXY_PORT);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    relay_loop();
    cleanup();
    return 0;
}