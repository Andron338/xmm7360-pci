/*
 * open_xdatachannel.c — bring up XMM7x60 modem data channel
 *
 * C port of open_xdatachannel.py.  Replaces all Python dependencies:
 *   pyroute2         → rtnetlink (xmm_netlink.c)
 *   dbus / xm_dbus   → libnm     (xmm_nm.c)
 *   rpc              → xmm_rpc.c + xmm_proto.c
 *   configargparse   → getopt_long + simple INI reader
 *
 * Usage:
 *   open_xdatachannel -a <apn> [options]
 *
 * Config file: /etc/xmm7360 or ../xmm7360.ini (relative to binary)
 * Format:  key = value  (one per line, # comments, blank lines ok)
 *   apn = internet
 *   metric = 1000
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#include "xmm_rpc.h"
#include "xmm_rpc_ids.h"
#include "xmm_netlink.h"
#include "xmm_nm.h"

/* ── Configuration ───────────────────────────────────────────────────────── */

typedef struct {
    char apn[256];
    int  no_default_route;
    int  metric;
    int  ip_fetch_timeout;
    int  no_resolv;
    int  use_nm;
    int  init_only;   /* --init-only: wake modem for ModemManager, then exit */
    int  disconnect;  /* --disconnect: clean RPC teardown, then exit */
    char device[256];
} cfg_t;

static void cfg_defaults(cfg_t *c) {
    c->apn[0]           = '\0';
    c->no_default_route = 0;
    c->metric           = 1000;
    c->ip_fetch_timeout = 1;
    c->no_resolv        = 0;
    c->use_nm           = 0;
    c->device[0]        = '\0';
    c->init_only        = 0;
    c->disconnect       = 0;
}

/* Trim leading/trailing whitespace in-place, returns pointer into s */
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) e--;
    e[1] = '\0';
    return s;
}

static void load_ini(cfg_t *c, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '\0' || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        if      (strcmp(key, "apn")             == 0) snprintf(c->apn, sizeof(c->apn), "%s", val);
        else if (strcmp(key, "metric")           == 0) c->metric           = atoi(val);
        else if (strcmp(key, "ip_fetch_timeout") == 0) c->ip_fetch_timeout = atoi(val);
        else if (strcmp(key, "nodefaultroute")   == 0) c->no_default_route = atoi(val);
        else if (strcmp(key, "noresolv")         == 0) c->no_resolv        = atoi(val);
        else if (strcmp(key, "dbus")             == 0) c->use_nm           = atoi(val);
    }
    fclose(f);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -a <apn> [options]\n"
        "\n"
        "Options:\n"
        "  -a, --apn <apn>              Network provider APN (required)\n"
        "  -n, --nodefaultroute         Do not install modem as default route\n"
        "  -m, --metric <n>             Route metric (default: 1000)\n"
        "  -t, --ip-fetch-timeout <n>   Retry interval for IP fetch (default: 1s)\n"
        "  -r, --noresolv               Do not write DNS to /etc/resolv.conf\n"
        "  -d, --dbus                   Activate connection via NetworkManager\n"
        "  -c, --conf <file>            Config file path\n"
        "  -i, --init-only              Init modem for ModemManager (no data channel)\n"
        "  -x, --disconnect             RPC teardown + interface down, then exit\n"
        "  -D, --device <path>          RPC device path\n"
        "  -h, --help                   Show this help\n"
        "\n"
        "Config files (loaded in order, CLI overrides):\n"
        "  /etc/xmm7360\n"
        "  <binary-dir>/../xmm7360.ini\n",
        prog);
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    cfg_t cfg;
    cfg_defaults(&cfg);

    /* Load default config files */
    load_ini(&cfg, "/etc/xmm7360");
    /* Resolve binary directory for ../xmm7360.ini */
    {
        char ini_path[512];
        char self[512] = {0};
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (n > 0) {
            char *slash = strrchr(self, '/');
            if (slash) {
                *slash = '\0';
                snprintf(ini_path, sizeof(ini_path), "%s/../xmm7360.ini", self);
                load_ini(&cfg, ini_path);
            }
        }
    }

    /* Parse CLI arguments */
    static const struct option longopts[] = {
        {"apn",              required_argument, NULL, 'a'},
        {"nodefaultroute",   no_argument,       NULL, 'n'},
        {"metric",           required_argument, NULL, 'm'},
        {"ip-fetch-timeout", required_argument, NULL, 't'},
        {"noresolv",         no_argument,       NULL, 'r'},
        {"dbus",             no_argument,       NULL, 'd'},
        {"conf",             required_argument, NULL, 'c'},
        {"device",           required_argument, NULL, 'D'},
        {"init-only",        no_argument,       NULL, 'i'},
        {"disconnect",       no_argument,       NULL, 'x'},
        {"help",             no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "a:nm:t:rdc:hD:ix", longopts, NULL)) != -1) {
        switch (opt) {
        case 'a': snprintf(cfg.apn, sizeof(cfg.apn), "%s", optarg); break;
        case 'n': cfg.no_default_route = 1; break;
        case 'm': cfg.metric           = atoi(optarg); break;
        case 't': cfg.ip_fetch_timeout = atoi(optarg); break;
        case 'r': cfg.no_resolv        = 1; break;
        case 'd': cfg.use_nm           = 1; break;
        case 'c': load_ini(&cfg, optarg); break;
        case 'D': snprintf(cfg.device, sizeof(cfg.device), "%s", optarg); break;
        case 'i': cfg.init_only = 1; break;
        case 'x': cfg.disconnect = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (cfg.apn[0] == '\0' && !cfg.init_only && !cfg.disconnect) {
        fprintf(stderr, "error: --apn is required (or use --init-only to just wake the modem)\n\n");
        usage(argv[0]);
        return 1;
    }

    /* ── Step 1: Open modem RPC interface ─────────────────────────────────── */
    /* Retry for up to 5 seconds — the RPC device may appear slightly after
     * ttyXMM1 which is what udev/systemd waits on. */
    xmm_rpc_t rpc;
    {
        int _opened = 0;
        for (int _i = 0; _i < 10; _i++) {
            if (xmm_rpc_open(&rpc, cfg.device[0] ? cfg.device : NULL) == 0) {
                _opened = 1;
                break;
            }
            if (_i == 0)
                fprintf(stderr, "RPC device not ready, retrying...\n");
            struct timespec _ts = {0, 500000000}; /* 500 ms */
            nanosleep(&_ts, NULL);
        }
        if (!_opened) {
            fprintf(stderr, "Hint: use --device to specify the RPC interface.\n"
                            "      Try: ls /dev/wwan* /dev/xmm* 2>/dev/null\n");
            return 1;
        }
    }

    /* ── Step 2: Modem init sequence ─────────────────────────────────────── */
    xmm_msg_t resp;
#define EXEC0(cmd) \
    do { \
        fprintf(stderr, "init: " #cmd "\n"); \
        if (xmm_rpc_execute(&rpc, XMM_CMD_##cmd, NULL, 0, false, &resp) < 0) \
            { xmm_rpc_close(&rpc); return 1; } \
        xmm_msg_free(&resp); \
    } while (0)

    EXEC0(UtaMsCbsInit);
    EXEC0(UtaMsNetOpen);
    EXEC0(UtaMsCallCsInit);
    EXEC0(UtaMsCallPsInitialize);
    EXEC0(UtaMsSsInit);
    EXEC0(UtaMsSimOpenReq);

    /* Enable signal strength reporting.
     * Body = asn_int4(1): value 1 = ENABLE (0 = disable — the wrong
     * default we had before). This arms UtaMsNetRadioSignalIndCb
     * unsolicited messages and enables AT+XCESQ responses. */
    {
        xmm_buf_t sig_body;
        xmm_buf_init(&sig_body);
        pack_u32(&sig_body, 1);   /* enable = 1 */
        if (xmm_rpc_execute(&rpc, XMM_CMD_UtaMsNetSetRadioSignalReporting,
                            sig_body.data, sig_body.len, false, &resp) == 0)
            xmm_msg_free(&resp);
        xmm_buf_free(&sig_body);
    }

    /* UtaMsNetSetRadioSignalReportingConfiguration (0x188):
     * pack(LLLLL): enable, rsrp_delta, rsrq_delta, rssi_delta, interval_sec
     * Drives how often the modem measures and what threshold triggers a report. */
    {
        xmm_buf_t cfg_body;
        xmm_buf_init(&cfg_body);
        pack_u32(&cfg_body, 1);    /* enable               */
        pack_u32(&cfg_body, 3);    /* RSRP delta  = 3 dB   */
        pack_u32(&cfg_body, 3);    /* RSRQ delta  = 3 dB   */
        pack_u32(&cfg_body, 3);    /* RSSI delta  = 3 dB   */
        pack_u32(&cfg_body, 5);    /* interval    = 5 sec  */
        if (xmm_rpc_execute(&rpc, XMM_CMD_UtaMsNetSetRadioSignalReportingConfiguration,
                            cfg_body.data, cfg_body.len, false, &resp) == 0)
            xmm_msg_free(&resp);
        xmm_buf_free(&cfg_body);
    }

    /* One-shot immediate reading so signal appears without waiting */
    EXEC0(UtaMsNetSingleShotRadioSignalReportingReq);
#undef EXEC0

    /* ── Step 3: FCC unlock + enable RF ─────────────────────────────────── */
    if (xmm_fcc_unlock(&rpc) < 0) {
        fprintf(stderr, "FCC unlock failed\n");
        xmm_rpc_close(&rpc);
        return 1;
    }
    if (xmm_mode_set(&rpc, 1) < 0) {
        fprintf(stderr, "mode_set failed\n");
        xmm_rpc_close(&rpc);
        return 1;
    }

    /* ── disconnect: clean RPC teardown, then exit ─────────────────────────── */
    if (cfg.disconnect) {
        /* Hard 5-second timeout: if the modem RPC channel is in a bad
         * state after MM's AT hangup, disconnect must not block forever. */
        signal(SIGALRM, SIG_DFL);
        alarm(5);
        xmm_rpc_disconnect(&rpc);
        alarm(0);
        xmm_if_teardown("wwan0");
        fprintf(stderr, "RPC disconnect complete.\n");
        xmm_rpc_close(&rpc);
        return 0;
    }

    /* ── init-only: wake modem for ModemManager, then exit ──────────────── */
    if (cfg.init_only) {
        fprintf(stderr,
            "Modem initialised (SIM open, RF on).\n"
            "ModemManager can now detect the SIM via the AT ports.\n"
            "Run: mmcli -m 0  to verify, then connect via NetworkManager.\n");
        xmm_rpc_close(&rpc);
        return 0;
    }

    /* ── Step 4: Attach to network ───────────────────────────────────────── */
    {
        xmm_buf_t body;
        xmm_buf_init(&body);
        pack_attach_apn_config(&body, cfg.apn);
        fprintf(stderr, "Configuring APN: %s\n", cfg.apn);
        if (xmm_rpc_execute(&rpc, XMM_CMD_UtaMsCallPsAttachApnConfigReq,
                            body.data, body.len, true, &resp) < 0) {
            xmm_buf_free(&body);
            xmm_rpc_close(&rpc);
            return 1;
        }
        xmm_buf_free(&body);
        xmm_msg_free(&resp);
    }

    {
        xmm_buf_t body;
        xmm_buf_init(&body);
        pack_net_attach(&body);
        fprintf(stderr, "Attaching to network...\n");
        if (xmm_rpc_execute(&rpc, XMM_CMD_UtaMsNetAttachReq,
                            body.data, body.len, true, &resp) < 0) {
            xmm_buf_free(&body);
            xmm_rpc_close(&rpc);
            return 1;
        }
        xmm_buf_free(&body);

        /* Check attach status: unpack 'nn', status is second value */
        xmm_reader_t r;
        xmm_reader_init(&r, resp.body, resp.body_len);
        uint32_t v0, status;
        int parse_ok = (unpack_u32(&r, &v0) == 0 && unpack_u32(&r, &status) == 0);
        xmm_msg_free(&resp);

        if (!parse_ok) {
            fprintf(stderr, "attach: failed to parse response\n");
            xmm_rpc_close(&rpc);
            return 1;
        }

        if (status == 0xFFFFFFFF) {
            fprintf(stderr, "Attach failed — waiting for attach_allowed signal...\n");
            while (!rpc.attach_allowed) {
                xmm_msg_t m;
                if (xmm_rpc_pump(&rpc, &m) < 0) { xmm_rpc_close(&rpc); return 1; }
                xmm_msg_free(&m);
            }

            /* Retry attach */
            xmm_buf_init(&body);
            pack_net_attach(&body);
            if (xmm_rpc_execute(&rpc, XMM_CMD_UtaMsNetAttachReq,
                                body.data, body.len, true, &resp) < 0) {
                xmm_buf_free(&body);
                xmm_rpc_close(&rpc);
                return 1;
            }
            xmm_buf_free(&body);

            xmm_reader_init(&r, resp.body, resp.body_len);
            parse_ok = (unpack_u32(&r, &v0) == 0 && unpack_u32(&r, &status) == 0);
            xmm_msg_free(&resp);

            if (!parse_ok || status == 0xFFFFFFFF) {
                fprintf(stderr, "Attach failed again — giving up\n");
                xmm_rpc_close(&rpc);
                return 1;
            }
        }
        fprintf(stderr, "Network attach OK (status=0x%x)\n", status);
    }

    /* ── Step 5: Open data channel (creates wwan0) ───────────────────────── */
    fprintf(stderr, "Opening data channel...\n");

    xmm_msg_t pscr_resp, dcr_resp;
    {
        xmm_buf_t body;
        xmm_buf_init(&body);
        pack_ps_connect(&body);
        if (xmm_rpc_execute(&rpc, XMM_CMD_UtaMsCallPsConnectReq,
                            body.data, body.len, true, &pscr_resp) < 0) {
            xmm_buf_free(&body);
            xmm_rpc_close(&rpc);
            return 1;
        }
        xmm_buf_free(&body);
    }
    {
        xmm_buf_t body;
        xmm_buf_init(&body);
        pack_connect_datachannel(&body, NULL);
        if (xmm_rpc_execute(&rpc, XMM_CMD_UtaRPCPsConnectToDatachannelReq,
                            body.data, body.len, false, &dcr_resp) < 0) {
            xmm_buf_free(&body);
            xmm_msg_free(&pscr_resp);
            xmm_rpc_close(&rpc);
            return 1;
        }
        xmm_buf_free(&body);
    }

    /*
     * Build UtaRPCPSConnectSetupReq body:
     *   pscr_body[:-6] + dcr_body + \x02\x04\x00\x00\x00\x00
     * The last 6 bytes of pscr_body are trimmed (trailing padding).
     */
    {
        size_t pscr_trim = pscr_resp.body_len > 6 ? pscr_resp.body_len - 6 : 0;
        static const uint8_t TAIL[6] = {0x02, 0x04, 0x00, 0x00, 0x00, 0x00};

        xmm_buf_t csr;
        xmm_buf_init(&csr);
        xmm_buf_append(&csr, pscr_resp.body, pscr_trim);
        xmm_buf_append(&csr, dcr_resp.body, dcr_resp.body_len);
        xmm_buf_append(&csr, TAIL, sizeof(TAIL));

        xmm_msg_free(&pscr_resp);
        xmm_msg_free(&dcr_resp);

        if (xmm_rpc_execute(&rpc, XMM_CMD_UtaRPCPSConnectSetupReq,
                            csr.data, csr.len, false, &resp) < 0) {
            xmm_buf_free(&csr);
            xmm_rpc_close(&rpc);
            return 1;
        }
        xmm_buf_free(&csr);
        xmm_msg_free(&resp);
    }
    fprintf(stderr, "Data channel open — wwan0 should now exist\n");

    /* ── Step 6: Fetch IP (retry until available) ────────────────────────── */
    char ip_str[16]   = "";
    char dns_v4[4][16];
    char dns_v6[4][46];
    int  ndns_v4 = 0, ndns_v6 = 0;

    while (1) {
        if (xmm_get_ip(&rpc, ip_str, dns_v4, &ndns_v4, dns_v6, &ndns_v6) == 0)
            break;
        fprintf(stderr, "IP not available yet, retrying in %ds...\n",
                cfg.ip_fetch_timeout);
        sleep((unsigned)cfg.ip_fetch_timeout);
    }

    fprintf(stderr, "IP address: %s\n", ip_str);
    for (int i = 0; i < ndns_v4; i++) fprintf(stderr, "DNS (v4): %s\n", dns_v4[i]);
    for (int i = 0; i < ndns_v6; i++) fprintf(stderr, "DNS (v6): %s\n", dns_v6[i]);

    /* ── Step 7: Configure wwan0 ─────────────────────────────────────────── */
    if (xmm_if_configure("wwan0", ip_str,
                         cfg.metric, !cfg.no_default_route) < 0) {
        fprintf(stderr, "Interface configuration failed\n");
        xmm_rpc_close(&rpc);
        return 1;
    }
    fprintf(stderr, "wwan0 configured\n");

    /* ── Step 8: DNS to /etc/resolv.conf ─────────────────────────────────── */
    if (!cfg.no_resolv && (ndns_v4 || ndns_v6)) {
        FILE *f = fopen("/etc/resolv.conf", "a");
        if (f) {
            fprintf(f, "\n# Added by xmm7360\n");
            for (int i = 0; i < ndns_v4; i++) fprintf(f, "nameserver %s\n", dns_v4[i]);
            for (int i = 0; i < ndns_v6; i++) fprintf(f, "nameserver %s\n", dns_v6[i]);
            fclose(f);
            fprintf(stderr, "DNS entries written to /etc/resolv.conf\n");
        } else {
            perror("open /etc/resolv.conf");
        }
    }

    /* ── Step 9: NetworkManager (optional) ───────────────────────────────── */
    if (cfg.use_nm) {
        fprintf(stderr, "Configuring NetworkManager...\n");
        if (xmm_nm_setup(ip_str, (const char (*)[16])dns_v4, ndns_v4, cfg.metric) < 0) {
            fprintf(stderr, "NetworkManager setup failed\n");
            xmm_rpc_close(&rpc);
            return 1;
        }
        fprintf(stderr, "NetworkManager connection activated\n");
    }

    xmm_rpc_close(&rpc);
    return 0;
}
