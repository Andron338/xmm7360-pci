#define _GNU_SOURCE   /* O_CLOEXEC, O_SYNC */
#include "xmm_rpc.h"
#include "xmm_rpc_ids.h"
#include "xmm_unsol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   /* usleep */
#include <openssl/sha.h>

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static void rpc_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Default body sent when body==NULL: asn_int4(0) */
static const uint8_t DEFAULT_BODY[6] = {0x02, 0x04, 0x00, 0x00, 0x00, 0x00};

/* ── Message lifecycle ────────────────────────────────────────────────────── */

void xmm_msg_free(xmm_msg_t *m) {
    free(m->body);
    memset(m, 0, sizeof(*m));
}

/* ── Device open ──────────────────────────────────────────────────────────── */

int xmm_rpc_open(xmm_rpc_t *rpc, const char *device_path) {
    static const char *defaults[] = {
        "/dev/wwan0xmmrpc0",
        "/dev/xmm0/rpc",
        NULL
    };
    const char *paths_single[2] = { device_path, NULL };
    const char **paths = device_path ? paths_single : defaults;

    for (int i = 0; paths[i]; i++) {
        /* Match Python's os.open() flags exactly: O_RDWR | O_SYNC.
         * Avoid O_CLOEXEC — some driver open() handlers inspect
         * f_flags and unexpected bits can cause subtle failures
         * with the custom xmm7360.c module. */
        int fd = open(paths[i], O_RDWR | O_SYNC);
        if (fd >= 0) {
            rpc->fd = fd;
            rpc->attach_allowed = false;
            rpc_log("xmm_rpc: opened %s", paths[i]);
            /* Give the custom xmm7360.c module a moment to finish
             * xmm7360_qp_start() DMA ring initialisation before the
             * first write.  iosm does not need this. */
            usleep(50000);   /* 50 ms */
            return 0;
        }
        rpc_log("xmm_rpc: cannot open %s: %s", paths[i], strerror(errno));
    }
    rpc_log("xmm_rpc: no usable RPC device found");
    return -1;
}

void xmm_rpc_close(xmm_rpc_t *rpc) {
    if (rpc->fd >= 0) close(rpc->fd);
    rpc->fd = -1;
}

/* ── Unsolicited handler (side-effects on rpc state) ─────────────────────── */

static void handle_unsolicited(xmm_rpc_t *rpc, const xmm_msg_t *m) {
    const char *name = xmm_unsol_name(m->code);
    rpc_log("  unsolicited: %s (0x%03x)",
         name ? name : "unknown", m->code);

    /* UtaMsNetRadioSignalIndCb (0x05a) — log signal so we can confirm
     * the modem is measuring. 3GPP indices: RSRP = val-141 dBm,
     * RSRQ = val/2-20 dB, RSSI = val-111 dBm */
    if (m->code == 0x05a) {
        xmm_reader_t sr;
        xmm_reader_init(&sr, m->body, m->body_len);
        uint32_t v[6] = {0};
        for (int i = 0; i < 6; i++) unpack_u32(&sr, &v[i]);
        rpc_log("  signal: rsrp=%ddBm rsrq=%ddB rssi=%ddBm",
                (int)v[0] - 141, (int)(v[1] / 2) - 20, (int)v[2] - 111);
    }

    /* UtaMsNetIsAttachAllowedIndCb — content[2] indicates whether attach ok */
    if (m->code == XMM_UNSOL_UtaMsNetIsAttachAllowedIndCb) {
        xmm_reader_t r;
        xmm_reader_init(&r, m->body, m->body_len);
        uint32_t v0, v1, v2;
        if (unpack_u32(&r, &v0) == 0 &&
            unpack_u32(&r, &v1) == 0 &&
            unpack_u32(&r, &v2) == 0) {
            rpc->attach_allowed = (v2 != 0);
            rpc_log("  attach_allowed → %s", rpc->attach_allowed ? "yes" : "no");
        }
    }
}

/* ── Pump — read one raw message ──────────────────────────────────────────── */

int xmm_rpc_pump(xmm_rpc_t *rpc, xmm_msg_t *m) {
    static uint8_t buf[XMM_MAX_MSG];

    /* Retry on EINTR: pkexec / fingerprint auth signals can interrupt read() */
    ssize_t n;
    do {
        n = read(rpc->fd, buf, sizeof(buf));
    } while (n < 0 && errno == EINTR);

    if (n < 0) { rpc_log("xmm_rpc: read error: %s", strerror(errno)); return -1; }
    if (n < 20) { rpc_log("xmm_rpc: message too short (%zd bytes)", n); return -1; }

    /*
     * Wire layout:
     *   [0..3]   LE uint32 total_length
     *   [4..9]   asn_int4(total_length)
     *   [10..15] asn_int4(code)
     *   [16..19] BE uint32 txid
     *   [20..]   body
     *
     * The xmm7360 cdev returns a full DMA page (e.g. 16384 B) per read()
     * regardless of actual message size; iosm returns the exact count.
     * Clamp n via the LE total_length header field to discard DMA padding
     * and leftover ring-buffer bytes that would corrupt body parsing.
     */
    uint32_t total_len_hdr = (uint32_t)buf[0]         |
                             ((uint32_t)buf[1] <<  8)  |
                             ((uint32_t)buf[2] << 16)  |
                             ((uint32_t)buf[3] << 24);
    size_t msg_size = 4u + (size_t)total_len_hdr;

    if (msg_size < 20) {
        rpc_log("xmm_rpc: header claims implausibly small message (%zu B)"
                " -- framing error", msg_size);
        return -1;
    }
    if (msg_size > (size_t)n) {
        rpc_log("xmm_rpc: header claims %zu B but only read %zd B"
                " -- partial read or framing error", msg_size, n);
        return -1;
    }
    n = (ssize_t)msg_size;   /* discard DMA-page padding */

    uint32_t txid = ((uint32_t)buf[16] << 24) | ((uint32_t)buf[17] << 16) |
                    ((uint32_t)buf[18] << 8)  |  (uint32_t)buf[19];

    uint32_t code = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                    ((uint32_t)buf[14] << 8)  |  (uint32_t)buf[15];

    size_t body_offset = 20;
    size_t body_len    = (size_t)n - body_offset;

    xmm_msg_type_t type;
    if (txid == 0x11000100) {
        type = XMM_MSG_RESPONSE;
    } else if ((txid & 0xFFFFFF00) == 0x11000100) {
        if (code >= 2000) {
            type = XMM_MSG_ASYNC_ACK;
        } else {
            type = XMM_MSG_RESPONSE;
            /*
             * Async response: body starts with asn_int4(tid) (6 bytes).
             * Trim it so callers see the same layout as sync responses.
             */
            if (body_len >= 6) {
                body_offset += 6;
                body_len    -= 6;
            }
        }
    } else {
        type = XMM_MSG_UNSOLICITED;
    }

    rpc_log("  pump: type=%s code=0x%03x txid=0x%08x body=%zu B",
         type == XMM_MSG_RESPONSE   ? "response"   :
         type == XMM_MSG_ASYNC_ACK  ? "async_ack"  : "unsolicited",
         code, txid, body_len);

    uint8_t *body_copy = malloc(body_len + 1);   /* +1 so body is never NULL */
    if (!body_copy) return -1;
    if (body_len) memcpy(body_copy, buf + body_offset, body_len);

    m->type     = type;
    m->code     = code;
    m->txid     = txid;
    m->body     = body_copy;
    m->body_len = body_len;

    if (type == XMM_MSG_UNSOLICITED)
        handle_unsolicited(rpc, m);

    return 0;
}

/* ── Execute — send command, collect response ─────────────────────────────── */

int xmm_rpc_execute(xmm_rpc_t     *rpc,
                    uint32_t       cmd,
                    const uint8_t *body,
                    size_t         body_len,
                    bool           is_async,
                    xmm_msg_t     *out)
{
    if (!body) { body = DEFAULT_BODY; body_len = sizeof(DEFAULT_BODY); }

    /*
     * Header:  [4B LE total_len] [asn4(total_len)] [asn4(cmd)] [4B BE tid_word]
     *          [asn4(tid)]  ← only when is_async
     */
    uint32_t tid      = is_async ? 0x11000101u : 0u;
    uint32_t tid_word = 0x11000100u | tid;
    uint32_t total_len = (uint32_t)(body_len + 16 + (is_async ? 6 : 0));

    uint8_t hdr[26];   /* max header size */
    size_t  hdr_len = 0;

    /* 4B LE total_len */
    hdr[hdr_len++] = (uint8_t)(total_len);
    hdr[hdr_len++] = (uint8_t)(total_len >> 8);
    hdr[hdr_len++] = (uint8_t)(total_len >> 16);
    hdr[hdr_len++] = (uint8_t)(total_len >> 24);

    /* asn4(total_len) */
    hdr[hdr_len++] = 0x02; hdr[hdr_len++] = 0x04;
    hdr[hdr_len++] = (uint8_t)(total_len >> 24);
    hdr[hdr_len++] = (uint8_t)(total_len >> 16);
    hdr[hdr_len++] = (uint8_t)(total_len >> 8);
    hdr[hdr_len++] = (uint8_t)(total_len);

    /* asn4(cmd) */
    hdr[hdr_len++] = 0x02; hdr[hdr_len++] = 0x04;
    hdr[hdr_len++] = (uint8_t)(cmd >> 24);
    hdr[hdr_len++] = (uint8_t)(cmd >> 16);
    hdr[hdr_len++] = (uint8_t)(cmd >> 8);
    hdr[hdr_len++] = (uint8_t)(cmd);

    /* 4B BE tid_word */
    hdr[hdr_len++] = (uint8_t)(tid_word >> 24);
    hdr[hdr_len++] = (uint8_t)(tid_word >> 16);
    hdr[hdr_len++] = (uint8_t)(tid_word >> 8);
    hdr[hdr_len++] = (uint8_t)(tid_word);

    if (is_async) {
        /* asn4(tid) */
        hdr[hdr_len++] = 0x02; hdr[hdr_len++] = 0x04;
        hdr[hdr_len++] = (uint8_t)(tid >> 24);
        hdr[hdr_len++] = (uint8_t)(tid >> 16);
        hdr[hdr_len++] = (uint8_t)(tid >> 8);
        hdr[hdr_len++] = (uint8_t)(tid);
    }

    /* Assemble in one contiguous buffer so we can do a single write() */
    size_t   pkt_len = hdr_len + body_len;
    uint8_t *pkt     = malloc(pkt_len);
    if (!pkt) return -1;
    memcpy(pkt, hdr, hdr_len);
    memcpy(pkt + hdr_len, body, body_len);

    rpc_log("xmm_rpc: execute cmd=0x%03x body=%zu B async=%d", cmd, body_len, is_async);

    /* xmm7360.c module returns ENOSPC without blocking when the DMA
     * ring is full (unlike iosm which blocks). Retry a few times. */
    ssize_t w = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        w = write(rpc->fd, pkt, pkt_len);
        if (w >= 0) break;
        if (errno != ENOSPC) break;
        rpc_log("xmm_rpc: ring full (ENOSPC), retrying %d/10...", attempt + 1);
        usleep(10000);   /* 10 ms */
    }
    free(pkt);
    if (w < 0 || (size_t)w != pkt_len) {
        rpc_log("xmm_rpc: write error after retries: %s", strerror(errno));
        return -1;
    }

    /* Pump until we get a RESPONSE (async_acks and unsolicited are handled
       inside pump and discarded from the caller's perspective). */
    while (1) {
        xmm_msg_t m;
        if (xmm_rpc_pump(rpc, &m) < 0) return -1;
        if (m.type == XMM_MSG_RESPONSE) { *out = m; return 0; }
        xmm_msg_free(&m);
    }
}

/* ── FCC unlock ───────────────────────────────────────────────────────────── */

int xmm_rpc_disconnect(xmm_rpc_t *rpc)
{
    xmm_msg_t resp;
    xmm_buf_t body;
    int ret;

    rpc_log("disconnect: releasing RPC data channel");

    /*
     * Fire-and-forget: send disconnect commands without waiting for
     * responses. After MM's AT hangup the modem RPC state may already
     * be partially torn down, so pumping for a confirmation response
     * blocks indefinitely. We just send the commands and move on.
     *
     * Step 1: UtaRPCPSConnectReleaseReq (0x07F) — release data channel
     */
    ret = xmm_rpc_execute(rpc, XMM_CMD_UtaRPCPSConnectReleaseReq,
                          NULL, 0, false, &resp);
    if (ret == 0)
        xmm_msg_free(&resp);

    /*
     * Step 2: UtaMsCallPsDeactivateReq (0x04E) — deactivate PDP context
     * cause = 0: normal local deactivation
     */
    xmm_buf_init(&body);
    pack_u32(&body, 0);
    rpc_log("disconnect: deactivating PDP context");
    ret = xmm_rpc_execute(rpc, XMM_CMD_UtaMsCallPsDeactivateReq,
                          body.data, body.len, false, &resp);
    xmm_buf_free(&body);
    if (ret == 0)
        xmm_msg_free(&resp);

    rpc_log("disconnect: done");
    return 0;
}

int xmm_fcc_unlock(xmm_rpc_t *rpc) {
    xmm_msg_t resp;

    /* Query lock state */
    if (xmm_rpc_execute(rpc, XMM_CMD_CsiFccLockQueryReq, NULL, 0, true, &resp) < 0)
        return -1;

    xmm_reader_t r;
    xmm_reader_init(&r, resp.body, resp.body_len);
    uint32_t dummy, fcc_state, fcc_mode;
    if (unpack_u32(&r, &dummy)     < 0 ||
        unpack_u32(&r, &fcc_state) < 0 ||
        unpack_u32(&r, &fcc_mode)  < 0) {
        xmm_msg_free(&resp);
        rpc_log("fcc_unlock: failed to parse query response");
        return -1;
    }
    xmm_msg_free(&resp);
    rpc_log("FCC lock: state=%u mode=%u", fcc_state, fcc_mode);

    if (!fcc_mode || fcc_state)  /* not locked, or already unlocked */
        return 0;

    /* Generate challenge */
    if (xmm_rpc_execute(rpc, XMM_CMD_CsiFccLockGenChallengeReq, NULL, 0, true, &resp) < 0)
        return -1;

    xmm_reader_init(&r, resp.body, resp.body_len);
    uint32_t fcc_chal;
    if (unpack_u32(&r, &dummy) < 0 || unpack_u32(&r, &fcc_chal) < 0) {
        xmm_msg_free(&resp);
        rpc_log("fcc_unlock: failed to parse challenge response");
        return -1;
    }
    xmm_msg_free(&resp);

    /* SHA-256(chal_LE || key) → take first 4 bytes as LE uint32 */
    static const uint8_t key[4] = {0x3d, 0xf8, 0xc7, 0x19};
    uint8_t input[8];
    input[0] = (uint8_t)(fcc_chal);
    input[1] = (uint8_t)(fcc_chal >> 8);
    input[2] = (uint8_t)(fcc_chal >> 16);
    input[3] = (uint8_t)(fcc_chal >> 24);
    memcpy(input + 4, key, 4);

    uint8_t digest[32];
    SHA256(input, 8, digest);
    uint32_t unlock_val = (uint32_t)digest[0] |
                          ((uint32_t)digest[1] << 8)  |
                          ((uint32_t)digest[2] << 16) |
                          ((uint32_t)digest[3] << 24);

    /* Send unlock response */
    xmm_buf_t body;
    xmm_buf_init(&body);
    pack_fcc_ver_challenge(&body, unlock_val);

    int rc = xmm_rpc_execute(rpc, XMM_CMD_CsiFccLockVerChallengeReq,
                             body.data, body.len, true, &resp);
    xmm_buf_free(&body);
    if (rc < 0) return -1;

    xmm_reader_init(&r, resp.body, resp.body_len);
    uint32_t result;
    rc = unpack_u32(&r, &result);
    xmm_msg_free(&resp);
    if (rc < 0 || result != 1) {
        rpc_log("fcc_unlock: unlock failed (result=%u)", result);
        return -1;
    }
    rpc_log("FCC unlock: success");
    return 0;
}

/* ── Mode set ─────────────────────────────────────────────────────────────── */

int xmm_mode_set(xmm_rpc_t *rpc, uint32_t mode) {
    xmm_buf_t body;
    xmm_buf_init(&body);
    pack_mode_set(&body, 15 /* mode_tid */, mode);

    xmm_msg_t resp;
    int rc = xmm_rpc_execute(rpc, XMM_CMD_UtaModeSetReq,
                             body.data, body.len, false, &resp);
    xmm_buf_free(&body);
    if (rc < 0) return -1;

    xmm_reader_t r;
    xmm_reader_init(&r, resp.body, resp.body_len);
    uint32_t status;
    rc = unpack_u32(&r, &status);
    xmm_msg_free(&resp);
    if (rc < 0 || status != 0) {
        rpc_log("mode_set: request failed (status=0x%x)", status);
        return -1;
    }

    /* Wait for UtaModeSetRspCb (0x12d) confirming the mode */
    while (1) {
        xmm_msg_t m;
        if (xmm_rpc_pump(rpc, &m) < 0) return -1;
        if (m.type == XMM_MSG_UNSOLICITED && m.code == XMM_UNSOL_UtaModeSetRspCb) {
            xmm_reader_init(&r, m.body, m.body_len);
            uint32_t got_mode;
            int ok = (unpack_u32(&r, &got_mode) == 0);
            xmm_msg_free(&m);
            if (!ok || got_mode != mode) {
                rpc_log("mode_set: wrong mode in callback (FCC lock active?)");
                return -1;
            }
            rpc_log("mode_set: mode %u confirmed", mode);
            return 0;
        }
        xmm_msg_free(&m);
    }
}

/* ── IP / DNS query ───────────────────────────────────────────────────────── */

/* Convert 4 raw bytes (big-endian) to dotted-quad string */
static void bytes_to_ipv4(const uint8_t *b, char out[16]) {
    snprintf(out, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* Convert 16 raw bytes (big-endian) to colon-hex IPv6 string */
static void bytes_to_ipv6(const uint8_t *b, char out[46]) {
    snprintf(out, 46,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],
        b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
}

int xmm_get_ip(xmm_rpc_t *rpc,
               char  ip_out[16],
               char  dns_v4[][16], int *ndns_v4,
               char  dns_v6[][46], int *ndns_v6)
{
    *ndns_v4 = *ndns_v6 = 0;

    /* ── IP address ── */
    xmm_buf_t body;
    xmm_buf_init(&body);
    pack_get_neg_ip_addr(&body);

    xmm_msg_t resp;
    int rc = xmm_rpc_execute(rpc, XMM_CMD_UtaMsCallPsGetNegIpAddrReq,
                             body.data, body.len, true, &resp);
    xmm_buf_free(&body);
    if (rc < 0) return -1;

    /*
     * unpack_UtaMsCallPsGetNegIpAddrReq: 'nsnnnn'
     * Skip first n, then read string (addresses), skip 4 more n's.
     * addresses: bytes [0..3]=IP1, [4..7]=IP2, [8..11]=IP3
     * Use last non-zero IP (handles IPv6-only networks returning partial addr).
     */
    xmm_reader_t r;
    xmm_reader_init(&r, resp.body, resp.body_len);

    uint32_t dummy;
    const uint8_t *addrs; size_t addrs_len;
    if (unpack_u32(&r, &dummy) < 0 || unpack_str(&r, &addrs, &addrs_len) < 0) {
        xmm_msg_free(&resp);
        rpc_log("get_ip: failed to parse IP response");
        return -1;
    }

    char found_ip[16] = "";
    /* Check the three candidate IPv4 addresses (each 4 bytes) in reverse */
    for (int i = 2; i >= 0 && !found_ip[0]; i--) {
        if ((size_t)(i * 4 + 4) <= addrs_len) {
            const uint8_t *b = addrs + i * 4;
            if (b[0] || b[1] || b[2] || b[3]) {
                bytes_to_ipv4(b, found_ip);
            }
        }
    }
    xmm_msg_free(&resp);

    if (!found_ip[0]) return -1;   /* no address yet */
    memcpy(ip_out, found_ip, 16);

    /* ── DNS ── */
    xmm_buf_init(&body);
    pack_get_neg_dns(&body);

    rc = xmm_rpc_execute(rpc, XMM_CMD_UtaMsCallPsGetNegotiatedDnsReq,
                         body.data, body.len, true, &resp);
    xmm_buf_free(&body);
    if (rc < 0) return 0;   /* IP found, DNS optional */

    /*
     * unpack_UtaMsCallPsGetNegotiatedDnsReq: 'n' + 16 * ('sn') + 'nsnnnn'
     * For each (address, type) pair:
     *   type==1 → IPv4 (first 4 bytes)
     *   type==2 → IPv6 (first 16 bytes)
     */
    xmm_reader_init(&r, resp.body, resp.body_len);
    if (unpack_u32(&r, &dummy) < 0) { xmm_msg_free(&resp); return 0; }

    for (int i = 0; i < 16; i++) {
        const uint8_t *addr; size_t alen;
        uint32_t typ;
        if (unpack_str(&r, &addr, &alen) < 0) break;
        if (unpack_u32(&r, &typ)         < 0) break;
        if (typ == 1 && alen >= 4 && *ndns_v4 < 4)
            bytes_to_ipv4(addr, dns_v4[(*ndns_v4)++]);
        else if (typ == 2 && alen >= 16 && *ndns_v6 < 4)
            bytes_to_ipv6(addr, dns_v6[(*ndns_v6)++]);
    }
    xmm_msg_free(&resp);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Pack functions
 * ═══════════════════════════════════════════════════════════════════════════ */

int pack_net_attach(xmm_buf_t *b) {
    /* pack('BLLLLHHLL', 0,0,0,0,0, 0xffff,0xffff, 0,0) */
    pack_u8(b,  0);
    pack_u32(b, 0); pack_u32(b, 0); pack_u32(b, 0); pack_u32(b, 0);
    pack_u16(b, 0xffff); pack_u16(b, 0xffff);
    pack_u32(b, 0); pack_u32(b, 0);
    return 0;
}

int pack_get_neg_ip_addr(xmm_buf_t *b) {
    /* pack('BLL', 0, 0, 0) */
    pack_u8(b, 0); pack_u32(b, 0); pack_u32(b, 0);
    return 0;
}

int pack_get_neg_dns(xmm_buf_t *b) {
    /* pack('BLL', 0, 0, 0) */
    pack_u8(b, 0); pack_u32(b, 0); pack_u32(b, 0);
    return 0;
}

int pack_ps_connect(xmm_buf_t *b) {
    /* pack('BLLL', 0, 6, 0, 0) */
    pack_u8(b, 0); pack_u32(b, 6); pack_u32(b, 0); pack_u32(b, 0);
    return 0;
}

int pack_connect_datachannel(xmm_buf_t *b, const char *path) {
    if (!path) path = "/sioscc/PCIE/IOSM/IPS/0";
    /* pack('s24', path_with_nul) — max_len=24 */
    size_t plen = strlen(path) + 1;   /* include NUL terminator */
    if (plen > 24) plen = 24;
    pack_str(b, (const uint8_t *)path, plen, 24);
    return 0;
}

int pack_mode_set(xmm_buf_t *b, uint32_t mode_tid, uint32_t mode) {
    pack_u32(b, 0); pack_u32(b, mode_tid); pack_u32(b, mode);
    return 0;
}

int pack_fcc_ver_challenge(xmm_buf_t *b, uint32_t response) {
    pack_u32(b, response);
    return 0;
}

/* ── AttachApnConfigReq — the big one ──────────────────────────────────────
 *
 * The message carries 4 near-identical "bearer config blocks".
 * Blocks 1–2 are zero-filled (unused bearers).
 * Blocks 3–4 carry the active APN config.
 *
 * Block layout (Python types string):
 *   Block 1:  B s260 L s66 s65 s250 B s252 H L×21 s20 L s104
 *   Block 2:    s260 L s66 s65 s250 B s252 H L×21 s20 L s104  (no leading B)
 *   Block 3:    s260 L s66 s65 s250 B s252 H L×21 s20 L s104
 *   Block 4:    s260 L s66 s65 s250 B s252 H L×21 s20 L s103 B L
 *
 * Verified byte-for-byte against test_rpc.py test vectors.
 */

/* L×21 values for the active bearer config blocks (3 & 4) */
static const uint32_t L21_ZERO[21]   = {0};
static const uint32_t L21_ACTIVE[21] = {
    0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0x404, 1, 0, 1, 0, 0
};

/*
 * Pack everything from H through the end of one block's tail.
 * str_max: 104 for blocks 1-3, 103 for block 4.
 * apn_str / apn_len: the APN payload (101 bytes zero-padded bytearray).
 */
static void pack_apn_tail(xmm_buf_t *b,
                          const uint32_t l21[21],
                          uint32_t l_after_s20,
                          const uint8_t *apn_str, /* always 101 bytes */
                          size_t str_max)
{
    pack_u16(b, 0);                             /* H = 0 */
    for (int i = 0; i < 21; i++) pack_u32(b, l21[i]);
    pack_str_zeros(b, 20, 20);                 /* s20 */
    pack_u32(b, l_after_s20);                  /* L */
    pack_str(b, apn_str, 101, str_max);        /* s104 or s103 */
}

int pack_attach_apn_config(xmm_buf_t *b, const char *apn) {
    /* Build 101-byte APN buffer (matches Python's bytearray(101)) */
    uint8_t apn_buf[101];
    memset(apn_buf, 0, sizeof(apn_buf));
    size_t apn_len = strlen(apn);
    if (apn_len > 100) apn_len = 100;
    memcpy(apn_buf, apn, apn_len);

    /* ── Block 1 (leading B=0, all zeros) ── */
    pack_u8(b, 0);                              /* B */
    pack_str_zeros(b, 257, 260);                /* s260 */
    pack_u32(b, 0);                             /* L */
    pack_str_zeros(b, 65, 66);                  /* s66 */
    pack_str_zeros(b, 65, 65);                  /* s65 */
    pack_str_zeros(b, 250, 250);                /* s250 */
    pack_u8(b, 0);                              /* B */
    pack_str_zeros(b, 250, 252);                /* s252 */
    pack_apn_tail(b, L21_ZERO, 0, apn_buf, 104);

    /* ── Block 2 (no leading B, all zeros) ── */
    pack_str_zeros(b, 257, 260);
    pack_u32(b, 0);
    pack_str_zeros(b, 65, 66);
    pack_str_zeros(b, 65, 65);
    pack_str_zeros(b, 250, 250);
    pack_u8(b, 0);
    pack_str_zeros(b, 250, 252);
    pack_apn_tail(b, L21_ZERO, 0, apn_buf, 104);

    /* ── Block 3 (active config, s104) ── */
    pack_str_zeros(b, 257, 260);
    pack_u32(b, 0);
    pack_str_zeros(b, 65, 66);
    pack_str_zeros(b, 65, 65);
    pack_str_zeros(b, 250, 250);
    pack_u8(b, 0);
    pack_str_zeros(b, 250, 252);
    pack_apn_tail(b, L21_ACTIVE, 3, apn_buf, 104);

    /* ── Block 4 (active config, s103, then B=3 L=0) ── */
    pack_str_zeros(b, 257, 260);
    pack_u32(b, 0);
    pack_str_zeros(b, 65, 66);
    pack_str_zeros(b, 65, 65);
    pack_str_zeros(b, 250, 250);
    pack_u8(b, 0);
    pack_str_zeros(b, 250, 252);
    pack_u16(b, 0);                             /* H */
    for (int i = 0; i < 21; i++) pack_u32(b, L21_ACTIVE[i]);
    pack_str_zeros(b, 20, 20);
    pack_u32(b, 3);
    pack_str(b, apn_buf, 101, 103);            /* s103 */
    pack_u8(b, 3);                              /* trailing B */
    pack_u32(b, 0);                             /* trailing L */

    return 0;
}
