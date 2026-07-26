#include "store.h"
#include "config.h"
#include "db.h"
#include "json.h"
#include "log.h"
#include "tse_worm.h"
#include "tse_worker.h"
#include "util.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── TSE worker job types ──────────────────────────────────────────────── */

typedef struct {
    const char *client_id;
    int         rc;
} reg_client_job_t;

static void reg_client_fn(void *arg) {
    reg_client_job_t *j = arg;
    j->rc = tse_worm_register_client(j->client_id);
}

typedef struct {
    const char      *client_id;
    const char      *process_type;
    const char      *process_data;
    tse_transaction_t *out;
    char             err[256];
    int              rc;
} start_tx_job_t;

static void start_tx_fn(void *arg) {
    start_tx_job_t *j = arg;
    j->rc = tse_worm_start_transaction(j->client_id, j->process_type, j->process_data,
                                        j->out, j->err, sizeof(j->err));
}

typedef struct {
    const char      *client_id;
    int64_t          transaction_number;
    const char      *process_type;
    const char      *process_data;
    tse_transaction_t *out;
    char            *err_code;
    size_t           err_code_len;
    char            *err_msg;
    size_t           err_msg_len;
    int              rc;
} finish_tx_job_t;

static void finish_tx_fn(void *arg) {
    finish_tx_job_t *j = arg;
    j->rc = tse_worm_finish_transaction(j->client_id, j->transaction_number,
                                         j->process_type, j->process_data,
                                         j->out, j->err_code, j->err_code_len,
                                         j->err_msg, j->err_msg_len);
}

typedef struct {
    tse_info_t *info;
} fill_info_job_t;

static void fill_info_fn(void *arg) {
    fill_info_job_t *j = arg;
    tse_worm_fill_info(j->info);
}

static char g_created_at[64];

void store_normalize_serial(const char *value, char *out, size_t outlen) {
    char tmp[256];
    strncpy(tmp, value ? value : "", sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    util_trim(tmp);
    if (strlen(tmp) >= 32 && util_is_hex_serial(tmp)) {
        strncpy(out, tmp, outlen - 1);
        out[outlen - 1] = '\0';
        util_uppercase(out);
        return;
    }
    strncpy(out, CLOUDTSE_DEFAULT_TSE_SERIAL, outlen - 1);
    out[outlen - 1] = '\0';
}

static void load_transaction_row(sqlite3_stmt *stmt, tse_transaction_t *tx) {
    memset(tx, 0, sizeof(*tx));
    tx->transaction_number = sqlite3_column_int64(stmt, 0);
    const char *client_id = (const char *)sqlite3_column_text(stmt, 1);
    const char *ext = (const char *)sqlite3_column_text(stmt, 2);
    const char *ptype = (const char *)sqlite3_column_text(stmt, 3);
    const char *pdata = (const char *)sqlite3_column_text(stmt, 4);
    const char *state = (const char *)sqlite3_column_text(stmt, 5);
    const char *tstart = (const char *)sqlite3_column_text(stmt, 6);
    const char *tend = (const char *)sqlite3_column_text(stmt, 7);
    tx->signature_counter = sqlite3_column_int64(stmt, 8);
    const char *sig = (const char *)sqlite3_column_text(stmt, 9);

    if (client_id) {
        strncpy(tx->client_id, client_id, sizeof(tx->client_id) - 1);
    }
    if (ext) {
        strncpy(tx->external_transaction_id, ext, sizeof(tx->external_transaction_id) - 1);
    }
    if (ptype) {
        strncpy(tx->process_type, ptype, sizeof(tx->process_type) - 1);
    }
    if (pdata) {
        strncpy(tx->process_data, pdata, sizeof(tx->process_data) - 1);
    }
    if (state) {
        strncpy(tx->state, state, sizeof(tx->state) - 1);
    }
    if (tstart) {
        strncpy(tx->time_start, tstart, sizeof(tx->time_start) - 1);
    }
    if (tend) {
        strncpy(tx->time_end, tend, sizeof(tx->time_end) - 1);
    }
    if (sig) {
        strncpy(tx->signature_value, sig, sizeof(tx->signature_value) - 1);
    }
    char serial_buf[128];
    db_get_setting("tse_serial", serial_buf, sizeof(serial_buf));
    store_normalize_serial(serial_buf, tx->serial_number, sizeof(tx->serial_number));
}

void store_init(void) {
    char buf[128];
    if (g_config.tse_mode == TSE_MODE_HARDWARE) {
        if (tse_worm_init() != 0) {
            log_warn("hardware TSE init failed — falling back to simulator");
        }
    }
    
    // Always sync the (potentially newly derived) tse_serial to the DB.
    store_normalize_serial(g_config.tse_serial, buf, sizeof(buf));
    db_set_setting("tse_serial", buf);

    if (db_get_setting("created_at", g_created_at, sizeof(g_created_at))) {
        return;
    }
    util_now_iso(g_created_at, sizeof(g_created_at));
}

void store_shutdown(void) {
    if (tse_worm_is_active()) {
        tse_worm_shutdown();
    }
}

static int store_register_client_locked(const char *serial_number) {
    if (tse_worm_is_active()) {
        reg_client_job_t job = { .client_id = serial_number, .rc = -1 };
        tse_worker_run(reg_client_fn, &job);
        return job.rc;
    }
    char now[64];
    util_now_iso(now, sizeof(now));
    const char *sql =
        "INSERT INTO clients (serial_number, registered_at, state, type_of_system, meta_json) "
        "VALUES (?, ?, 'REGISTERED', NULL, NULL) "
        "ON CONFLICT(serial_number) DO UPDATE SET "
        "registered_at = excluded.registered_at, state = excluded.state;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, serial_number, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, now, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

/*
 * The hardware TSE is the source of truth for signatures, but it only
 * exposes a *count* of started transactions (worm_info_startedTransactions),
 * not their identities. Mirror start/finish into the local `transactions`
 * table (state only, no re-signing) so GET /transactions can report which
 * transaction numbers are still open ("started" on the TSE, no matching
 * finish yet), even in hardware mode.
 */
static void record_transaction_open(const tse_transaction_t *tx, const char *external_tx_id) {
    const char *sql =
        "INSERT INTO transactions ("
        "transaction_number, client_id, external_transaction_id,"
        "process_type, process_data, state, time_start,"
        "signature_counter, signature_value"
        ") VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?) "
        "ON CONFLICT(transaction_number) DO UPDATE SET "
        "client_id = excluded.client_id, external_transaction_id = excluded.external_transaction_id, "
        "process_type = excluded.process_type, state = 'ACTIVE';";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    char now[64];
    util_now_iso(now, sizeof(now));
    sqlite3_bind_int64(stmt, 1, tx->transaction_number);
    sqlite3_bind_text(stmt, 2, tx->client_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, external_tx_id && external_tx_id[0] ? external_tx_id : NULL, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, tx->process_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, tx->signature_counter);
    sqlite3_bind_text(stmt, 8, tx->signature_value, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static void record_transaction_finished(int64_t transaction_number) {
    const char *sql = "UPDATE transactions SET state = 'FINISHED', time_end = ? "
                      "WHERE transaction_number = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    char now[64];
    util_now_iso(now, sizeof(now));
    sqlite3_bind_text(stmt, 1, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, transaction_number);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static int store_list_open_transactions_locked(const char *client_id, tse_transaction_t *out,
                                               size_t max, size_t *out_count) {
    *out_count = 0;
    const char *sql = "SELECT transaction_number, client_id, external_transaction_id, "
                      "process_type, process_data, state, time_start, time_end, "
                      "signature_counter, signature_value "
                      "FROM transactions WHERE state = 'ACTIVE' AND client_id = ? "
                      "ORDER BY transaction_number;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, client_id ? client_id : "", -1, SQLITE_STATIC);
    while (*out_count < max && sqlite3_step(stmt) == SQLITE_ROW) {
        load_transaction_row(stmt, &out[*out_count]);
        (*out_count)++;
    }
    sqlite3_finalize(stmt);
    return 0;
}

static int store_start_transaction_locked(const char *client_id, const char *process_type,
                                          const char *process_data, const char *external_tx_id,
                                          tse_transaction_t *out) {
    if (tse_worm_is_active()) {
        start_tx_job_t job = {
            .client_id    = client_id,
            .process_type = process_type,
            .process_data = process_data,
            .out          = out,
            .rc           = -1,
        };
        tse_worker_run(start_tx_fn, &job);
        if (job.rc != 0) {
            log_error("%s", job.err);
            return -1;
        }
        if (external_tx_id && external_tx_id[0]) {
            strncpy(out->external_transaction_id, external_tx_id,
                    sizeof(out->external_transaction_id) - 1);
        }
        record_transaction_open(out, external_tx_id);
        return 0;
    }
    int64_t tx_num = db_increment_counter("transaction_counter");
    int64_t sig_counter = db_increment_counter("signature_counter");
    char now[64];
    util_now_iso(now, sizeof(now));
    char sig[128];
    if (util_random_base64(sig, sizeof(sig), 32) != 0) {
        return -1;
    }

    const char *sql =
        "INSERT INTO transactions ("
        "transaction_number, client_id, external_transaction_id,"
        "process_type, process_data, state, time_start,"
        "signature_counter, signature_value"
        ") VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, tx_num);
    sqlite3_bind_text(stmt, 2, client_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, external_tx_id && external_tx_id[0] ? external_tx_id : NULL, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, process_type ? process_type : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, process_data ? process_data : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, sig_counter);
    sqlite3_bind_text(stmt, 8, sig, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);

    const char *get_sql = "SELECT transaction_number, client_id, external_transaction_id, "
                          "process_type, process_data, state, time_start, time_end, "
                          "signature_counter, signature_value "
                          "FROM transactions WHERE transaction_number = ?;";
    if (sqlite3_prepare_v2(g_db, get_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, tx_num);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        load_transaction_row(stmt, out);
    }
    sqlite3_finalize(stmt);
    return 0;
}

static int store_finish_transaction_locked(const char *client_id, int64_t transaction_number,
                                           const char *process_type, const char *process_data,
                                           tse_transaction_t *out, char *err_code,
                                           size_t err_code_len, char *err_msg,
                                           size_t err_msg_len) {
    if (tse_worm_is_active()) {
        finish_tx_job_t job = {
            .client_id          = client_id,
            .transaction_number = transaction_number,
            .process_type       = process_type,
            .process_data       = process_data,
            .out                = out,
            .err_code           = err_code,
            .err_code_len       = err_code_len,
            .err_msg            = err_msg,
            .err_msg_len        = err_msg_len,
            .rc                 = -1,
        };
        tse_worker_run(finish_tx_fn, &job);
        if (job.rc == 0) {
            record_transaction_finished(transaction_number);
        }
        return job.rc;
    }
    (void)client_id;
    const char *get_sql = "SELECT transaction_number, client_id, external_transaction_id, "
                          "process_type, process_data, state, time_start, time_end, "
                          "signature_counter, signature_value "
                          "FROM transactions WHERE transaction_number = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, get_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, transaction_number);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        strncpy(err_code, "ErrorNoTransaction", err_code_len);
        strncpy(err_msg, "No open transaction for this number", err_msg_len);
        return -1;
    }
    tse_transaction_t existing;
    load_transaction_row(stmt, &existing);
    sqlite3_finalize(stmt);

    if (strcmp(existing.state, "ACTIVE") != 0) {
        strncpy(err_code, "ErrorNoTransaction", err_code_len);
        strncpy(err_msg, "No open transaction for this number", err_msg_len);
        return -1;
    }

    int64_t sig_counter = db_increment_counter("signature_counter");
    char now[64];
    util_now_iso(now, sizeof(now));
    char sig[128];
    if (util_random_base64(sig, sizeof(sig), 32) != 0) {
        return -1;
    }

    const char *final_pt = (process_type && process_type[0]) ? process_type : existing.process_type;
    const char *final_pd = (process_data && process_data[0]) ? process_data : existing.process_data;

    const char *upd_sql =
        "UPDATE transactions SET process_type = ?, process_data = ?, state = 'FINISHED', "
        "time_end = ?, signature_counter = ?, signature_value = ? "
        "WHERE transaction_number = ?;";
    if (sqlite3_prepare_v2(g_db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, final_pt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, final_pd, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, sig_counter);
    sqlite3_bind_text(stmt, 5, sig, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, transaction_number);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(g_db, get_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, transaction_number);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        load_transaction_row(stmt, out);
    }
    sqlite3_finalize(stmt);
    return 0;
}

static void store_info_locked(tse_info_t *info) {
    memset(info, 0, sizeof(*info));
    if (tse_worm_is_active()) {
        fill_info_job_t job = { .info = info };
        tse_worker_run(fill_info_fn, &job);
        util_strlcpy(info->fcc_version, g_config.fcc_version, sizeof(info->fcc_version));
        util_strlcpy(info->db_path, g_config.tse_device, sizeof(info->db_path));
        info->initialized = true;
        if (g_created_at[0]) {
            util_strlcpy(info->created_at, g_created_at, sizeof(info->created_at));
        } else {
            db_get_setting("created_at", info->created_at, sizeof(info->created_at));
        }
        return;
    }
    char buf[128];
    db_get_setting("tse_serial", buf, sizeof(buf));
    store_normalize_serial(buf, info->serial_number, sizeof(info->serial_number));
    db_get_setting("signature_counter", buf, sizeof(buf));
    info->signature_counter = atoll(buf);
    if (g_created_at[0]) {
        util_strlcpy(info->created_at, g_created_at, sizeof(info->created_at));
    } else {
        db_get_setting("created_at", info->created_at, sizeof(info->created_at));
    }
    util_strlcpy(info->fcc_version, g_config.fcc_version, sizeof(info->fcc_version));
    util_strlcpy(info->db_path, g_config.db_path, sizeof(info->db_path));
    info->initialized = true;

    const char *sql = "SELECT COUNT(*) FROM clients;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            info->registered_clients = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    /* currentNumberOfTransactions = open (ACTIVE) txs, not the lifetime
     * transaction_counter used to allocate new numbers. Matches hardware
     * worm_info_startedTransactions. */
    sql = "SELECT COUNT(*) FROM transactions WHERE state = 'ACTIVE';";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            info->transaction_counter = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    /* Simulator has no real hardware limits; these match the values printed
     * in the swissbit dev-kit docs for a fresh TSE and are only used when
     * not running against real hardware (see tse_worm_fill_info for the
     * real values). */
    info->max_registered_clients = 100;
    info->max_started_transactions = 500;
}

/*
 * Public entry points. Requests are served concurrently, but the TSE has a
 * single monotonic signature counter and the sequences below read state and
 * then write it back, so each operation runs to completion before the next
 * one starts. The hardware itself is serialised anyway (tse_worker plus
 * g_worm_mu), so this costs nothing in hardware mode.
 */

int store_register_client(const char *serial_number) {
    db_lock();
    int rc = store_register_client_locked(serial_number);
    db_unlock();
    return rc;
}

int store_list_open_transactions(const char *client_id, tse_transaction_t *out, size_t max,
                                 size_t *out_count) {
    db_lock();
    int rc = store_list_open_transactions_locked(client_id, out, max, out_count);
    db_unlock();
    return rc;
}

int64_t store_count_open_transactions(const char *client_id) {
    int64_t count = 0;
    db_lock();
    const char *sql = "SELECT COUNT(*) FROM transactions WHERE state = 'ACTIVE' AND client_id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, client_id ? client_id : "", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    db_unlock();
    return count;
}

int store_start_transaction(const char *client_id, const char *process_type,
                            const char *process_data, const char *external_tx_id,
                            tse_transaction_t *out) {
    db_lock();
    int rc = store_start_transaction_locked(client_id, process_type, process_data, external_tx_id,
                                            out);
    db_unlock();
    return rc;
}

int store_finish_transaction(const char *client_id, int64_t transaction_number,
                             const char *process_type, const char *process_data,
                             tse_transaction_t *out, char *err_code, size_t err_code_len,
                             char *err_msg, size_t err_msg_len) {
    db_lock();
    int rc = store_finish_transaction_locked(client_id, transaction_number, process_type,
                                             process_data, out, err_code, err_code_len, err_msg,
                                             err_msg_len);
    db_unlock();
    return rc;
}

void store_info(tse_info_t *info) {
    db_lock();
    store_info_locked(info);
    db_unlock();
}

/* ── Demo/sim ustar export ─────────────────────────────────────────────── */

#define TAR_BLOCK 512
#define TAR_CHUNK_MAX (128 * TAR_BLOCK) /* match worm_export_tar */

static void tar_header(unsigned char hdr[TAR_BLOCK], const char *name, size_t size,
                       time_t mtime) {
    memset(hdr, 0, TAR_BLOCK);
    snprintf((char *)hdr, 100, "%s", name);
    snprintf((char *)hdr + 100, 8, "%07o", 0644);
    snprintf((char *)hdr + 108, 8, "%07o", 0);
    snprintf((char *)hdr + 116, 8, "%07o", 0);
    snprintf((char *)hdr + 124, 12, "%011o", (unsigned)size);
    snprintf((char *)hdr + 136, 12, "%011o", (unsigned)mtime);
    memset(hdr + 148, ' ', 8);
    hdr[156] = '0';
    memcpy(hdr + 257, "ustar", 5);
    hdr[262] = '0';
    hdr[263] = '0';

    unsigned sum = 0;
    for (int i = 0; i < TAR_BLOCK; i++) {
        sum += hdr[i];
    }
    /* 6 octal digits + NUL + space — byte 0x9a (154) must be NUL for WormAPI. */
    snprintf((char *)hdr + 148, 8, "%06o", sum & 0777777);
    hdr[154] = '\0';
    hdr[155] = ' ';
}

typedef struct {
    tse_export_cb cb;
    void *ctx;
    unsigned char buf[TAR_CHUNK_MAX];
    size_t len;
} tar_out_t;

static int tar_out_flush(tar_out_t *o, int final_partial) {
    while (o->len >= TAR_CHUNK_MAX || (final_partial && o->len > 0)) {
        size_t n = o->len;
        if (n > TAR_CHUNK_MAX) {
            n = TAR_CHUNK_MAX;
        }
        /* Prefer full 512-byte multiples mid-stream; allow short final chunk. */
        if (!final_partial || o->len > TAR_CHUNK_MAX) {
            n = (n / TAR_BLOCK) * TAR_BLOCK;
            if (n == 0) {
                break;
            }
        }
        if (o->cb(o->buf, n, o->ctx) != 0) {
            return -1;
        }
        o->len -= n;
        if (o->len > 0) {
            memmove(o->buf, o->buf + n, o->len);
        }
    }
    return 0;
}

static int tar_out_write(tar_out_t *o, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len > 0) {
        size_t room = TAR_CHUNK_MAX - o->len;
        size_t n = len < room ? len : room;
        memcpy(o->buf + o->len, p, n);
        o->len += n;
        p += n;
        len -= n;
        if (o->len == TAR_CHUNK_MAX && tar_out_flush(o, 0) != 0) {
            return -1;
        }
    }
    return 0;
}

static int tar_out_pad(tar_out_t *o, size_t size) {
    size_t pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
    unsigned char zeros[TAR_BLOCK];
    memset(zeros, 0, sizeof(zeros));
    return pad ? tar_out_write(o, zeros, pad) : 0;
}

static int tar_add_file(tar_out_t *o, const char *name, const void *data, size_t size,
                        time_t mtime) {
    unsigned char hdr[TAR_BLOCK];
    tar_header(hdr, name, size, mtime);
    if (tar_out_write(o, hdr, TAR_BLOCK) != 0) {
        return -1;
    }
    if (size > 0 && tar_out_write(o, data, size) != 0) {
        return -1;
    }
    return tar_out_pad(o, size);
}

int store_export_tar(tse_export_cb cb, void *ctx) {
    tar_out_t out = {.cb = cb, .ctx = ctx, .len = 0};
    time_t now = time(NULL);
    tse_info_t info;
    memset(&info, 0, sizeof(info));
    store_info(&info);

    char readme[512];
    int readme_len =
        snprintf(readme, sizeof(readme),
                 "cloudtse simulator export\n"
                 "serial=%s\n"
                 "fccVersion=%s\n"
                 "This archive is a demo stand-in for worm_export_tar.\n"
                 "Member names use _Sig-<n> like the Swissbit TSE store.\n",
                 info.serial_number, info.fcc_version);
    if (readme_len < 0) {
        return -1;
    }
    if (tar_add_file(&out, "demo/README.txt", readme, (size_t)readme_len, now) != 0) {
        return -1;
    }

    const char *sql = "SELECT transaction_number, client_id, external_transaction_id, "
                      "process_type, process_data, state, time_start, time_end, "
                      "signature_counter, signature_value "
                      "FROM transactions WHERE state = 'FINISHED' "
                      "ORDER BY signature_counter, transaction_number;";

    tse_transaction_t *rows = NULL;
    size_t count = 0;
    size_t cap = 0;

    db_lock();
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        db_unlock();
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            tse_transaction_t *nr = realloc(rows, ncap * sizeof(*nr));
            if (!nr) {
                sqlite3_finalize(stmt);
                db_unlock();
                free(rows);
                return -1;
            }
            rows = nr;
            cap = ncap;
        }
        memset(&rows[count], 0, sizeof(rows[count]));
        load_transaction_row(stmt, &rows[count]);
        util_strlcpy(rows[count].serial_number, info.serial_number,
                     sizeof(rows[count].serial_number));
        count++;
    }
    sqlite3_finalize(stmt);
    db_unlock();

    int rc = 0;
    for (size_t i = 0; i < count; i++) {
        const tse_transaction_t *tx = &rows[i];
        char esc_client[512], esc_ext[512], esc_ptype[1024], esc_pdata[8192], esc_sig[512];
        json_escape(tx->client_id, esc_client, sizeof(esc_client));
        json_escape(tx->external_transaction_id, esc_ext, sizeof(esc_ext));
        json_escape(tx->process_type, esc_ptype, sizeof(esc_ptype));
        json_escape(tx->process_data, esc_pdata, sizeof(esc_pdata));
        json_escape(tx->signature_value, esc_sig, sizeof(esc_sig));

        char body[12288];
        int body_len = snprintf(
            body, sizeof(body),
            "{\"transactionNumber\":\"%lld\",\"signatureCounter\":\"%lld\","
            "\"signatureValue\":\"%s\",\"clientId\":\"%s\","
            "\"externalTransactionId\":\"%s\",\"processType\":\"%s\","
            "\"processData\":\"%s\",\"timeStart\":\"%s\",\"timeEnd\":\"%s\","
            "\"serialNumber\":\"%s\"}\n",
            (long long)tx->transaction_number, (long long)tx->signature_counter, esc_sig,
            esc_client, esc_ext, esc_ptype, esc_pdata, tx->time_start, tx->time_end,
            tx->serial_number);
        if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
            rc = -1;
            break;
        }

        /* Name must contain _Sig-<decimal> (see signatureCounterOfEntry). */
        char name[100];
        snprintf(name, sizeof(name), "demo/LogMessage_Tx%lld_Sig-%lld.json",
                 (long long)tx->transaction_number, (long long)tx->signature_counter);

        if (tar_add_file(&out, name, body, (size_t)body_len, now) != 0) {
            rc = -1;
            break;
        }
    }
    free(rows);
    if (rc != 0) {
        return rc;
    }

    /* Two zero blocks = end-of-archive (same as worm_export_tar's size+2). */
    unsigned char zblk[TAR_BLOCK * 2];
    memset(zblk, 0, sizeof(zblk));
    if (tar_out_write(&out, zblk, sizeof(zblk)) != 0) {
        return -1;
    }
    return tar_out_flush(&out, 1);
}
