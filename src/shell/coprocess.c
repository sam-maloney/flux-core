/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

/* coprocess.c - launch helper process(es) alongside a job
 *
 * A coprocess is a helper command (e.g. a node monitoring tool) that runs
 * for the duration of the job. Co-processes are described by the "coprocess"
 * job shell option, a JSON object keyed by co-process name, e.g.
 *
 *   -o coprocess='{"gpumon":{"command":["nvidia-smi","dmon"],
 *                            "output":"gpumon-{{id}}.log"}}'
 *
 * Each named entry may set:
 *   command  (array of strings, required) - argv of the helper
 *   output   (string, optional)           - output file template
 *   ranks    (idset string or "all")      - shell ranks that launch it;
 *                                           default "all"
 *
 * Where command and output support shell mustache templates as expanded
 * by flux_shell_mustache_render(3).
 *
 * If `output` renders per-shell, then each shell opens the output file
 * and directs output locally. Otherwise, output is sent back to the rank 0
 * shell which then directs output to the single output file.
 *
 * At shell.finish each co-process is sent SIGTERM, escalating to SIGKILL
 * after coprocess-kill-timeout. A completion reference per co-process keeps
 * the shell reactor alive until the helper is reaped, so all of its output
 * (including any final output emitted on SIGTERM) is read before exit.
 *
 * For aggregated output, a follower forwards a final EOF to the leader from
 * its completion callback (after all output has been read and forwarded, and
 * since RPCs are delivered in order, after the last data chunk). The leader
 * holds a "coprocess.service" completion reference until every forwarding
 * follower has sent its EOF, so late output is not dropped by the leader
 * exiting early. A lost shell is dropped from the waited-on set via
 * shell.lost so the reference is still released.
 */
#define FLUX_SHELL_PLUGIN_NAME "coprocess"

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <flux/core.h>
#include <flux/shell.h>
#include <flux/idset.h>
#include <jansson.h>

#include "src/common/libczmqcontainers/czmq_containers.h"
#include "src/common/libutil/read_all.h"
#include "src/common/libutil/fsd.h"
#include "ccan/str/str.h"

#include "internal.h"
#include "builtins.h"

extern char **environ;

static const double default_kill_timeout = 10.;

struct coprocess_ctx {
    flux_shell_t *shell;
    int shell_rank;
    int shell_size;
    zlistx_t *procs;            /* list of struct coproc */
    int running;                /* count of live local subprocesses */
    double kill_timeout;
    flux_watcher_t *kill_timer;
    bool killed;                /* SIGKILL escalation sent */
    bool service_ref;           /* leader holds "coprocess.service" ref */
};

struct coproc {
    char *name;
    flux_cmd_t *cmd;
    char *output;               /* output file template */
    bool output_per_shell;      /* template renders to a distinct file/shell */
    struct idset *ranks;        /* shell ranks to launch on, NULL = all */
    flux_subprocess_t *proc;    /* live subprocess on this shell, or NULL */
    int fd;                     /* open output file, or -1 */
    struct idset *eof_pending;  /* leader: follower ranks owing an EOF */
    struct coprocess_ctx *ctx;
};

static void coproc_destroy (struct coproc *c)
{
    if (c) {
        int saved_errno = errno;
        free (c->name);
        flux_cmd_destroy (c->cmd);
        free (c->output);
        idset_destroy (c->ranks);
        idset_destroy (c->eof_pending);
        flux_subprocess_destroy (c->proc);
        if (c->fd >= 0)
            close (c->fd);
        free (c);
        errno = saved_errno;
    }
}

/* zlistx destructor */
static void coproc_destructor (void **item)
{
    if (item) {
        coproc_destroy (*item);
        *item = NULL;
    }
}

static void coprocess_ctx_destroy (struct coprocess_ctx *ctx)
{
    if (ctx) {
        int saved_errno = errno;
        zlistx_destroy (&ctx->procs);
        flux_watcher_destroy (ctx->kill_timer);
        free (ctx);
        errno = saved_errno;
    }
}

static struct coproc *coproc_find (struct coprocess_ctx *ctx,
                                   const char *name)
{
    struct coproc *c = zlistx_first (ctx->procs);
    while (c) {
        if (streq (c->name, name))
            return c;
        c = zlistx_next (ctx->procs);
    }
    return NULL;
}

/* True if this co-process should be launched on the local shell rank.
 */
static bool coproc_on_rank (struct coproc *c, int rank)
{
    if (!c->ranks)                          /* "all" */
        return true;
    return idset_test (c->ranks, rank);
}

/* Parse a single co-process config entry into a struct coproc.
 */
static struct coproc *coproc_create (struct coprocess_ctx *ctx,
                                     const char *name,
                                     json_t *entry)
{
    struct coproc *c;
    json_t *command = NULL;
    json_t *value;
    const char *output = NULL;
    const char *ranks = NULL;
    size_t index;
    json_error_t error;

    if (!(c = calloc (1, sizeof (*c))))
        return NULL;
    c->ctx = ctx;
    c->fd = -1;
    if (!(c->name = strdup (name)))
        goto error;
    if (json_unpack_ex (entry,
                        &error,
                        0,
                        "{s:o s?s s?s !}",
                        "command", &command,
                        "output", &output,
                        "ranks", &ranks) < 0) {
        shell_log_error ("%s: %s", name, error.text);
        goto inval;
    }
    if (!json_is_array (command) || json_array_size (command) == 0) {
        shell_log_error ("%s: command must be a non-empty array",
                         name);
        goto inval;
    }
    if (!(c->cmd = flux_cmd_create (0, NULL, environ)))
        goto error;
    json_array_foreach (command, index, value) {
        int rc;
        const char *arg;
        char *xarg = NULL;
        if (!json_is_string (value)) {
            shell_log_error ("%s: command elements must be strings",
                             name);
            goto inval;
        }
        arg = json_string_value (value);
        if (strstr (arg, "{{")) {
            if (!(xarg = flux_shell_mustache_render (ctx->shell, arg))) {
                shell_log_error ("%s: failed to expand '%s'", name, arg);
                goto error;
            }
            arg = xarg;
        }
        rc = flux_cmd_argv_append (c->cmd, arg);
        free (xarg);
        if (rc < 0)
            goto error;
    }
    /* Default output template if not configured. */
    if (output) {
        if (!(c->output = strdup (output)))
            goto error;
    }
    else if (asprintf (&c->output, "coproc-%s-{{id}}.log", name) < 0)
        goto error;
    c->output_per_shell = flux_shell_mustache_is_per_rank (ctx->shell,
                                                           c->output);
    if (ranks && !streq (ranks, "all")) {
        if (!(c->ranks = idset_decode (ranks))) {
            shell_log_error ("%s: invalid ranks '%s'", name, ranks);
            goto inval;
        }
    }
    /* Leader with aggregated output: track the follower ranks that will
     * forward output and owe an EOF (rank 0 writes its own output directly).
     * eof_pending stays NULL if no follower participates.
     */
    if (ctx->shell_rank == 0
        && !c->output_per_shell
        && ctx->shell_size > 1) {
        int rank;
        if (!(c->eof_pending = idset_create (ctx->shell_size, 0)))
            goto error;
        if (!c->ranks)  /* "all" */
            idset_range_set (c->eof_pending, 1, ctx->shell_size - 1);
        else {
            for (rank = 1; rank < ctx->shell_size; rank++) {
                if (coproc_on_rank (c, rank)
                    && idset_set (c->eof_pending, rank) < 0)
                    goto error;
            }
        }
        if (idset_count (c->eof_pending) == 0) {
            idset_destroy (c->eof_pending);
            c->eof_pending = NULL;
        }
    }
    return c;
inval:
    errno = EINVAL;
error:
    coproc_destroy (c);
    return NULL;
}

/* Lazily open the co-process output file, returning its fd or -1 on error.
 */
static int coproc_getfd (struct coproc *c)
{
    char *path;

    if (c->fd >= 0)
        return c->fd;
    if (!(path = flux_shell_rank_mustache_render (c->ctx->shell,
                                                  c->ctx->shell_rank,
                                                  c->output)))
        return -1;
    if ((c->fd = open (path, O_CREAT | O_WRONLY | O_TRUNC, 0600)) < 0)
        shell_log_errno ("%s: open %s", c->name, path);
    free (path);
    return c->fd;
}

/* Write a chunk to the co-process output file, opening it if necessary.
 */
static void coproc_write (struct coproc *c, const char *buf, int len)
{
    int fd = coproc_getfd (c);
    if (fd >= 0 && write_all (fd, buf, len) < 0)
        shell_log_errno ("%s: write output", c->name);
}

/* Follower: forward an output chunk to the leader's coprocess-write service. */
static void coproc_forward (struct coproc *c, const char *buf, int len)
{
    flux_future_t *f;

    if (!(f = flux_shell_rpc_pack (c->ctx->shell,
                                   "coprocess-write",
                                   0,
                                   FLUX_RPC_NORESPONSE,
                                   "{s:s s:s#}",
                                   "name", c->name,
                                   "data", buf, len)))
        shell_log_errno ("%s: forward output", c->name);
    flux_future_destroy (f);
}

/* Notify the leader that this follower has forwarded all output for 'c'. */
static void coproc_forward_eof (struct coproc *c)
{
    flux_future_t *f;

    if (!(f = flux_shell_rpc_pack (c->ctx->shell,
                                   "coprocess-write",
                                   0,
                                   FLUX_RPC_NORESPONSE,
                                   "{s:s s:i}",
                                   "name", c->name,
                                   "eof_rank", c->ctx->shell_rank)))
        shell_log_errno ("%s: forward eof", c->name);
    flux_future_destroy (f);
}

/* Leader: release the output aggregation service reference once every
 * follower that forwards output has sent its EOF (or been lost).
 */
static bool coproc_eof_outstanding (struct coprocess_ctx *ctx)
{
    struct coproc *c = zlistx_first (ctx->procs);
    while (c) {
        if (c->eof_pending && idset_count (c->eof_pending) > 0)
            return true;
        c = zlistx_next (ctx->procs);
    }
    return false;
}

static void coproc_service_check (struct coprocess_ctx *ctx)
{
    if (ctx->service_ref && !coproc_eof_outstanding (ctx)) {
        if (flux_shell_remove_completion_ref (ctx->shell,
                                              "coprocess.service") < 0)
            shell_log_errno ("coprocess: remove service completion ref");
        ctx->service_ref = false;
    }
}

/* Leader: follower rank 'shell_rank' has finished forwarding output for 'c'.
 */
static void coproc_eof (struct coproc *c, int shell_rank)
{
    if (c->eof_pending) {
        idset_clear (c->eof_pending, shell_rank);
        coproc_service_check (c->ctx);
    }
}

/* stdout/stderr callback for a local co-process. Drain and write the data:
 * the leader writes directly; a follower writes its own file directly when
 * the output template is per-shell, otherwise forwards to the leader for
 * aggregation into a single per-job file. Don't assume the data is NUL or
 * newline terminated.
 */
static void coproc_output_cb (flux_subprocess_t *p, const char *stream)
{
    struct coproc *c = flux_subprocess_aux_get (p, "coproc");
    const char *buf;
    int len;

    len = flux_subprocess_read (p, stream, &buf);
    if (len <= 0)
        return;
    if (c->ctx->shell_rank == 0 || c->output_per_shell)
        coproc_write (c, buf, len);
    else
        coproc_forward (c, buf, len);
}

static void kill_continuation (flux_future_t *f, void *arg)
{
    /* ESRCH means the co-process already exited before or during the kill,
     * which is an expected race (e.g. a short-lived helper) and not an error.
     */
    if (flux_future_get (f, NULL) < 0 && errno != ESRCH)
        shell_log_errno ("coprocess: kill");
    flux_future_destroy (f);
}

static int coproc_kill (struct coproc *c, int signum)
{
    flux_future_t *f;

    if (!c->proc)
        return 0;
    if (!(f = flux_subprocess_kill (c->proc, signum))) {
        if (errno == ESRCH)
            return 0;
        return -1;
    }
    if (flux_future_then (f, -1, kill_continuation, NULL) < 0) {
        flux_future_destroy (f);
        return -1;
    }
    return 0;
}

/* Co-process completed (exited or was signaled): drop its completion
 * reference so the shell can exit once all co-processes are reaped.
 */
static void coproc_completion_cb (flux_subprocess_t *p)
{
    struct coproc *c = flux_subprocess_aux_get (p, "coproc");
    struct coprocess_ctx *ctx = c->ctx;

    c->proc = NULL;
    flux_subprocess_destroy (p);

    /* A follower forwarding to the leader has now read and forwarded all
     * output, so tell the leader no more is coming for this co-process.
     */
    if (ctx->shell_rank != 0 && !c->output_per_shell)
        coproc_forward_eof (c);

    if (--ctx->running == 0 && ctx->kill_timer)
        flux_watcher_stop (ctx->kill_timer);
    if (flux_shell_remove_completion_ref (ctx->shell,
                                          "coprocess::%s",
                                          c->name) < 0)
        shell_log_errno ("%s: remove completion ref", c->name);
}

/* SIGKILL escalation timer: any co-process still running after kill_timeout
 * gets SIGKILL.
 */
static void kill_timer_cb (flux_reactor_t *r,
                           flux_watcher_t *w,
                           int revents,
                           void *arg)
{
    struct coprocess_ctx *ctx = arg;
    struct coproc *c;

    if (ctx->killed)
        return;
    ctx->killed = true;
    shell_warn ("coprocess: helper(s) still running, sending SIGKILL");
    c = zlistx_first (ctx->procs);
    while (c) {
        if (c->proc && coproc_kill (c, SIGKILL) < 0)
            shell_log_errno ("%s: SIGKILL", c->name);
        c = zlistx_next (ctx->procs);
    }
}

/* Leader service: receive output forwarded by a follower shell. Each message
 * carries either "data" (an output chunk) or "eof_rank" (the follower is done
 * forwarding), never both. Since RPCs from a given follower are delivered in
 * order, the eof_rank message arrives after that follower's last data chunk.
 */
static void write_service_cb (flux_t *h,
                              flux_msg_handler_t *mh,
                              const flux_msg_t *msg,
                              void *arg)
{
    struct coprocess_ctx *ctx = arg;
    const char *name;
    const char *data = NULL;
    size_t len = 0;
    int eof_rank = -1;
    struct coproc *c;

    if (flux_request_unpack (msg,
                             NULL,
                             "{s:s s?s% s?i}",
                             "name", &name,
                             "data", &data, &len,
                             "eof_rank", &eof_rank) < 0) {
        shell_log_errno ("coprocess: write service unpack");
        return;
    }
    if (!(c = coproc_find (ctx, name))) {
        shell_log_error ("coprocess: write for unknown co-process '%s'", name);
        return;
    }
    if (data)
        coproc_write (c, data, len);
    if (eof_rank >= 0)
        coproc_eof (c, eof_rank);
}

/* Leader: a lost shell will never send its EOF, so drop it from every
 * co-process's pending set. The lost shell independently raises a job
 * exception, so this does not mask the failure.
 */
static int coprocess_lost (flux_plugin_t *p,
                           const char *topic,
                           flux_plugin_arg_t *args,
                           void *arg)
{
    struct coprocess_ctx *ctx = arg;
    struct coproc *c;
    int shell_rank;

    if (flux_plugin_arg_unpack (args,
                                FLUX_PLUGIN_ARG_IN,
                                "{s:i}",
                                "shell_rank", &shell_rank) < 0)
        return shell_log_errno ("coprocess: shell.lost unpack");
    c = zlistx_first (ctx->procs);
    while (c) {
        if (c->eof_pending)
            idset_clear (c->eof_pending, shell_rank);
        c = zlistx_next (ctx->procs);
    }
    coproc_service_check (ctx);
    return 0;
}

static int coprocess_start (flux_plugin_t *p,
                            const char *topic,
                            flux_plugin_arg_t *args,
                            void *data)
{
    struct coprocess_ctx *ctx = data;
    struct coproc *c;
    flux_subprocess_ops_t ops = {
        .on_stdout = coproc_output_cb,
        .on_stderr = coproc_output_cb,
        .on_completion = coproc_completion_cb,
    };

    c = zlistx_first (ctx->procs);
    while (c) {
        if (coproc_on_rank (c, ctx->shell_rank)) {
            flux_subprocess_t *proc;
            if (!(proc = flux_local_exec (ctx->shell->r, 0, c->cmd, &ops))
                || flux_subprocess_aux_set (proc, "coproc", c, NULL) < 0) {
                shell_log_errno ("%s: launch failed", c->name);
                flux_subprocess_destroy (proc);
                /* This follower will produce no output to forward, so release
                 * the leader from waiting on its EOF.
                 */
                if (ctx->shell_rank != 0 && !c->output_per_shell)
                    coproc_forward_eof (c);
                c = zlistx_next (ctx->procs);
                continue;
            }
            c->proc = proc;
            ctx->running++;
            if (flux_shell_add_completion_ref (ctx->shell,
                                               "coprocess::%s",
                                               c->name) < 0)
                shell_log_errno ("%s: add completion ref",
                                 c->name);
            shell_debug ("%s: launched", c->name);
        }
        c = zlistx_next (ctx->procs);
    }
    return 0;
}

static int coprocess_finish (flux_plugin_t *p,
                             const char *topic,
                             flux_plugin_arg_t *args,
                             void *data)
{
    struct coprocess_ctx *ctx = data;
    struct coproc *c;

    if (ctx->running == 0)
        return 0;

    c = zlistx_first (ctx->procs);
    while (c) {
        if (c->proc && coproc_kill (c, SIGTERM) < 0)
            shell_log_errno ("%s: SIGTERM", c->name);
        c = zlistx_next (ctx->procs);
    }

    /* Escalate to SIGKILL after kill_timeout */
    if (!(ctx->kill_timer = flux_timer_watcher_create (ctx->shell->r,
                                                       ctx->kill_timeout,
                                                       0.,
                                                       kill_timer_cb,
                                                       ctx)))
        return shell_log_errno ("coprocess: create kill timer");
    flux_watcher_start (ctx->kill_timer);
    return 0;
}

static int coprocess_init (flux_plugin_t *p,
                           const char *topic,
                           flux_plugin_arg_t *args,
                           void *data)
{
    flux_shell_t *shell = flux_plugin_get_shell (p);
    struct coprocess_ctx *ctx;
    json_t *config = NULL;
    const char *name;
    json_t *entry;
    const char *timeout = NULL;

    if (flux_shell_getopt_unpack (shell, "coprocess", "o", &config) < 0)
        return -1;

    if (!config)
        return 0;

    if (!json_is_object (config) || json_object_size (config) == 0) {
        shell_log_error ("coprocess option must be a non-empty object");
        return -1;
    }
    if (!(ctx = calloc (1, sizeof (*ctx))))
        return -1;
    ctx->shell = shell;
    ctx->kill_timeout = default_kill_timeout;
    /* Grace period after SIGTERM before escalating to SIGKILL (FSD). */
    if (flux_shell_getopt_unpack (shell,
                                  "coprocess-kill-timeout",
                                  "s",
                                  &timeout) < 0) {
        shell_log_error ("invalid coprocess-kill-timeout");
        goto error;
    }
    if (timeout && fsd_parse_duration (timeout, &ctx->kill_timeout) < 0) {
        shell_log_error ("failed to parse coprocess-kill-timeout");
        goto error;
    }
    if (flux_shell_info_unpack (shell,
                                "{s:i s:i}",
                                "rank", &ctx->shell_rank,
                                "size", &ctx->shell_size) < 0)
        goto error;
    if (!(ctx->procs = zlistx_new ())) {
        errno = ENOMEM;
        goto error;
    }
    zlistx_set_destructor (ctx->procs, coproc_destructor);

    json_object_foreach (config, name, entry) {
        struct coproc *c;
        if (!(c = coproc_create (ctx, name, entry)))
            goto error;
        if (!zlistx_add_end (ctx->procs, c)) {
            coproc_destroy (c);
            errno = ENOMEM;
            goto error;
        }
    }

    /* Transfer ownership of ctx to the plugin aux before taking any resource
     * (service, completion ref) that would otherwise be leaked on a later
     * error. After this succeeds, ctx is freed on plugin destruction, so error
     * paths return -1 without destroying it.
     */
    if (flux_plugin_aux_set (p,
                             "coprocess",
                             ctx,
                             (flux_free_f)coprocess_ctx_destroy) < 0)
        goto error;

    if (flux_plugin_add_handler (p, "shell.start", coprocess_start, ctx) < 0
        || flux_plugin_add_handler (p,
                                    "shell.finish",
                                    coprocess_finish,
                                    ctx) < 0)
        return -1;

    /* If any follower will forward output (a non-empty eof_pending set on the
     * leader), register the aggregation service to receive it and hold a
     * completion reference until all such followers have reported EOF.
     */
    if (coproc_eof_outstanding (ctx)) {
        if (flux_plugin_add_handler (p,
                                     "shell.lost",
                                     coprocess_lost,
                                     ctx) < 0
            || flux_shell_service_register (shell,
                                            "coprocess-write",
                                            write_service_cb,
                                            ctx) < 0
            || flux_shell_add_completion_ref (shell,
                                              "coprocess.service") < 0)
            return -1;
        ctx->service_ref = true;
    }

    shell_debug ("coprocess enabled (%d configured)",
                 (int)zlistx_size (ctx->procs));
    return 0;
error:
    coprocess_ctx_destroy (ctx);
    return -1;
}

struct shell_builtin builtin_coprocess = {
    .name = FLUX_SHELL_PLUGIN_NAME,
    .init = coprocess_init,
};

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
