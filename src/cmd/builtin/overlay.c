/************************************************************\
 * Copyright 2021 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
# include <config.h>
#endif
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <jansson.h>
#include <flux/core.h>
#ifdef HAVE_STRERRORNAME_NP
#include <string.h>
#else
#include "src/common/libmissing/strerrorname_np.h"
#endif

#include "src/common/libccan/ccan/str/str.h"
#include "src/common/libccan/ccan/ptrint/ptrint.h"
#include "src/common/libutil/monotime.h"
#include "src/common/libutil/fsd.h"
#include "src/common/libhostlist/hostlist.h"
#include "src/common/librlist/rlist.h"
#include "src/common/libutil/errprintf.h"
#include "src/common/libutil/ansi_color.h"
#include "src/common/libutil/parse_size.h"
#include "src/common/libczmqcontainers/czmq_containers.h"
#include "ccan/str/str.h"
#include "ccan/array_size/array_size.h"

#include "builtin.h"

static double default_timeout = 0.5;

static struct optparse_option errors_opts[] = {
    { .name = "timeout", .key = 't', .has_arg = 1, .arginfo = "FSD",
      .usage = "Set RPC timeout, 0=disable (default 0.5s)",
    },
    OPTPARSE_TABLE_END
};

static struct optparse_option status_opts[] = {
    { .name = "rank", .key = 'r', .has_arg = 1, .arginfo = "NODEID",
      .usage = "Check health of subtree rooted at NODEID (default 0)",
    },
    { .name = "verbose", .key = 'v', .has_arg = 2, .arginfo = "[LEVEL]",
      .usage = "Increase reporting detail:"
               " 1=show time since current state was entered,"
               " 2=show round-trip RPC times."
    },
    { .name = "timeout", .key = 't', .has_arg = 1, .arginfo = "FSD",
      .usage = "Set RPC timeout, 0=disable (default 0.5s)",
    },
    { .name = "summary", .has_arg = 0,
      .usage = "Show only the root subtree status."
    },
    { .name = "down", .has_arg = 0,
      .usage = "Show only the partial/degraded subtrees."
    },
    { .name = "no-pretty", .has_arg = 0,
      .usage = "Do not indent entries and use line drawing characters"
               " to show overlay tree structure",
    },
    { .name = "no-ghost", .has_arg = 0,
      .usage = "Do not fill in presumed state of nodes that are"
               " inaccessible behind offline/lost overlay parents",
    },
    { .name = "color", .key = 'L', .has_arg = 2, .arginfo = "WHEN",
      .flags = OPTPARSE_OPT_SHORTOPT_OPTIONAL_ARG,
      .usage = "Colorize output when supported; WHEN can be 'always' "
               "(default if omitted), 'never', or 'auto' (default)."
    },
    { .name = "highlight", .key = 'H', .has_arg = 1, .arginfo = "TARGET",
      .usage = "Highlight one or more TARGETs and their ancestors."
    },
    { .name = "wait", .key = 'w', .has_arg = 1, .arginfo = "STATE",
      .usage = "Wait until subtree enters STATE before reporting"
               " (full, partial, offline, degraded, lost)",
    },
    OPTPARSE_TABLE_END
};

static struct optparse_option disconnect_opts[] = {
    { .name = "parent", .key = 'r', .has_arg = 1, .arginfo = "NODEID",
      .usage = "Set parent rank to NODEID (default: determine from topology)",
    },
    OPTPARSE_TABLE_END
};

static struct optparse_option trace_opts[] = {
    { .name = "rank", .key = 'r', .has_arg = 1, .arginfo = "NODEID",
      .usage = "Filter output by peer rank",
    },
    { .name = "full", .key = 'f', .has_arg = 0,
      .usage = "Show JSON message payload, if any",
    },
    { .name = "type", .key = 't', .has_arg = 1,
      .flags = OPTPARSE_OPT_AUTOSPLIT,
      .arginfo = "TYPE,...",
      .usage = "Filter output by message type "
               "(request, response, event, control)",
    },
    { .name = "color", .key = 'L', .has_arg = 2, .arginfo = "WHEN",
      .flags = OPTPARSE_OPT_SHORTOPT_OPTIONAL_ARG,
      .usage = "Colorize output when supported; WHEN can be 'always' "
               "(default if omitted), 'never', or 'auto' (default)." },
    { .name = "human",  .key = 'H',  .has_arg = 0,
      .usage = "Human readable output", },
    { .name = "delta",  .key = 'd',  .has_arg = 0,
      .usage = "With --human, show timestamp delta between messages", },
    OPTPARSE_TABLE_END,
};

struct status {
    flux_t *h;
    int verbose;
    int color;
    double timeout;
    optparse_t *opt;
    struct timespec start;
    const char *wait;
    struct idset *highlight;
    zlistx_t *stack;
};

enum connector {
    PIPE = 1,
    TEE = 2,
    ELBOW = 3,
    BLANK = 4,
    NIL = 5,
};

struct status_node {
    int rank;
    struct idset *subtree_ranks;
    const char *status;
    double duration;
    bool ghost;
    enum connector connector;
    flux_error_t error;
};

struct trace_ctx {
    int color;
    int nodeid;
    struct flux_match match;
    int delta;
    double last_sec;
    double last_timestamp;
};

static json_t *overlay_topology;
static struct hostlist *overlay_hostmap;

typedef bool (*map_f)(struct status *ctx,
                      struct status_node *node,
                      bool parent,
                      int level);

static int status_prefix_push (struct status *ctx, enum connector c)
{
    if (zlistx_add_end (ctx->stack, int2ptr (c)) == NULL)
        return -1;
    return 0;
}

static void status_prefix_pop (struct status *ctx)
{
    if (zlistx_last (ctx->stack))
        zlistx_detach_cur (ctx->stack);
}

static json_t *get_topology (flux_t *h)
{
    if (!overlay_topology) {
        flux_future_t *f;

        if (!(f = flux_rpc_pack (h,
                                 "overlay.topology",
                                 0,
                                 0,
                                 "{s:i}",
                                 "rank", 0))
            || flux_rpc_get_unpack (f, "O", &overlay_topology) < 0)
            log_err_exit ("error fetching overlay topology");

        flux_future_destroy (f);
    }
    return overlay_topology;
}

static struct hostlist *get_hostmap (flux_t *h)
{
    if (!overlay_hostmap) {
        const char *s;
        struct hostlist *hl;

        if (!(s = flux_attr_get (h, "hostlist"))
            || !(hl = hostlist_decode (s)))
            log_err_exit ("could not fetch/decode hostlist");
        overlay_hostmap = hl;
    }
    return overlay_hostmap;
}

static const char *status_duration (struct status *ctx, double since)
{
    char dbuf[128];
    static char buf[256];

    if (ctx->verbose < 1
        || since <= 0.
        || fsd_format_duration (dbuf, sizeof (dbuf), since) < 0)
        return "";
    snprintf (buf, sizeof (buf), " for %s", dbuf);
    return buf;
}

static const char *status_colorize (struct status *ctx,
                                    const char *status,
                                    bool ghost)
{
    static char buf[128];

    if (ctx->color) {
        if (streq (status, "lost") && !ghost) {
            snprintf (buf, sizeof (buf), "%s%s%s",
                      ANSI_COLOR_RED, status, ANSI_COLOR_DEFAULT);
            status = buf;
        }
        else if (streq (status, "offline") && !ghost) {
            snprintf (buf, sizeof (buf), "%s%s%s",
                      ANSI_COLOR_YELLOW, status, ANSI_COLOR_DEFAULT);
            status = buf;
        }
        else if (ghost) {
            snprintf (buf, sizeof (buf), "%s%s%s",
                      ANSI_COLOR_DARK_GRAY, status, ANSI_COLOR_DEFAULT);
            status = buf;
        }
    }
    return status;
}

static const char *connector_string (enum connector c)
{
    switch (c) {
        case PIPE:
            return "│  ";
        case TEE:
            return "├─ ";
        case ELBOW:
            return "└─ ";
        case BLANK:
            return "   ";
        case NIL:
            return "";
    }
    return "";
}

static const char *status_indent (struct status *ctx, int n)
{
    void *val;
    static char buf[1024];
    int nleft = sizeof (buf) - 1;
    size_t size = zlistx_size (ctx->stack);
    int i;

    if (optparse_hasopt (ctx->opt, "no-pretty") || n == 0)
        return "";

    buf[0] = '\0';
    i = 0;
    val = zlistx_first (ctx->stack);
    while (val) {
        /*  Only print up to the penultimate connector on the stack.
         *  The final connector is for the next level down.
         */
        if (i++ == size - 1)
            break;
        (void) strncat (buf, connector_string (ptr2int (val)), nleft);
        nleft -= 4;
        val = zlistx_next (ctx->stack);
    }
    return buf;
}

/* Return string containing hostname and rank.
 */
static const char *status_getname (struct status *ctx,
                                   struct status_node *node)
{
    static char buf[128];
    const char * highlight_start = "";
    const char * highlight_end = "";

    /*  Highlight name if colorized output is enabled and this rank's
     *   subtree (when known) intersects requested highlighted ranks:
     */
    if (node->subtree_ranks
        && idset_has_intersection (ctx->highlight, node->subtree_ranks)) {
        highlight_start = ctx->color ? ANSI_COLOR_BOLD_BLUE : "<<";
        highlight_end = ctx->color ? ANSI_COLOR_RESET : ">>";
    }

    snprintf (buf,
              sizeof (buf),
              "%s%d %s%s",
              highlight_start,
              node->rank,
              flux_get_hostbyrank (ctx->h, node->rank),
              highlight_end);
    return buf;
}

/* If verbose >= 2, return string containing parenthesised elapsed
 * time since last RPC was started, with leading space.
 * Otherwise, return the empty string
 */
static const char *status_rpctime (struct status *ctx)
{
    static char buf[64];
    if (ctx->verbose < 2)
        return "";
    snprintf (buf, sizeof (buf), " (%.3f ms)", monotime_since (ctx->start));
    return buf;
}

static void status_print (struct status *ctx,
                          struct status_node *node,
                          bool parent,
                          int level)
{
    enum connector connector = optparse_hasopt (ctx->opt, "no-pretty") ?
                               0 :
                               node->connector;
    printf ("%s%s%s: %s%s%s%s%s\n",
            status_indent (ctx, level),
            connector_string (connector),
            status_getname (ctx, node),
            status_colorize (ctx, node->status, node->ghost),
            status_duration (ctx, node->duration),
            strlen (node->error.text) > 0 ? " " : "",
            node->error.text,
            parent ? status_rpctime (ctx) : "");
}

static void status_print_noname (struct status *ctx,
                                 struct status_node *node,
                                 bool parent,
                                 int level)
{
    printf ("%s%s%s%s%s\n",
            status_indent (ctx, level),
            connector_string (node->connector),
            status_colorize (ctx, node->status, node->ghost),
            status_duration (ctx, node->duration),
            parent ? status_rpctime (ctx) : "");
}

/* Recursive function to walk 'topology', adding all subtree ranks to 'ids'.
 * Returns 0 on success, -1 on failure (errno is not set).
 *
 * Note: Lifted directly from src/broker/groups.c
 */
static int add_subtree_ids (struct idset *ids, json_t *topology)
{
    int rank;
    json_t *a;
    size_t index;
    json_t *entry;

    if (json_unpack (topology, "{s:i s:o}", "rank", &rank, "children", &a) < 0
        || idset_set (ids, rank) < 0)
        return -1;
    json_array_foreach (a, index, entry) {
        if (add_subtree_ids (ids, entry) < 0)
            return -1;
    }
    return 0;
}

/*  Return an idset of ranks included in subtree 'topology'
 *   (including root rank).
 */
static struct idset *topology_subtree_ranks (json_t *topology)
{
    struct idset *ids;

    if (!topology)
        return NULL;

    if (!(ids = idset_create (0, IDSET_FLAG_AUTOGROW))
        || add_subtree_ids (ids, topology))
        goto error;
    return ids;
error:
    idset_destroy (ids);
    return NULL;
}

/*  Return the subtree topology rooted at 'subtree_rank'.
 */
static json_t *get_subtree_topology (json_t *topo, int subtree_rank)
{
    int rank;
    json_t *a;
    json_t *result;
    size_t index;
    json_t *entry;

    if (json_unpack (topo, "{s:i s:o}", "rank", &rank, "children", &a) < 0)
        return NULL;
    if (rank == subtree_rank)
        return topo;
    json_array_foreach (a, index, entry) {
        if (json_unpack (entry, "{s:i}", "rank", &rank) < 0)
            return NULL;
        if (rank == subtree_rank)
            return entry;
        else if ((result = get_subtree_topology (entry, subtree_rank)))
            return result;
    }
    return NULL;
}

/*  Return an idset of all ranks in the topology subtree rooted at 'rank'.
 */
static struct idset *subtree_ranks (flux_t *h, int rank)
{
    json_t *topo;
    json_t *topology = get_topology (h);

    if (!(topo = get_subtree_topology (topology, rank))) {
        log_err ("get_subtree_topology");
        return NULL;
    }
    return topology_subtree_ranks (topo);
}

/* Walk a "ghost" subtree from the fixed topology.  Each node is assumed to
 * have the same 'status' as the offline/lost parent at the subtree root.
 * This augments healthwalk() to fill in nodes that would otherwise be missing
 * because they don't have a direct parent that is online for probing.
 * N.B. the starting point, the rank at the root of topo, is assumed to
 * have already been mapped/iterated over.
 */
static void status_ghostwalk (struct status *ctx,
                              json_t *topo,
                              int level,
                              const char *status,
                              enum connector connector,
                              map_f fun)
{
    json_t *children;
    size_t index;
    size_t total;
    json_t *entry;
    struct status_node node = {
        .status = status,
        .duration = -1., // invalid - don't print
        .ghost = true,
        .connector = connector,
        .subtree_ranks = NULL,
    };

    if (json_unpack (topo, "{s:o}", "children", &children) < 0)
        return;
    total = json_array_size (children);
    json_array_foreach (children, index, entry) {
        if (json_unpack (entry, "{s:i}", "rank", &node.rank) < 0)
            return;
        if (index == total - 1) {
            status_prefix_push (ctx, BLANK);
            node.connector = ELBOW;
        }
        else {
            status_prefix_push (ctx, PIPE);
            node.connector = TEE;
        }
        if (!(node.subtree_ranks = topology_subtree_ranks (entry)))
            log_err_exit ("Unable to get subtree ranks for rank %d",
                          node.rank);
        if (fun (ctx, &node, false, level + 1))
            status_ghostwalk (ctx,
                              entry,
                              level + 1,
                              status,
                              node.connector,
                              fun);
        status_prefix_pop (ctx);
        idset_destroy (node.subtree_ranks);
    }
}

static double time_now (flux_t *h)
{
    return flux_reactor_now (flux_get_reactor (h));
}

static flux_future_t *health_rpc (flux_t *h,
                                  int rank,
                                  const char *wait,
                                  double timeout)
{
    flux_future_t *f;
    double start = time_now (h);
    const char *status;
    int rpc_flags = 0;

    if (wait)
        rpc_flags |= FLUX_RPC_STREAMING;

    if (!(f = flux_rpc (h,
                        "overlay.health",
                        NULL,
                        rank,
                        rpc_flags)))
        return NULL;

    do {
        if (flux_future_wait_for (f, timeout - (time_now (h) - start)) < 0
            || flux_rpc_get_unpack (f, "{s:s}", "status", &status) < 0) {
            flux_future_destroy (f);
            return NULL;
        }
        if (!wait || streq (wait, status))
            break;
        flux_future_reset (f);
    } while (1);

    return f;
}

/* Execute fun() for each online broker in subtree rooted at 'rank'.
 * If fun() returns true, follow tree to the broker's children.
 * If false, don't go down that path.
 */
static int status_healthwalk (struct status *ctx,
                              int rank,
                              int level,
                              enum connector connector,
                              map_f fun)
{
    struct status_node node = {
        .ghost = false,
        .connector = connector,
        .rank = rank
    };
    flux_future_t *f;
    json_t *children;
    const char *errstr;
    int rc = 0;

    monotime (&ctx->start);
    node.subtree_ranks = NULL;

    if (!(f = health_rpc (ctx->h, rank, ctx->wait, ctx->timeout))
        || flux_rpc_get_unpack (f,
                                "{s:i s:s s:f s:o}",
                                "rank", &node.rank,
                                "status", &node.status,
                                "duration", &node.duration,
                                "children", &children) < 0) {
        errstr = future_strerror (f, errno);
        /* RPC failed.
         * An error at level 0 should be fatal, e.g. unknown wait argument,
         * bad rank, timeout.  An error at level > 0 should return -1 so
         * ghostwalk() can be tried (parent hasn't noticed child crash?)
         * and sibling subtrees can be probed.
         */
        if (level == 0)
            log_msg_exit ("%s", errstr);
        printf ("%s%s%s: %s%s\n",
                status_indent (ctx, level),
                connector_string (connector),
                status_getname (ctx, &node),
                errstr,
                status_rpctime (ctx));
        rc = -1;
        goto done;
    }
    node.subtree_ranks = subtree_ranks (ctx->h, node.rank);
    if (fun (ctx, &node, true, level)) {
        if (children) {
            size_t index;
            size_t total;
            json_t *entry;
            struct status_node child = { .ghost = false };
            json_t *topo;

            total = json_array_size (children);
            json_array_foreach (children, index, entry) {
                const char *error = NULL;
                if (json_unpack (entry,
                                 "{s:i s:s s:f s?s}",
                                 "rank", &child.rank,
                                 "status", &child.status,
                                 "duration", &child.duration,
                                 "error", &error) < 0)
                    log_msg_exit ("error parsing child array entry");
                errprintf (&child.error, "%s", error ? error : "");
                if (!(child.subtree_ranks = subtree_ranks (ctx->h, child.rank)))
                      log_err_exit ("Unable to get subtree idset for rank %d",
                                    child.rank);
                if (index == total - 1) {
                    status_prefix_push (ctx, BLANK);
                    connector = child.connector = ELBOW;
                }
                else {
                    status_prefix_push (ctx, PIPE);
                    connector = child.connector = TEE;
                }
                if (fun (ctx, &child, false, level + 1)) {
                    if (streq (child.status, "offline")
                        || streq (child.status, "lost")
                        || status_healthwalk (ctx, child.rank,
                                              level + 1, connector, fun) < 0) {
                        if (optparse_hasopt (ctx->opt, "no-ghost"))
                            topo = NULL;
                        else if ((topo = get_topology (ctx->h)))
                            topo = get_subtree_topology (topo, child.rank);
                        status_ghostwalk (ctx,
                                          topo,
                                          level + 1,
                                          child.status,
                                          connector,
                                          fun);
                    }
                }
                status_prefix_pop (ctx);
                idset_destroy (child.subtree_ranks);
            }
        }
    }
done:
    idset_destroy (node.subtree_ranks);
    flux_future_destroy (f);
    return rc;
}

/* map fun - print the first entry without adornment and stop the walk.
 */
static bool show_top (struct status *ctx,
                      struct status_node *node,
                      bool parent,
                      int level)
{
    status_print_noname (ctx, node, parent, level);
    return false;
}

/* map fun - only follow degraded/partial, but print all non-full nodes.
 */
static bool show_badtrees (struct status *ctx,
                           struct status_node *node,
                           bool parent,
                           int level)
{
    int have_children = false;

    if (streq (node->status, "full"))
        return false;
    if (idset_count (node->subtree_ranks) > 1)
        have_children = true;
    if (parent
        || streq (node->status, "lost")
        || streq (node->status, "offline")
        || (!have_children && ctx->verbose < 2))
        status_print (ctx, node, parent, level);
    return have_children || ctx->verbose >= 2;
}

/* map fun - follow all live brokers and print everything
 */
static bool show_all (struct status *ctx,
                      struct status_node *node,
                      bool parent,
                      int level)
{
    int have_children = false;

    if (idset_count (node->subtree_ranks) > 1)
        have_children = true;
    if (parent
        || streq (node->status, "lost")
        || streq (node->status, "offline")
        || (!have_children && ctx->verbose < 2))
        status_print (ctx, node, parent, level);
    return have_children || ctx->verbose >= 2;
}

static bool validate_wait (const char *wait)
{
    if (wait
        && !streq (wait, "full")
        && !streq (wait, "partial")
        && !streq (wait, "degraded")
        && !streq (wait, "lost")
        && !streq (wait, "offline"))
        return false;
    return true;
}

// N.B. used by both status and trace subcommands
static int status_use_color (optparse_t *p)
{
    const char *when;
    int color;

    if (!(when = optparse_get_str (p, "color", "auto")))
        when = "always";
    if (streq (when, "always"))
        color = 1;
    else if (streq (when, "never"))
        color = 0;
    else if (streq (when, "auto"))
        color = isatty (STDOUT_FILENO) ? 1 : 0;
    else
        log_msg_exit ("Invalid argument to --color: '%s'", when);
    return color;
}

static struct idset *highlight_ranks (struct status *ctx, optparse_t *p)
{
    const char *arg;
    struct idset *ids;
    struct idset *diff = NULL;
    struct idset *allranks = NULL;
    uint32_t size;

    if (flux_get_size (ctx->h, &size) < 0)
        log_err_exit ("flux_get_size");

    if (!(allranks = idset_create (0, IDSET_FLAG_AUTOGROW))
        || idset_range_set (allranks, 0, size - 1) < 0
        || !(ids = idset_create (0, IDSET_FLAG_AUTOGROW)))
        log_err_exit ("Failed to create highlight idset");

    optparse_getopt_iterator_reset (p, "highlight");
    while ((arg = optparse_getopt_next (p, "highlight"))) {
        flux_error_t error;
        struct idset *idset;
        char *result;

        /*  First, attempt to decode as idset. If that fails, assume
         *   a hostlist was provided and lookup using the hostmap.
         */
        if (!(idset = idset_decode (arg))) {
            if (!(result = flux_hostmap_lookup (ctx->h, arg, &error)))
                log_msg_exit ("Error decoding %s: %s", arg, error.text);
            if (!(idset = idset_decode (result)))
                log_err_exit ("Unable to decode %s", arg);
            free (result);
        }

        /*  Accumulate ids in result idset
         */
        if (idset_add (ids, idset) < 0)
            log_err_exit ("Failed to append %s to highlight idset", arg);
        idset_destroy (idset);
    }

    /*  Fail with error if any ranks in returned idset will fall outside
     *   the range 0-size.
     */
    if (!(diff = idset_difference (ids, allranks)))
        log_err_exit ("Failed to determine validity of highlight idset");
    if (idset_count (diff) > 0)
        log_msg_exit ("--highlight: rank%s %s not in set %s",
                      idset_count (diff) > 1 ? "s" : "",
                      idset_encode (diff, IDSET_FLAG_RANGE),
                      idset_encode (allranks, IDSET_FLAG_RANGE));

    idset_destroy (diff);
    idset_destroy (allranks);
    return ids;
}

static int subcmd_status (optparse_t *p, int ac, char *av[])
{
    int rank = optparse_get_int (p, "rank", 0);
    struct status ctx;
    map_f fun;

    ctx.h = builtin_get_flux_handle (p);
    ctx.verbose = optparse_get_int (p, "verbose", 0);
    ctx.color = status_use_color (p);
    ctx.timeout = optparse_get_duration (p, "timeout", default_timeout);
    if (ctx.timeout == 0)
        ctx.timeout = -1.0; // disabled
    ctx.opt = p;
    ctx.wait = optparse_get_str (p, "wait", NULL);
    if (!validate_wait (ctx.wait))
        log_msg_exit ("invalid --wait state");
    if (!(ctx.stack = zlistx_new ()))
        log_msg_exit ("failed to create status zlistx");
    if (!(ctx.highlight = highlight_ranks (&ctx, p)))
        log_msg_exit ("failed to create highlight idset");

    if (optparse_hasopt (p, "summary"))
        fun = show_top;
    else if (optparse_hasopt (p, "down"))
        fun = show_badtrees;
    else
        fun = show_all;

    status_healthwalk (&ctx, rank, 0, NIL, fun);

    zlistx_destroy (&ctx.stack);
    idset_destroy (ctx.highlight);
    return 0;
}

struct overlay_errors {
    flux_t *h;
    double timeout;
    int max_rpcs;
    int active_rpcs;
    struct idset *pending_ranks;
    zhashx_t *errhash;

    flux_watcher_t *idle;
    flux_watcher_t *check;
    flux_watcher_t *prep;
};

// zhashx_destructor_fn footprint
static void idset_destructor (void **item)
{
    if (*item) {
        idset_destroy (*item);
        *item = NULL;
    }
}

static struct idset *errhash_add_entry (zhashx_t *errhash,
                                        const char *error)
{
    struct idset *entry;
    if (!(entry = zhashx_lookup (errhash, error))) {
        if (!(entry = idset_create (0, IDSET_FLAG_AUTOGROW)))
            return NULL;
        if (zhashx_insert (errhash, error, entry) < 0) {
            idset_destroy (entry);
            errno = ENOMEM;
            return NULL;
        }
    }
    return entry;
}

static int errhash_add_one (zhashx_t *errhash,
                            int rank,
                            const char *error)
{
    struct idset *entry;
    if (!(entry = errhash_add_entry (errhash, error)))
        return -1;
    if (idset_set (entry, rank) < 0)
        return -1;
    return 0;
}

static int errhash_add_set (zhashx_t *errhash,
                            const struct idset *ranks,
                            const char *error)
{
    if (ranks && idset_count (ranks) > 0) {
        struct idset *entry;
        if (!(entry = errhash_add_entry (errhash, error))
            || idset_add (entry, ranks) < 0)
            return -1;
    }
    return 0;
}

int errhash_add_children (zhashx_t *errhash, int rank, flux_t *h)
{
    struct idset *ranks = subtree_ranks (h, rank);
    int rc;

    idset_clear (ranks, rank);
    rc = errhash_add_set (errhash, ranks, "lost parent");
    idset_destroy (ranks);
    return rc;
}

static void errhash_future_strerror (zhashx_t *errhash,
                                     flux_t *h,
                                     flux_future_t *f,
                                     int rank)
{
    const char *error = future_strerror (f, errno);
    if (errhash_add_one (errhash, rank, error) < 0
        || errhash_add_children (errhash, rank, h) < 0)
        log_msg_exit ("error adding to error hash");
}

void gather_errors (struct overlay_errors *ctx, int rank);

static void errors_prep_cb (flux_reactor_t *r,
                             flux_watcher_t *w,
                             int revents,
                             void *arg)
{
    struct overlay_errors *ctx = arg;

    /* If no more ranks pending, then disable prep and check watchers.
     * Otherwise, if more RPCs can be sent, start idle watcher so reactor
     * does not block.
     */
    if (idset_count (ctx->pending_ranks) == 0) {
        flux_watcher_stop (ctx->prep);
        flux_watcher_stop (ctx->check);
    }
    else if (ctx->active_rpcs < ctx->max_rpcs)
        flux_watcher_start (ctx->idle);
}

static void errors_check_cb (flux_reactor_t *r,
                             flux_watcher_t *w,
                             int revents,
                             void *arg)
{
    struct overlay_errors *ctx = arg;
    unsigned int rank;

    flux_watcher_stop (ctx->idle);

    /* Allow up to ctx->max_rpcs in flight:
     */
    rank = idset_first (ctx->pending_ranks);
    while (rank != IDSET_INVALID_ID && ctx->active_rpcs < ctx->max_rpcs) {
        gather_errors (ctx, rank);
        rank = idset_next (ctx->pending_ranks, rank);
    }
}

static void gather_errors_cb (flux_future_t *f, void *arg)
{
    flux_t *h = flux_future_get_flux (f);
    struct overlay_errors *ctx = arg;
    json_t *children;
    size_t index;
    json_t *value;
    int rank = flux_rpc_get_nodeid (f);

    ctx->active_rpcs--;

    if (flux_rpc_get_unpack (f, "{s:o}", "children", &children) < 0) {
        errhash_future_strerror (ctx->errhash, h, f, rank);
        flux_future_destroy (f);
        return;
    }

    json_array_foreach (children, index, value) {
        int child_rank;
        const char *status;
        const char *error = NULL;
        if (json_unpack (value,
                         "{s:i s:s s?s}",
                         "rank", &child_rank,
                         "status", &status,
                         "error", &error) < 0)
            log_msg_exit ("error parsing topology");
        if (streq (status, "lost")) {
            if (!error)
                error = "unknown error";
            // record error for child_rank and its children
            if (errhash_add_one (ctx->errhash, child_rank, error) < 0
                || errhash_add_children (ctx->errhash, child_rank, h) < 0)
                log_msg_exit ("error adding to error hash");
        }
        else if (streq (status, "offline")) {
            // report offline only if there is error text
            if (error && strlen (error) > 0) {
                if (errhash_add_one (ctx->errhash, child_rank, error) < 0)
                    log_msg_exit ("error adding to error hash");
            }
        }
        else {
            /*  Send up to max_rpcs, otherwise append rank to set of
             *  pending ranks
             */
            if (ctx->active_rpcs < ctx->max_rpcs)
                gather_errors (ctx, child_rank);
            else if (idset_set (ctx->pending_ranks, child_rank) < 0)
                log_msg_exit ("error adding rank %d to pending ranks",
                              child_rank);
        }
    }

    /* Ensure prep/check watchers are started if there are any pending ranks:
     */
    if (idset_count (ctx->pending_ranks) > 0) {
        flux_watcher_start (ctx->prep);
        flux_watcher_start (ctx->check);
    }

    flux_future_destroy (f);
}

void gather_errors (struct overlay_errors *ctx, int rank)
{
    flux_future_t *f;
    if (!(f = flux_rpc (ctx->h, "overlay.health", NULL, rank, 0))
        || flux_future_then (f, ctx->timeout, gather_errors_cb, ctx) < 0) {
        errhash_future_strerror (ctx->errhash, ctx->h, f, rank);
        flux_future_destroy (f);
        return;
    }
    /* Clear rank from pending ranks if set
     */
    if (idset_clear (ctx->pending_ranks, rank) < 0)
        log_msg_exit ("failed to clear pending rank %d\n", rank);
    ctx->active_rpcs++;
}

void print_errors (flux_t *h, zhashx_t *errhash)
{
    struct idset *r;

    r = zhashx_first (errhash);
    while (r) {
        char *ranks;
        char *hostlist;

        if (!(ranks = idset_encode (r, IDSET_FLAG_RANGE))
            || !(hostlist = flux_hostmap_lookup (h, ranks, NULL)))
            log_err_exit ("converting ranks to hostnames");
        printf ("%s: %s\n",
                hostlist,
                (const char *)zhashx_cursor (errhash));
        free (hostlist);
        free (ranks);

        r = zhashx_next (errhash);
    }
}

static void overlay_errors_destroy (struct overlay_errors *ctx)
{
    if (ctx) {
        int saved_errno = errno;
        zhashx_destroy (&ctx->errhash);
        flux_watcher_destroy (ctx->prep);
        flux_watcher_destroy (ctx->check);
        flux_watcher_destroy (ctx->idle);
        idset_destroy (ctx->pending_ranks);
        free (ctx);
        errno = saved_errno;
    }
}

static struct overlay_errors *overlay_errors_create (flux_t *h, double timeout)
{
    struct overlay_errors *ctx;
    flux_reactor_t *r = flux_get_reactor (h);

    if (!(ctx = malloc (sizeof (*ctx)))
        || !(ctx->errhash = zhashx_new ())
        || !(ctx->pending_ranks = idset_create (0, IDSET_FLAG_AUTOGROW))
        || !(ctx->prep = flux_prepare_watcher_create (r, errors_prep_cb, ctx))
        || !(ctx->check = flux_check_watcher_create (r, errors_check_cb, ctx))
        || !(ctx->idle = flux_idle_watcher_create (r, NULL, NULL))) {
        overlay_errors_destroy (ctx);
        return NULL;
    }
    zhashx_set_destructor (ctx->errhash, idset_destructor);
    ctx->h = h;
    ctx->timeout = timeout;
    ctx->max_rpcs = 512;
    ctx->active_rpcs = 0;
    flux_watcher_start (ctx->prep);
    flux_watcher_start (ctx->check);
    return ctx;
}

static int subcmd_errors (optparse_t *p, int ac, char *av[])
{
    flux_t *h = builtin_get_flux_handle (p);
    struct overlay_errors *ctx = NULL;
    uint32_t size;
    double timeout;

    /* On large systems with a flat tbon, the default 0.5s timeout may be
     * too short because processing the initial JSON response for rank 0
     * can take longer than that. To address this, increase the timeout
     * based on the instance size:
     */
    if (flux_get_size (h, &size) == 0 && size > 2048)
        default_timeout *= (size / 2000.); /* ~2.5s timeout on 10K nodes */

    timeout = optparse_get_duration (p, "timeout", default_timeout);
    if (timeout == 0)
        timeout = -1.0; // disabled

    if (!(ctx = overlay_errors_create (h, timeout)))
        log_msg_exit ("could not create overlay errors context");

    if (idset_set (ctx->pending_ranks, 0) < 0)
        log_msg_exit ("failed to set rank 0 in pending ranks");

    flux_reactor_run (flux_get_reactor (h), 0);
    print_errors (h, ctx->errhash);

    overlay_errors_destroy (ctx);
    flux_close (h);
    json_decref (overlay_topology);
    return 0;
}

static int subcmd_lookup (optparse_t *p, int ac, char *av[])
{
    int optindex = optparse_option_index (p);
    flux_t *h = builtin_get_flux_handle (p);
    flux_error_t error;
    char *s;

    if (optindex != ac - 1)
        log_msg_exit ("single TARGET argument is required");

    if (!(s = flux_hostmap_lookup (h, av[optindex], &error)))
        log_msg_exit ("%s", error.text);

    printf ("%s\n", s);

    free (s);
    return 0;
}

/* Recursively search 'topo' for the parent of 'rank'.
 * Return the parent of rank, or -1 on error.
 */
static int parentof (json_t *topo, int rank)
{
    int parent, child;
    json_t *children;
    size_t index;
    json_t *value;

    if (json_unpack (topo,
                     "{s:i s:o}",
                     "rank", &parent,
                     "children", &children) < 0)
        log_msg_exit ("error parsing topology");

    json_array_foreach (children, index, value) {
        if (json_unpack (value, "{s:i}", "rank", &child) < 0)
            log_msg_exit ("error parsing topology");
        if (child == rank)
            return parent;
    }
    json_array_foreach (children, index, value) {
        if ((parent = parentof (value, rank)) >= 0)
            return parent;
    }
    return -1;
}

/* Lookup instance topology from rank 0, then search for the parent of 'rank'.
 * Return parent or -1 on error.
 */
static int lookup_parentof (flux_t *h, int rank)
{
    json_t *topo = get_topology (h);
    int parent, size;

    /* Validate 'rank'.
     */
    if (json_unpack (topo,
                     "{s:i s:i}",
                     "rank", &parent,
                     "size", &size) < 0)
        log_msg_exit ("error parsing topology");
    if (rank < 0 || rank >= size)
        log_msg_exit ("%d is not a valid rank in this instance", rank);
    if (rank == 0)
        log_msg_exit ("%d has no parent", rank);

    return parentof (topo, rank);
}

static int subcmd_parentof (optparse_t *p, int ac, char *av[])
{
    int optindex = optparse_option_index (p);
    flux_t *h = builtin_get_flux_handle (p);
    int rank;

    if (optindex != ac - 1)
        log_msg_exit ("RANK is required");
    rank = strtoul (av[optindex++], NULL, 10);

    printf ("%d\n", lookup_parentof (h, rank));

    return 0;
}

static int subcmd_disconnect (optparse_t *p, int ac, char *av[])
{
    int optindex = optparse_option_index (p);
    flux_t *h = builtin_get_flux_handle (p);
    int parent = optparse_get_int (p, "parent", -1);
    int rank;
    flux_future_t *f;
    char *endptr;

    if (optindex != ac - 1)
        log_msg_exit ("TARGET is required");
    errno = 0;
    rank = strtol (av[optindex], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || rank < 0) {
        struct hostlist *hostmap = get_hostmap (h);
        if ((rank = hostlist_find (hostmap, av[optindex])) < 0)
            log_msg_exit ("TARGET must be a valid rank or hostname");
    }

    if (parent == -1)
        parent = lookup_parentof (h, rank); // might return -1 (unlikely)

    char *host = strdup (flux_get_hostbyrank (h, rank));
    if (!host)
        log_msg_exit ("out of memory");
    log_msg ("asking %s (rank %d) to disconnect child %s (rank %d)",
             flux_get_hostbyrank (h, parent),
             parent,
             host,
             rank);
    free (host);

    if (!(f = flux_rpc_pack (h,
                             "overlay.disconnect-subtree",
                             parent,
                             0,
                             "{s:i}",
                             "rank", rank)))
        log_err_exit ("overlay.disconnect-subtree");
    if (flux_rpc_get (f, NULL) < 0) {
        log_msg_exit ("overlay.disconnect-subtree: %s",
                      future_strerror (f, errno));
    }
    flux_future_destroy (f);

    return 0;
}

struct typemap {
    const char *s;
    int type;
};

static struct typemap typemap[] = {
    { ">", FLUX_MSGTYPE_REQUEST },
    { "<", FLUX_MSGTYPE_RESPONSE},
    { "e", FLUX_MSGTYPE_EVENT},
    { "c", FLUX_MSGTYPE_CONTROL},
};

static const char *type2str (int type)
{
    int i;

    for (i = 0; i < ARRAY_SIZE (typemap); i++)
        if ((type & typemap[i].type))
            return typemap[i].s;
    return "?";
}

enum {
    TRACE_COLOR_EVENT = FLUX_MSGTYPE_EVENT,
    TRACE_COLOR_REQUEST = FLUX_MSGTYPE_REQUEST,
    TRACE_COLOR_RESPONSE = FLUX_MSGTYPE_RESPONSE,
    TRACE_COLOR_CONTROL = FLUX_MSGTYPE_CONTROL,
    TRACE_COLOR_TIME = 0x10,
    TRACE_COLOR_TIMEBREAK = 0x11,
    TRACE_COLOR_RESPONSE_FAIL = 0x12,
};

static const char *trace_colors[] = {
    [TRACE_COLOR_EVENT]         = ANSI_COLOR_YELLOW,
    [TRACE_COLOR_REQUEST]       = ANSI_COLOR_BOLD_BLUE,
    [TRACE_COLOR_RESPONSE]      = ANSI_COLOR_CYAN,
    [TRACE_COLOR_CONTROL]       = ANSI_COLOR_BOLD,
    [TRACE_COLOR_TIME]          = ANSI_COLOR_GREEN,
    [TRACE_COLOR_TIMEBREAK]     = ANSI_COLOR_BOLD ANSI_COLOR_GREEN,
    [TRACE_COLOR_RESPONSE_FAIL] = ANSI_COLOR_BOLD ANSI_COLOR_RED
};

static const char *months[] = {
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
    NULL
};

static const char *trace_color (struct trace_ctx *ctx, int type)
{
    if (ctx->color)
        return trace_colors[type];
    return "";
}

static const char *trace_color_reset (struct trace_ctx *ctx)
{
    if (ctx->color)
        return ANSI_COLOR_RESET;
    return "";
}


static void trace_print_human_timestamp (struct trace_ctx *ctx,
                                         double timestamp)
{

    if ((time_t)(timestamp/60) == (time_t)(ctx->last_timestamp/60)) {
        /* Within same minute, print offset in sec */
        printf ("%s[%+11.6f]%s ",
                trace_color (ctx, TRACE_COLOR_TIME),
                timestamp - ctx->last_timestamp
                    + fmod (ctx->last_timestamp, 60.),
                trace_color_reset (ctx));
    }
    else {
        struct tm tm;
        time_t t = timestamp;

        localtime_r (&t, &tm);

        /* New minute, print datetime */
        printf ("%s[%s%02d %02d:%02d]%s ",
                trace_color (ctx, TRACE_COLOR_TIMEBREAK),
                months [tm.tm_mon],
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                trace_color_reset (ctx));
        ctx->last_timestamp  = timestamp;
    }
}

static void trace_print_human (struct trace_ctx *ctx,
                               double timestamp,
                               int message_type,
                               int errnum,
                               const char *s,
                               const char *payload_str)
{
    if (message_type == FLUX_MSGTYPE_RESPONSE && errnum > 0)
        message_type = TRACE_COLOR_RESPONSE_FAIL;
    trace_print_human_timestamp (ctx, timestamp);
    printf (" %s%s%s%s%s\n",
            trace_color (ctx, message_type),
            s,
            payload_str ? "\n" : "",
            payload_str ? payload_str : "",
            trace_color_reset (ctx));
}

static void trace_print_timestamp (struct trace_ctx *ctx, double timestamp)
{
    time_t t = timestamp;
    struct tm tm;
    char buf[64] = "";

    localtime_r (&t, &tm);

    strftime (buf, sizeof (buf), "%Y-%m-%dT%T", &tm);
    printf ("%s%s.%.3d%s",
            trace_color (ctx, TRACE_COLOR_TIME),
            buf,
            (int)(1e3 * (timestamp - t)),
            trace_color_reset (ctx));
}

static void trace_print (struct trace_ctx *ctx,
                         double timestamp,
                         int message_type,
                         int errnum,
                         const char *s,
                         const char *payload_str)
{
    if (message_type == FLUX_MSGTYPE_RESPONSE && errnum > 0)
        message_type = TRACE_COLOR_RESPONSE_FAIL;
    trace_print_timestamp (ctx, timestamp);
    printf (" %s%s%s%s%s\n",
            trace_color (ctx, message_type),
            s,
            payload_str ? "\n" : "",
            payload_str ? payload_str : "",
            trace_color_reset (ctx));
}

static void trace_ctx_init (struct trace_ctx *ctx,
                            optparse_t *p,
                            int ac,
                            char *av[])
{
    int n = optparse_option_index (p);

    memset (ctx, 0, sizeof (*ctx));

    if (n < ac - 1) {
        optparse_print_usage (p);
        exit (1);
    }
    if (optparse_hasopt (p, "delta")) {
        if (!optparse_hasopt (p, "human"))
            log_msg_exit ("--delta can only be used with --human");
        ctx->delta = 1;
    }
    ctx->nodeid = optparse_get_int (p, "rank", FLUX_NODEID_ANY);
    ctx->match = FLUX_MATCH_ANY;
    if (n < ac)
        ctx->match.topic_glob = av[n++];
    else
        ctx->match.topic_glob = "*";
    ctx->color = status_use_color (p); // borrowed from status subcommand
    if (optparse_hasopt (p, "type")) {
        const char *arg;

        optparse_getopt_iterator_reset (p, "type");
        ctx->match.typemask = 0;
        while ((arg = optparse_getopt_next (p, "type"))) {
            if (streq (arg, "request"))
                ctx->match.typemask |= FLUX_MSGTYPE_REQUEST;
            else if (streq (arg, "response"))
                ctx->match.typemask |= FLUX_MSGTYPE_RESPONSE;
            else if (streq (arg, "event"))
                ctx->match.typemask |= FLUX_MSGTYPE_EVENT;
            else if (streq (arg, "control"))
                ctx->match.typemask |= FLUX_MSGTYPE_CONTROL;
            else
                log_msg_exit ("valid types: request, response, event, control");
        }
    }
}

static int subcmd_trace (optparse_t *p, int ac, char *av[])
{
    flux_t *h = builtin_get_flux_handle (p);
    flux_future_t *f;
    struct trace_ctx ctx;

    trace_ctx_init (&ctx, p, ac, av);

    if (!(f = flux_rpc_pack (h,
                             "overlay.trace",
                             FLUX_NODEID_ANY,
                             FLUX_RPC_STREAMING,
                             "{s:i s:s s:i s:b}",
                             "typemask", ctx.match.typemask,
                             "topic_glob", ctx.match.topic_glob,
                             "nodeid", ctx.nodeid,
                             "full", optparse_hasopt (p, "full") ? 1 : 0)))
        log_err_exit ("error sending overlay.trace request");
    do {
        double timestamp;
        const char *prefix;
        int rank;
        int type;
        const char *topic;
        int payload_size;
        json_t *payload_json = json_null ();
        const char *payload_str = NULL;
        char *payload_tmp_str = NULL;
        int errnum = 0;
        const char *errstr = NULL;
        char buf[160];

        if (flux_rpc_get_unpack (f,
                                 "{s:F s:s s:i s:i s:s s:i s?o s?i s?s}",
                                 "timestamp", &timestamp,
                                 "prefix", &prefix,
                                 "rank", &rank,
                                 "type", &type,
                                 "topic", &topic,
                                 "payload_size", &payload_size,
                                 "payload", &payload_json,
                                 "errnum", &errnum,
                                 "errstr", &errstr) < 0)
            log_msg_exit ("%s", future_strerror (f, errno));

        if (errnum > 0) {
            if (errstr && strlen (errstr) > 0)
                payload_str = errstr;
        }
        else if (!json_is_null (payload_json)) {
            payload_tmp_str = json_dumps (payload_json, JSON_INDENT(2));
            payload_str = payload_tmp_str;
        }

        char rankstr[16];
        if (rank < 0)
            snprintf (rankstr, sizeof (rankstr), "*");
        else
            snprintf (rankstr, sizeof (rankstr), "%d", rank);

        snprintf (buf,
                  sizeof (buf),
                  "%s %s %s %s [%s]",
                  prefix,
                  rankstr,
                  type2str (type),
                  topic,
                  encode_size (payload_size));

        if (type == FLUX_MSGTYPE_RESPONSE) {
            const char *desc = strerrorname_np (errnum);
            size_t len = strlen (buf);

            if (errnum == 0)
                snprintf (buf + len, sizeof (buf) - len, " success");
            else if (desc && !isdigit (desc[0]))
                snprintf (buf + len, sizeof (buf) - len, " %s", desc);
            else
                snprintf (buf + len, sizeof (buf) - len, " errno %d", errnum);
        }

        if (optparse_hasopt (p, "human"))
            trace_print_human (&ctx, timestamp, type, errnum, buf, payload_str);
        else
            trace_print (&ctx, timestamp, type, errnum, buf, payload_str);
        fflush (stdout);

        free (payload_tmp_str);

        flux_future_reset (f);
    } while (1);
}

int cmd_overlay (optparse_t *p, int argc, char *argv[])
{
    log_init ("flux-overlay");

    if (optparse_run_subcommand (p, argc, argv) != OPTPARSE_SUCCESS)
        exit (1);

    hostlist_destroy (overlay_hostmap);

    return (0);
}

static struct optparse_subcommand overlay_subcmds[] = {
    { "trace",
      "[OPTIONS] [topic-glob]",
      "Trace messages received on overlay network",
      subcmd_trace,
      0,
      trace_opts,
    },
    { "errors",
      "[OPTIONS]",
      "Summarize overlay errors",
      subcmd_errors,
      0,
      errors_opts,
    },
    { "status",
      "[OPTIONS]",
      "Display overlay subtree health status",
      subcmd_status,
      0,
      status_opts,
    },
    { "lookup",
      "[OPTIONS] TARGET",
      "translate rank idset to hostlist or the reverse",
      subcmd_lookup,
      0,
      NULL,
    },
    { "parentof",
      "[OPTIONS] RANK",
      "show the parent of RANK",
      subcmd_parentof,
      0,
      NULL,
    },
    { "disconnect",
      "[OPTIONS] TARGET",
      "disconnect a subtree rooted at TARGET (hostname or rank)",
      subcmd_disconnect,
      0,
      disconnect_opts,
    },
    OPTPARSE_SUBCMD_END
};


int subcommand_overlay_register (optparse_t *p)
{
    optparse_err_t e;

    e = optparse_reg_subcommand (p,
        "overlay",
        cmd_overlay,
        NULL,
        "Manage overlay network",
        0,
        NULL);
    if (e != OPTPARSE_SUCCESS)
        return -1;

    e = optparse_reg_subcommands (optparse_get_subcommand (p, "overlay"),
                                  overlay_subcmds);
    return (e == OPTPARSE_SUCCESS ? 0 : -1);
}

/*
 * vi: ts=4 sw=4 expandtab
 */
