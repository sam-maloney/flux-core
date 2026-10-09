/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

/* tasks-complete.c - signal when all tasks in the job have completed
 *
 * Each shell reports to shell rank 0 when its local tasks have all
 * completed, which occurs on the shell.finish callback. The leader
 * tracks the set of shells that have not yet reported, and when the
 * set becomes empty, invokes the shell.tasks-complete plugin callback
 * once. A lost shell is removed from the set since it will never report,
 * so the callback fires even if a shell is lost.
 *
 * Consumers register a shell.tasks-complete handler to act once all tasks
 * have completed, regardless of non-task processes (e.g. rexec-launched
 * tool daemons) that may keep the shell alive.
 */
#define FLUX_SHELL_PLUGIN_NAME "tasks-complete"

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <flux/core.h>
#include <flux/shell.h>
#include <flux/idset.h>

#include "internal.h"
#include "builtins.h"

struct tasks_complete {
    flux_shell_t *shell;
    int shell_rank;
    /* Leader only: shells that have not yet reported completion. Destroyed
     * and set NULL when the callback fires, which also prevents the callback
     * from being invoked more than once.
     */
    struct idset *active_shells;
};

static void tasks_complete_destroy (struct tasks_complete *tc)
{
    if (tc) {
        int saved_errno = errno;
        idset_destroy (tc->active_shells);
        free (tc);
        errno = saved_errno;
    }
}

/* Leader: note that shell_rank has completed. When the last outstanding
 * shell reports, invoke the shell.tasks-complete callback exactly once.
 */
static void leader_report (struct tasks_complete *tc, int shell_rank)
{
    if (!tc->active_shells) // already fired (or not the leader)
        return;
    idset_clear (tc->active_shells, shell_rank);
    if (idset_count (tc->active_shells) == 0) {
        idset_destroy (tc->active_shells);
        tc->active_shells = NULL;
        shell_debug ("all shells report tasks complete");
        flux_shell_plugstack_call (tc->shell, "shell.tasks-complete", NULL);
    }
}

/* Leader service: a follower shell reports completion of its local tasks.
 */
static void tasks_complete_cb (flux_t *h,
                               flux_msg_handler_t *mh,
                               const flux_msg_t *msg,
                               void *arg)
{
    struct tasks_complete *tc = arg;
    int shell_rank;

    if (flux_request_unpack (msg,
                             NULL,
                             "{s:i}",
                             "shell_rank", &shell_rank) < 0) {
        shell_log_errno ("failed to unpack tasks-complete request");
        return;
    }
    leader_report (tc, shell_rank);
}

/* Leader: a lost shell will never report, so remove it from the outstanding
 * set. The lost shell independently raises a job exception, so this does not
 * mask the failure.
 */
static int tasks_complete_lost (flux_plugin_t *p,
                                const char *topic,
                                flux_plugin_arg_t *args,
                                void *arg)
{
    struct tasks_complete *tc = arg;
    int shell_rank;

    if (flux_plugin_arg_unpack (args,
                                FLUX_PLUGIN_ARG_IN,
                                "{s:i}",
                                "shell_rank", &shell_rank) < 0)
        return shell_log_errno ("shell.lost: unpack of shell_rank failed");
    leader_report (tc, shell_rank);
    return 0;
}

/* All ranks: local tasks have all completed. The leader records its own
 * completion directly; followers report to the leader.
 */
static int tasks_complete_finish (flux_plugin_t *p,
                                  const char *topic,
                                  flux_plugin_arg_t *args,
                                  void *arg)
{
    struct tasks_complete *tc;
    flux_future_t *f;

    if (!(tc = flux_plugin_aux_get (p, "tasks-complete")))
        return -1;

    if (tc->shell_rank == 0) {
        leader_report (tc, 0);
        return 0;
    }
    if (!(f = flux_shell_rpc_pack (tc->shell,
                                   "tasks-complete",
                                   0,
                                   FLUX_RPC_NORESPONSE,
                                   "{s:i}",
                                   "shell_rank", tc->shell_rank)))
        return shell_log_errno ("failed to send tasks-complete request");
    flux_future_destroy (f);
    return 0;
}

static int tasks_complete_init (flux_plugin_t *p,
                                const char *topic,
                                flux_plugin_arg_t *args,
                                void *arg)
{
    flux_shell_t *shell = flux_plugin_get_shell (p);
    struct tasks_complete *tc;
    int shell_size;

    if (!shell || !(tc = calloc (1, sizeof (*tc))))
        return -1;
    tc->shell = shell;
    if (flux_shell_info_unpack (shell,
                                "{s:i s:i}",
                                "rank", &tc->shell_rank,
                                "size", &shell_size) < 0
        || flux_plugin_aux_set (p,
                                "tasks-complete",
                                tc,
                                (flux_free_f) tasks_complete_destroy) < 0) {
        tasks_complete_destroy (tc);
        return shell_log_errno ("plugin setup failed");
    }
    if (tc->shell_rank != 0)
        return 0;

    /* Leader: track the set of outstanding shells, including itself.
     */
    if (!(tc->active_shells = idset_create (shell_size, 0))
        || idset_range_set (tc->active_shells, 0, shell_size - 1) < 0) {
        return shell_log_errno ("failed to create idset");
    }

    /* With more than one shell, collect the reports from followers
     * and account for lost shells
     */
    if (shell_size > 1) {
        if (flux_shell_service_register (shell,
                                         "tasks-complete",
                                         tasks_complete_cb,
                                         tc) < 0)
            return shell_log_errno ("service register failed");
        if (flux_plugin_add_handler (p,
                                     "shell.lost",
                                     tasks_complete_lost,
                                     tc) < 0)
            return shell_log_errno ("failed to add lost handler");
    }
    return 0;
}

struct shell_builtin builtin_tasks_complete = {
    .name = FLUX_SHELL_PLUGIN_NAME,
    .init = tasks_complete_init,
    .finish = tasks_complete_finish,
};

/*
 * vi: ts=4 sw=4 expandtab
 */
