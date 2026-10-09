/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

#define FLUX_SHELL_PLUGIN_NAME "linger"

/* Test plugin that keeps the shell alive past task completion, simulating
 * a non-task process (such as an MPIR tool daemon) that outlives the job's
 * tasks. It takes a shell completion reference at shell.init and releases it
 * after a delay. Used to verify that the exit-timeout watchdog does not fire
 * once all tasks have completed even if the shell remains active.
 *
 * Config: linger = seconds to hold the reference (default 2.0)
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <flux/core.h>
#include <flux/shell.h>

struct linger {
    flux_shell_t *shell;
    flux_watcher_t *timer;
};

static void linger_destroy (struct linger *l)
{
    if (l) {
        int saved_errno = errno;
        flux_watcher_destroy (l->timer);
        free (l);
        errno = saved_errno;
    }
}

static void linger_timeout (flux_reactor_t *r,
                            flux_watcher_t *w,
                            int revents,
                            void *arg)
{
    struct linger *l = arg;
    shell_log ("releasing linger reference");
    if (flux_shell_remove_completion_ref (l->shell, "test::linger") < 0)
        shell_log_errno ("flux_shell_remove_completion_ref");
    flux_watcher_stop (w);
}

static int linger_init (flux_plugin_t *p,
                        const char *topic,
                        flux_plugin_arg_t *args,
                        void *arg)
{
    struct linger *l = arg;
    flux_reactor_t *r = flux_get_reactor (flux_shell_get_flux (l->shell));
    double delay = 2.0;

    (void) flux_plugin_conf_unpack (p, "{s?F}", "linger", &delay);

    if (flux_shell_add_completion_ref (l->shell, "test::linger") < 0)
        return shell_log_errno ("flux_shell_add_completion_ref");
    if (!(l->timer = flux_timer_watcher_create (r,
                                                delay,
                                                0.,
                                                linger_timeout,
                                                l)))
        return shell_log_errno ("flux_timer_watcher_create");
    flux_watcher_start (l->timer);
    return 0;
}

int flux_plugin_init (flux_plugin_t *p)
{
    flux_shell_t *shell = flux_plugin_get_shell (p);
    struct linger *l;

    if (!shell || !(l = calloc (1, sizeof (*l))))
        return -1;
    l->shell = shell;
    flux_plugin_set_name (p, FLUX_SHELL_PLUGIN_NAME);
    if (flux_plugin_aux_set (p, NULL, l, (flux_free_f) linger_destroy) < 0
        || flux_plugin_add_handler (p, "shell.init", linger_init, l) < 0) {
        linger_destroy (l);
        return -1;
    }
    return 0;
}

/*
 * vi: ts=4 sw=4 expandtab
 */
