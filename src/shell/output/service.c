/************************************************************\
 * Copyright 2024 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
\************************************************************/

/* shell std output write service implementation
 *
 * When output is going to the KVS or a single output file, the
 * leader shell implements this "shell-<id>.write" service to which
 * client shell ranks send output (see output/client.c).
 *
 * Clients may send an RFC 24 encoded data event, or a "log" event for
 * propagation of log messages from other job shells.
 *
 * Local task and logging output is not routed through this service
 * code.
 *
 * If there are no remote shells the service is not started. When the
 * service is in use, an 'output.service' completion reference is taken
 * on the job shell to ensure the shell and this service remain active.
 * The reference is dropped once all tasks across all shells have
 * completed, signaled by the shell.tasks-complete callback (see the
 * tasks-complete builtin), which also accounts for any lost shells.
 *
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>

#define FLUX_SHELL_PLUGIN_NAME "output.service"

#include <flux/core.h>
#include <flux/shell.h>

#include "output/output.h"

struct output_service {
    struct shell_output *out;
};

void output_service_destroy (struct output_service *service)
{
    if (service) {
        int saved_errno = errno;
        free (service);
        errno = saved_errno;
    }
}

/* All tasks across all shells have completed (see the tasks-complete
 * builtin), so no more output will be sent from any remote shell. Drop
 * the completion reference that keeps this service and the shell active.
 * This callback is invoked at most once so no re-entry guard is needed.
 */
static int output_service_tasks_complete (flux_plugin_t *p,
                                          const char *topic,
                                          flux_plugin_arg_t *args,
                                          void *arg)
{
    struct output_service *service = arg;

    if (flux_shell_remove_completion_ref (service->out->shell,
                                          "output.service") < 0)
        shell_log_errno ("flux_shell_remove_completion_ref");
    shell_output_decref (service->out);
    return 0;
}

static void output_service_write_cb (flux_t *h,
                                     flux_msg_handler_t *mh,
                                     const flux_msg_t *msg,
                                     void *arg)
{
    struct output_service *service = arg;
    int shell_rank = -1;
    json_t *o;
    const char *type;

    if (flux_request_unpack (msg,
                             NULL,
                             "{s:s s:i s:o}",
                             "name", &type,
                             "shell_rank", &shell_rank,
                             "context", &o) < 0
        || shell_output_write_entry (service->out, type, o) < 0)
        shell_log_errno ("error recording write data for rank %d", shell_rank);
}

static void output_service_write_getcredit_cb (flux_t *h,
                                               flux_msg_handler_t *mh,
                                               const flux_msg_t *msg,
                                               void *arg)
{
    int credits;

    if (flux_request_unpack (msg, NULL, "{s:i}", "credits", &credits) < 0)
        goto error;
    if (flux_respond_pack (h, msg, "{s:i}", "credits", credits) < 0)
        shell_log_errno ("error responding to write-getcredit");
    return;
error:
    if (flux_respond_error (h, msg, errno, NULL) < 0)
        shell_log_errno ("error responding to write-getcredit");
}

struct output_service *output_service_create (struct shell_output *out,
                                              flux_plugin_t *p,
                                              int size)
{
    struct output_service *service;

    if (!(service = calloc (1, sizeof (*service))))
        return NULL;

    /* Nothing to do if there are no remote shells. Return an empty
     * service object.
     */
    if (size == 1)
        return service;

    service->out = out;

    /* Keep the service and shell active until all tasks across all shells
     * have completed, signaled by the shell.tasks-complete callback. The
     * tasks-complete builtin accounts for lost shells, so no shell.lost
     * handler is needed here.
     */
    if (flux_plugin_add_handler (p,
                                 "shell.tasks-complete",
                                 output_service_tasks_complete,
                                 service) < 0
        || flux_shell_add_completion_ref (out->shell, "output.service") < 0
        || flux_shell_service_register (out->shell,
                                        "write",
                                        output_service_write_cb,
                                        service) < 0
        || flux_shell_service_register (out->shell,
                                        "write-getcredit",
                                        output_service_write_getcredit_cb,
                                        service) < 0)
        goto error;

    /* Output service takes a reference on shell output
     */
    shell_output_incref (out);
    return service;
error:
    output_service_destroy (service);
    return NULL;
}

/* vi: ts=4 sw=4 expandtab
 */
