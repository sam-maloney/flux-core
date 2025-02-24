/************************************************************\
 * Copyright 2019 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* job shell jobspec */
#define FLUX_SHELL_PLUGIN_NAME NULL

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <flux/core.h>
#include <jansson.h>
#include "ccan/str/str.h"

#include "jobspec.h"
#include "info.h"
#include "rcalc.h"

void set_error (json_error_t *error, const char *fmt, ...)
{
    va_list ap;

    if (error) {
        va_start (ap, fmt);
        vsnprintf (error->text, sizeof (error->text), fmt, ap);
        va_end (ap);
    }
}

void jobspec_destroy (struct jobspec *job)
{
    if (job) {
        /*  refcounts were incremented on environment, options */
        json_decref (job->environment);
        json_decref (job->options);
        json_decref (job->jobspec);
        free (job);
    }
}

int jobspec_parse (struct shell_info *info, json_error_t *error)
{
    struct jobspec *job = info->jobspec;
    rcalc_t *r = info->rcalc;

    if (job->environment && !json_is_object (job->environment)) {
        set_error (error, "attributes.system.environment is not object type");
        goto error;
    }
    /* Ensure that shell options and environment are never NULL, so a shell
     * component or plugin may set a new option or environment var.
     */
    if ((!job->options && !(job->options = json_object ()))
        || (!job->environment && !(job->environment = json_object ()))) {
        set_error (error, "unable to create empty jobspec options/environment");
        goto error;
    }

    /* Store resource counts from R
     */
    job->slot_count = rcalc_total_ntasks (r);
    job->cores_per_slot = rcalc_total_cores (r) / job->slot_count;
    /* Check whether nodes were explicitly specified in jobspec, as determined
     * and stored in lookup_jobspec_get () of info.c
     */
    if (job->node_count) {
        job->node_count = rcalc_total_nodes (r);
        job->slots_per_node = job->slot_count / job->node_count;
    }
    else {
        job->node_count = -1;
        job->slots_per_node = -1;
    }

    /* Set job->task_count
     */
    if (json_object_size (job->count) != 1) {
        set_error (error, "tasks count must have exactly one key set");
        goto error;
    }
    if (json_unpack (job->count, "{s:i}", "total", &job->task_count) < 0) {
        int per_slot;
        if (json_unpack (job->count, "{s:i}", "per_slot", &per_slot) < 0) {
            set_error (error, "Unable to parse tasks count");
            goto error;
        }
        if (per_slot != 1) {
            set_error (error, "per_slot count: expected 1 got %d", per_slot);
            goto error;
        }
        job->task_count = job->slot_count;
    }

    /* Check command
     */
    if (!json_is_array (job->command)) {
        set_error (error, "Malformed command entry");
        goto error;
    }
    return 0;
error:
    return -1;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
