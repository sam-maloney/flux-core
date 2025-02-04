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
#include <limits.h>
#include <flux/core.h>
#include <flux/shell.h>
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

struct resource_range {
    int min;
    int max;
    char operator;
    int operand;
};

struct resource_range *create_resource_range(json_t *json_range,
                                             json_error_t *error)
{    
    json_error_t loc_error;
    struct resource_range *range = NULL;

    if (!(range = calloc (1, sizeof (*range)))) {
        set_error (error, "create_resource_range: Out of memory");
    }

    // set defaults for optional fields
    range->max = INT_MAX;
    range->operator = '+';
    range->operand = 1;

    if (json_is_integer (json_range)) {
        range->min = json_integer_value (json_range);
        range->max = range->min;
        return range;
    }

    const char *operator = NULL;
    if (json_unpack_ex(json_range, &loc_error, 0,
                       "{s:i, s?i, s?s, s?i}",
                       "min", &range->min,
                       "max", &range->max,
                       "operator", &operator,
                       "operand", &range->operand) < 0) {
        set_error (error, "create_resource_range: %s", loc_error.text);
        goto error;
    }

    if (operator) {
        range->operator = operator[0];
    }

    switch (range->operator) {
        case '+':
            if (range->operand < 1) {
                set_error (error, "create_resource_range: '+' operand must be >= 1");
                goto error;
            }
            break;
        case '*':
            if (range->operand < 2) {
                set_error (error, "create_resource_range: '*' operand must be >= 2");
                goto error;
            }
            break;
        case '^':
            if (range->operand < 2) {
                set_error (error, "create_resource_range: '^' operand must be >= 2");
                goto error;
            }
            break;
        default:
            set_error (error, "create_resource_range: unknown operator %c", range->operator);
            goto error;
    }

    return range;

error:
    free (range);
    return NULL; 
}

static int resolve_slot_range(struct shell_info *info,
                              json_t *slot_json,
                              json_t *core_json,
                              json_error_t *error)
{
//    int total_nodes = rcalc_total_nodes (info->rcalc);
//    int total_cores = rcalc_total_cores (info->rcalc);
    int slot_count = 0;

    struct resource_range *slot_range = create_resource_range (slot_json, error);
    struct resource_range *core_range = create_resource_range (core_json, error);

    fprintf(stderr, "slot range is [%d, %d, %c, %d]\n", slot_range->min,
                                                        slot_range->max,
                                                        slot_range->operator,
                                                        slot_range->operand);
    fprintf(stderr, "core range is [%d, %d, %c, %d]\n", core_range->min,
                                                        core_range->max,
                                                        core_range->operator,
                                                        core_range->operand);

    int i = slot_range->min;
    while (i <= slot_range->max) {


        switch (slot_range->operator) {
            case '+':
                i += slot_range->operand;
                break;
            case '*':
                i *= slot_range->operand;
                break;
            case '^':
                int base = i;
                for (int j = 1; j < slot_range->operand; ++j) {
                    i *= base;
                }
                break;
            default:
                set_error (error, "resolve_slot_range: unknown operator %c", slot_range->operator);
                return -1;
        }
    }

    free (slot_range);
    free (core_range);

    return slot_count;
}

static int recursive_parse_helper (struct shell_info *info,
                                  json_t *curr_resource,
                                  json_error_t *error,
                                  int level,
                                  int multiplier,
                                  json_t *slot_range)
{
    struct jobspec *job = info->jobspec;
    rcalc_t *r = info->rcalc;
    size_t index;
    json_t *value;
    json_error_t loc_error;
    size_t size = json_array_size (curr_resource);
    const char *type;
    json_t *count;
    json_t *with;

    if (size == 0) {
        set_error (error, "Malformed jobspec: resource entry is not a list");
        return -1;
    }

    json_array_foreach (curr_resource, index, value) {
        if (value == NULL) {
            set_error (error, "level %d: missing", level);
            return -1;
        }
        with = NULL;
        /* For jobspec version 1, expect exactly one array element per level.
         */
        if (json_unpack_ex (value, &loc_error, 0,
                            "{s:s s:o s?o}",
                            "type", &type,
                            "count", &count,
                            "with", &with) < 0) {
            set_error (error, "level %d: %s", level, loc_error.text);
            return -1;
        }

        if (streq (type, "node")) {
            if (job->slot_count > 0) {
                set_error (error, "node resource encountered after slot resource");
                return -1;
            }
            if (job->cores_per_slot > 0) {
                set_error (error, "node resource encountered after core resource");
                return -1;
            }
            if (job->node_count > 0) {
                set_error (error, "node resource encountered after node resource");
                return -1;
            }

            job->node_count = rcalc_total_nodes (r);
            multiplier = job->node_count;
        } else if (streq (type, "slot")) {
            if (job->cores_per_slot > 0) {
                set_error (error, "slot resource encountered after core resource");
                return -1;
            }
            if (job->slot_count > 0) {
                set_error (error, "slot resource encountered after slot resource");
                return -1;
            }
            if (json_is_integer (count)) {
                job->slot_count = multiplier * json_integer_value (count);
            } else {
                slot_range = count;
            }

            // Check if we already encountered the `node` resource
            if (job->node_count > 0) {
                // N.B.: with a strictly enforced ordering of node then slot
                // (with arbitrary non-core resources in between)
                // the slots_per_node will always be a perfectly round integer
                // (i.e., job->slot_count % job->node_count == 0)
                job->slots_per_node = job->slot_count / job->node_count;
            }
        } else if (streq (type, "core")) {
            if (job->slot_count < 1 && !slot_range) {
                set_error (error, "core resource encountered before slot resource");
                return -1;
            }
            if (job->cores_per_slot > 0) {
                set_error (error, "core resource encountered after core resource");
                return -1;
            }

            if (slot_range) {
                job->slot_count = resolve_slot_range(info, slot_range, count, error);
                if (job->slot_count < 0) {
                    return -1;
                } 
            } else {
                job->cores_per_slot = rcalc_total_cores (r) / job->slot_count;
            }
            // N.B.: despite having found everything we were looking for (i.e.,
            // node, slot, and core resources), we have to keep recursing to
            // make sure their aren't additional erroneous node/slot/core
            // resources in the jobspec
        }

        if (with != NULL) {
            if (recursive_parse_helper (info,
                                        with,
                                        error,
                                        level+1,
                                        multiplier,
                                        slot_range)
                < 0) {
                return -1;
            }
        }

        if (streq (type, "node")) {
            if ((job->slot_count <= 0) || (job->cores_per_slot <= 0)) {
                set_error (error,
                           "node encountered without slot&core below it");
                return -1;
            }
        } else if (streq (type, "slot")) {
            if (job->cores_per_slot <= 0) {
                set_error (error, "slot encountered without core below it");
                return -1;
            }
        }
    }
    return 0;
}

/* This function requires that the jobspec resource ordering is the same as the
 * ordering specified in V1, but it allows additional resources before and in
 * between the V1 resources (i.e., node, slot, and core).  In shorthand, it
 * requires that the jobspec follows the form ...->[node]->...->slot->...->core.
 * Where `node` is optional, and `...` represents any non-V1
 * resources. Additionally, this function also allows multiple resources at any
 * level, as long as there is only a single node, slot, and core within the
 * entire jobspec.
 */
static int recursive_parse_jobspec_resources (struct shell_info *info,
                                              json_error_t *error)
{
    struct jobspec *job = info->jobspec;

    if (job->resources == NULL) {
        set_error (error, "jobspec top-level resources empty");
        return -1;
    }

    // Set node-related values to -1 ahead of time, if the recursive descent
    // encounters node in the jobspec, it will overwrite these values
    job->slots_per_node = -1;
    job->node_count = -1;

    int rc = recursive_parse_helper (info, job->resources, error, 0, 1, NULL);

    if ((rc == 0) && (job->cores_per_slot < 1)) {
        set_error (error, "Missing core resource");
        return -1;
    }
    return rc;

}

int jobspec_parse (struct shell_info *info, json_error_t *error)
{
    struct jobspec *job = info->jobspec;

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

    if (recursive_parse_jobspec_resources (info, error) < 0) {
        // recursive_parse_jobspec_resources calls set_error
        goto error;
    }

    /* Set job->task_count
     */
    if (json_unpack_ex (job->tasks, NULL, 0,
                        "[{s:{s:i}}]",
                        "count", "total", &job->task_count) < 0) {
        int per_slot;
        if (json_unpack_ex (job->tasks, NULL, 0,
                            "[{s:{s:i}}]",
                            "count", "per_slot", &per_slot) < 0) {
            set_error (error, "Unable to parse task count");
            goto error;
        }
        if (per_slot != 1) {
            set_error (error, "per_slot count: expected 1 got %d", per_slot);
            goto error;
        }
        job->task_count = job->slot_count;
    }
    /* Get command
     */
    if (json_unpack_ex (job->tasks, NULL, 0,
                        "[{s:o}]",
                        "command", &job->command) < 0) {
        set_error (error, "Unable to parse command");
        goto error;
    }
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
