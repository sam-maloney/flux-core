/************************************************************\
 * Copyright 2014 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_JJ_RANGE_H
#define HAVE_JJ_RANGE_H 1

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <jansson.h>
#include <stdbool.h>
#include "count.h"

#ifndef JJ_ERROR_TEXT_LENGTH
#define JJ_ERROR_TEXT_LENGTH 256
#endif

struct jj_range_counts {
    struct count *nnodes;    /* total number of nodes requested */
    struct count *nslots;    /* total number of slots requested */
    struct count *slot_size; /* number of cores per slot        */
    struct count *slot_gpus; /* number of gpus per slot        */

    bool exclusive;  /* enable node exclusive allocation if available */

    double duration; /* attributes.system.duration if set */

    char error[JJ_ERROR_TEXT_LENGTH]; /* On error, contains error description */
};

/*  Parse jobspec from json string `spec`, return resource request summary
 *   in `counts` on success.
 *  Returns 0 on success and -1 on failure with errno set and jj->error[]
 *   with an error message string.
 */
int jj_range_get_counts (const char *spec, struct jj_range_counts *counts);

/*  Identical to jj_get_counts, but take json_t  */
int jj_range_get_counts_json (json_t *jobspec, struct jj_range_counts *counts);

/*  Destroy jj_range_counts struct */
void jj_range_destroy (struct jj_range_counts *counts);

#endif /* !HAVE_JJ_RANGE_H */
