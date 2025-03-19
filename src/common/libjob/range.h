/************************************************************\
 * Copyright 2018 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* A range is an RFC14 resource range defined by min/max/operator/operand.
 */


#ifndef FLUX_RANGE_H
#define FLUX_RANGE_H

#include <jansson.h>

#include <flux/idset.h>

#define RANGE_MAX (UINT_MAX)

struct range {
    unsigned int min;
    unsigned int max;
    char operator;
    unsigned int operand;
    unsigned int current_value;
    unsigned int last_value;
};

/* Create a range from a json object.
 * Returns range on success, or NULL on failure with error->text set.
 */
struct range *create_range (json_t *json_range,
                            json_error_t *error);

/* Return the first (min) value in the range.
 */
unsigned int range_first (struct range *range);

/* Return the next value in the range.
 * Returns RANGE_MAX if value goes above the max.
 */
unsigned int range_next (struct range *range);

/* Returns the last value in the range.
 * N.B. this is not necessarily equal to the value stored in max.
 * The value is computed on first call and then stored.
 */
unsigned int range_last (struct range *range);

#endif /* !FLUX_RANGE_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
