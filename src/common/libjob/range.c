/************************************************************\
 * Copyright 2018 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <jansson.h>

#include "range.h"

void set_error (json_error_t *error, const char *fmt, ...)
{
    va_list ap;

    if (error) {
        va_start (ap, fmt);
        vsnprintf (error->text, sizeof (error->text), fmt, ap);
        va_end (ap);
    }
}

struct range *create_range (json_t *json_range,
                            json_error_t *error)
{
    struct range *range;
    const char *operator = NULL;
    int64_t min;
    int64_t max = RANGE_MAX;
    int64_t operand = 1;

    if (!(range = calloc (1, sizeof (*range)))) {
        set_error (error, "create_range: Out of memory");
        goto error;
    }
    // allow single integer counts; just creates a degenerate range
    if (json_is_integer (json_range)) {
        min = json_integer_value (json_range);
        if (min < 1) {
            set_error (error, "create_range: count must be >= 1");
            goto error;
        }
        range->min = min;
        range->max = min;
        range->operator = '+';
        range->operand = 1;
        range->current_value = min;
        range->last_value = min;
        return range;
    }
    if (json_unpack_ex(json_range, error, 0,
                       "{s:i, s?i, s?s, s?i}",
                       "min", &min,
                       "max", &max,
                       "operator", &operator,
                       "operand", &operand) < 0) {
        goto error;
    }
    // have to check positivity first before assigning to unsigned ints
    if (min < 1 || max < 1 || operand < 1) {
        set_error (error, "create_range: min, max, and operand must be >= 1");
        goto error;
    }
    range->min = min;
    range->max = max;
    range->operand = operand;
    range->operator = operator ? operator[0] : '+';
    // check validity of operator/operand combination
    switch (range->operator) {
    case '+':
        if (range->operand < 1) {
            set_error (error, "create_range: operand must be >= 1 for addition '+'");
            goto error;
        }
        break;
    case '*':
        if (range->operand < 2) {
            set_error (error, "create_range: operand must be >= 2 for multiplication '*'");
            goto error;
        }
        break;
    case '^':
        if (range->operand < 2) {
            set_error (error, "create_range: operand must be >= 2 for exponentiation '^'");
            goto error;
        }
        if (range->min < 2) {
            set_error (error, "create_range: min must be >= 2 for exponentiation '^'");
            goto error;
        }
        break;
    default:
        set_error (error, "create_range: unknown operator '%c'", range->operator);
        goto error;
    }
    if (range->max < range->min) {
        set_error (error, "create_range: max must be >= min");
        goto error;
    }
    range->current_value = range->min;
    range->last_value = range->max < RANGE_MAX ? 0 : RANGE_MAX;
    return range;
error:
    free (range);
    return NULL; 
}

unsigned int range_first (struct range *range)
{
    range->current_value = range->min;
    return range->current_value;
}

unsigned int range_next (struct range *range)
{
    switch (range->operator) {
        case '+':
            range->current_value += range->operand;
            break;
        case '*':
            range->current_value *= range->operand;
            break;
        case '^': ;
            unsigned int base = range->current_value;
            for (unsigned int i = 1; i < range->operand; ++i) {
                range->current_value *= base;
            }
    }
    if (range->current_value > range->max) {
        range->current_value = RANGE_MAX;
    }
    return range->current_value;
}

unsigned int range_last (struct range *range)
{
    if (range->last_value == 0) {
        if (range->current_value > range->max) {
            range->current_value = range->min;
        }
        while (range->current_value <= range->max) {
            range->last_value = range->current_value;
            range_next (range);
        }
    }
    range->current_value = range->last_value;
    return range->last_value;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
