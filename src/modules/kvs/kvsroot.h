/************************************************************\
 * Copyright 2015 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef _FLUX_KVS_KVSROOT_H
#define _FLUX_KVS_KVSROOT_H

#include <stdbool.h>
#include <flux/core.h>

#include "cache.h"
#include "kvstxn.h"
#include "waitqueue.h"
#include "src/common/libutil/blobref.h"
#include "src/common/libccan/ccan/list/list.h"
#include "src/common/libczmqcontainers/czmq_containers.h"

typedef struct kvsroot_mgr kvsroot_mgr_t;

struct kvsroot {
    char *ns_name;
    bool is_primary;
    uint32_t owner;
    int seq;
    char ref[BLOBREF_MAX_STRING_SIZE];
    kvstxn_mgr_t *ktm;
    zhash_t *transaction_requests;
    zlist_t *wait_version_list;
    double last_update_time;
    int flags;
    bool remove;
    bool setroot_pause;
    struct flux_msglist *setroot_queue;
    struct list_node work_queue_node;
};

/* return -1 on error, 0 on success, 1 on success & to stop iterating */
typedef int (*kvsroot_root_f)(struct kvsroot *root, void *arg);

/* flux_t optional, if NULL logging will go to stderr */
/* void *arg passed as arg value to kvstxn_mgr_create() internally */
kvsroot_mgr_t *kvsroot_mgr_create (flux_t *h, void *arg);

void kvsroot_mgr_destroy (kvsroot_mgr_t *krm);

int kvsroot_mgr_root_count (kvsroot_mgr_t *krm);

struct kvsroot *kvsroot_mgr_create_root (kvsroot_mgr_t *krm,
                                         struct cache *cache,
                                         const char *hash_name,
                                         const char *ns,
                                         uint32_t owner,
                                         int flags);

int kvsroot_mgr_remove_root (kvsroot_mgr_t *krm, const char *ns);

/* returns NULL if not found */
struct kvsroot *kvsroot_mgr_lookup_root (kvsroot_mgr_t *krm,
                                         const char *ns);

/* safe lookup, will return NULL if root in process of being removed,
 * i.e. remove flag set to true */
struct kvsroot *kvsroot_mgr_lookup_root_safe (kvsroot_mgr_t *krm,
                                              const char *ns);

int kvsroot_mgr_iter_roots (kvsroot_mgr_t *krm, kvsroot_root_f cb, void *arg);

/* Convenience functions on struct kvsroot
 */

int kvsroot_save_transaction_request (struct kvsroot *root,
                                      const flux_msg_t *request,
                                      const char *name);

void kvsroot_setroot (kvsroot_mgr_t *krm,
                      struct kvsroot *root,
                      const char *root_ref,
                      int root_seq);

int kvsroot_check_user (kvsroot_mgr_t *krm,
                        struct kvsroot *root,
                        struct flux_msg_cred cred);

#endif /* !_FLUX_KVS_KVSROOT_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
