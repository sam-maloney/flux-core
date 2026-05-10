/************************************************************\
 * Copyright 2014 Lawrence Livermore National Security, LLC
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
#include <stdbool.h>
#include <zmq.h>
#include <errno.h>
#include <stdio.h>
#include <flux/core.h>

#include "src/common/libzmqutil/msg_zsock.h"
#include "src/common/libtap/tap.h"
#include "ccan/str/str.h"

#include "sockopt.h"

static void *zctx;

void check_sendzsock (void)
{
    void *zsock[2] = { NULL, NULL };
    flux_msg_t *msg, *msg2;
    const char *topic;
    int type;
    const char *uri = "inproc://test";

    ok ((zsock[0] = zmq_socket (zctx, ZMQ_PAIR)) != NULL
        && zmq_bind (zsock[0], uri) == 0
        && (zsock[1] = zmq_socket (zctx, ZMQ_PAIR)) != NULL
        && zmq_connect( zsock[1], uri) == 0,
        "got inproc socket pair");

    if (zsetsockopt_int (zsock[0], ZMQ_LINGER, 5) < 0
        || zsetsockopt_int (zsock[1], ZMQ_LINGER, 5) < 0)
        BAIL_OUT ("could not set ZMQ_LINGER socket option");

    ok ((msg = flux_msg_create (FLUX_MSGTYPE_REQUEST)) != NULL
            && flux_msg_set_topic (msg, "foo.bar") == 0,
        "created test message");

    /* corner case tests */
    ok (zmqutil_msg_send (NULL, msg) < 0 && errno == EINVAL,
        "zmqutil_msg_send returns < 0 and EINVAL on dest = NULL");
    ok (zmqutil_msg_send_ex (NULL, msg, true) < 0 && errno == EINVAL,
        "zmqutil_msg_send_ex returns < 0 and EINVAL on dest = NULL");
    ok (zmqutil_msg_recv (NULL) == NULL && errno == EINVAL,
        "zmqutil_msg_recv returns NULL and EINVAL on dest = NULL");

    ok (zmqutil_msg_send (zsock[1], msg) == 0,
        "zmqutil_msg_send works");
    ok ((msg2 = zmqutil_msg_recv (zsock[0])) != NULL,
        "zmqutil_msg_recv works");
    ok (flux_msg_get_type (msg2, &type) == 0 && type == FLUX_MSGTYPE_REQUEST
            && flux_msg_get_topic (msg2, &topic) == 0
            && streq (topic, "foo.bar")
            && flux_msg_has_payload (msg2) == false,
        "decoded message looks like what was sent");
    flux_msg_destroy (msg2);

    /* Send it again.
     */
    ok (zmqutil_msg_send (zsock[1], msg) == 0,
        "try2: zmqutil_msg_send works");
    ok ((msg2 = zmqutil_msg_recv (zsock[0])) != NULL,
        "try2: zmqutil_msg_recv works");
    ok (flux_msg_get_type (msg2, &type) == 0 && type == FLUX_MSGTYPE_REQUEST
            && flux_msg_get_topic (msg2, &topic) == 0
            && streq (topic, "foo.bar")
            && flux_msg_has_payload (msg2) == false,
        "try2: decoded message looks like what was sent");
    flux_msg_destroy (msg2);
    flux_msg_destroy (msg);

    zmq_close (zsock[0]);
    zmq_close (zsock[1]);
}

/* Exercise the zerocopy path with a payload larger than ZEROCOPY_THRESHOLD */
void check_sendzsock_large (void)
{
    void *zsock[2] = { NULL, NULL };
    flux_msg_t *msg, *msg2;
    const char *uri = "inproc://test-large";
    const size_t paysize = 128 * 1024;
    void *payload;
    const void *payload2;
    size_t payload2_size;
    int type;

    ok ((zsock[0] = zmq_socket (zctx, ZMQ_PAIR)) != NULL
        && zmq_bind (zsock[0], uri) == 0
        && (zsock[1] = zmq_socket (zctx, ZMQ_PAIR)) != NULL
        && zmq_connect (zsock[1], uri) == 0,
        "large: got inproc socket pair");

    if (zsetsockopt_int (zsock[0], ZMQ_LINGER, 5) < 0
        || zsetsockopt_int (zsock[1], ZMQ_LINGER, 5) < 0)
        BAIL_OUT ("could not set ZMQ_LINGER socket option");

    ok ((payload = malloc (paysize)) != NULL,
        "large: allocated 64K payload");
    memset (payload, 0xab, paysize);

    ok ((msg = flux_msg_create (FLUX_MSGTYPE_REQUEST)) != NULL
        && flux_msg_set_topic (msg, "big.payload") == 0
        && flux_msg_set_payload (msg, payload, paysize) == 0,
        "large: created message with 64K payload");
    free (payload);

    ok (zmqutil_msg_send (zsock[1], msg) == 0,
        "large: zmqutil_msg_send works");

    /* Release our reference before recv:
     * zerocopy should keep msg alive via incref
     */
    flux_msg_destroy (msg);

    ok ((msg2 = zmqutil_msg_recv (zsock[0])) != NULL,
        "large: zmqutil_msg_recv works");
    ok (flux_msg_get_type (msg2, &type) == 0 && type == FLUX_MSGTYPE_REQUEST,
        "large: decoded message has correct type");
    ok (flux_msg_get_payload (msg2, &payload2, &payload2_size) == 0
        && payload2_size == paysize,
        "large: decoded payload has correct size");

    /* Verify payload content */
    bool payload_ok = true;
    const uint8_t *p = payload2;
    for (size_t i = 0; i < payload2_size; i++) {
        if (p[i] != 0xab) {
            payload_ok = false;
            break;
        }
    }
    ok (payload_ok, "large: decoded payload content is correct");

    flux_msg_destroy (msg2);

    zmq_close (zsock[0]);
    zmq_close (zsock[1]);
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    if (!(zctx = zmq_ctx_new ()))
        BAIL_OUT ("could not create zeromq context");

    check_sendzsock ();
    check_sendzsock_large ();

    zmq_ctx_term (zctx);

    done_testing();
    return (0);
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

