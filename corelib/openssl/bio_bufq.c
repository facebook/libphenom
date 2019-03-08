/*
 * Copyright 2013-present Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "phenom/stream.h"
#include "phenom/openssl.h"
#include <openssl/bio.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define BIO_set_init(b, val) (b)->init = (val)
#define BIO_set_data(b, val) (b)->ptr = (val)
#define BIO_get_data(b) (b)->ptr
#endif

/* Implements an OpenSSL BIO that writes to a phenom bufq */

static int bio_bufq_write(BIO *h, const char *buf, int size)
{
  uint64_t n;
  ph_bufq_t *q = BIO_get_data(h);

  BIO_clear_retry_flags(h);
  if (ph_bufq_append(q, buf, size, &n) != PH_OK) {
    BIO_set_retry_write(h);
    errno = EAGAIN;
    return -1;
  }

  return (int)n;
}

static int bio_bufq_puts(BIO *h, const char *str)
{
  return bio_bufq_write(h, str, strlen(str));
}

static int bio_bufq_read(BIO *h, char *buf, int size)
{
  ph_unused_parameter(h);
  ph_unused_parameter(buf);
  ph_unused_parameter(size);
  errno = ENOSYS;
  return -1;
}

static long bio_bufq_ctrl(BIO *h, int cmd, // NOLINT(runtime/int)
    long arg1, void *arg2)                 // NOLINT(runtime/int)
{
  ph_unused_parameter(h);
  ph_unused_parameter(cmd);
  ph_unused_parameter(arg1);
  ph_unused_parameter(arg2);
  return 1;
}

static void bio_bufq_clear(BIO *h)
{
  BIO_set_init(h, 0);
  BIO_set_data(h, NULL);
  BIO_clear_flags(h, ~0);
}

static int bio_bufq_new(BIO *h)
{
  bio_bufq_clear(h);
  return 1;
}

static int bio_bufq_free(BIO *h)
{
  if (!h) {
    return 0;
  }

  bio_bufq_clear(h);
  return 1;
}

BIO *ph_openssl_bio_wrap_bufq(ph_bufq_t *bufq)
{
  static BIO_METHOD *bm;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  static BIO_METHOD old_meth = {
    // See bio_stream.c
    81 | BIO_TYPE_SOURCE_SINK,
    "phenom-bufq",
    bio_bufq_write,
    bio_bufq_read,
    bio_bufq_puts,
    NULL, /* no gets */
    bio_bufq_ctrl,
    bio_bufq_new,
    bio_bufq_free,
    NULL, /* no callback ctrl */
  };

  bm = &old_meth;
#else
  if (!bm) {
    bm = BIO_meth_new(81/*see bio_stream.c*/ | BIO_TYPE_SOURCE_SINK,
                      "phenom-bufq");
    if (!bm) {
      return NULL;
    }

    BIO_meth_set_write(bm, bio_bufq_write);
    BIO_meth_set_read(bm, bio_bufq_read);
    BIO_meth_set_puts(bm, bio_bufq_puts);
    BIO_meth_set_ctrl(bm, bio_bufq_ctrl);
    BIO_meth_set_create(bm, bio_bufq_new);
    BIO_meth_set_destroy(bm, bio_bufq_free);
  }
#endif

  BIO *h = BIO_new(bm);
  if (!h) {
    return NULL;
  }

  BIO_set_data(h, bufq);
  BIO_set_init(h, 1);

  return h;
}


/* vim:ts=2:sw=2:et:
 */

