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
#include "phenom/log.h"
#include "phenom/openssl.h"
#include <openssl/bio.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define BIO_set_init(b, val) (b)->init = (val)
#define BIO_set_data(b, val) (b)->ptr = (val)
#define BIO_get_data(b) (b)->ptr
#endif

/* Implements an OpenSSL BIO that invokes phenom streams */

static bool should_retry(ph_stream_t *stm)
{
  switch (ph_stm_errno(stm)) {
    case EAGAIN:
    case EINTR:
    case EINPROGRESS:
      return true;
    default:
      return false;
  }
}

static void bio_stm_clear(BIO *h)
{
  BIO_set_init(h, 0);
  BIO_set_data(h, NULL);
  BIO_clear_flags(h, ~0);
}

static int bio_stm_write(BIO *h, const char *buf, int size)
{
  uint64_t nwrote;
  ph_stream_t *stm = BIO_get_data(h);

  if (buf == NULL || size == 0 || stm == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(h);
  if (ph_stm_write(stm, buf, size, &nwrote)) {
    return (int)nwrote;
  }

  if (should_retry(stm)) {
    BIO_set_retry_write(h);
  }

  return -1;
}

static int bio_stm_puts(BIO *h, const char *str)
{
  return bio_stm_write(h, str, strlen(str));
}

static int bio_stm_read(BIO *h, char *buf, int size)
{
  uint64_t nread;
  ph_stream_t *stm = BIO_get_data(h);

  if (buf == NULL || size == 0 || stm == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(h);
  if (ph_stm_read(stm, buf, size, &nread)) {
    return (int)nread;
  }

  if (should_retry(stm)) {
    BIO_set_retry_read(h);
  }

  return -1;
}

static long bio_stm_ctrl(BIO *h, int cmd, // NOLINT(runtime/int)
    long arg1, void *arg2)                // NOLINT(runtime/int)
{
  ph_stream_t *stm = BIO_get_data(h);

  switch (cmd) {
    case BIO_CTRL_FLUSH:
      ph_stm_flush(stm);
      return 1;
    default:
      ph_unused_parameter(arg1);
      ph_unused_parameter(arg2);
      return 1;
  }
}

static int bio_stm_new(BIO *h)
{
  bio_stm_clear(h);
  return 1;
}

static int bio_stm_free(BIO *h)
{
  if (!h) {
    return 0;
  }

  bio_stm_clear(h);
  return 1;
}

BIO *ph_openssl_bio_wrap_stream(ph_stream_t *stm)
{
  static BIO_METHOD *bm;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  static BIO_METHOD old_meth = {
    // There are no clear rules on how the type numbers are assigned, so we'll
    // just pick 'P' as our type number and hope it doesn't collide any time
    // soon.  TODO: consider using: BIO_TYPE_BIO | BIO_get_new_index ();
    80 | BIO_TYPE_SOURCE_SINK,
    "phenom-stream",
    bio_stm_write,
    bio_stm_read,
    bio_stm_puts,
    NULL, /* no gets */
    bio_stm_ctrl,
    bio_stm_new,
    bio_stm_free,
    NULL, /* no callback ctrl */
  };

  bm = &old_meth;
#else
  if (!bm) {
    bm = BIO_meth_new(80 /* 'P' */ | BIO_TYPE_SOURCE_SINK, "phenom-stream");
    if (!bm) {
      return NULL;
    }

    BIO_meth_set_write(bm, bio_stm_write);
    BIO_meth_set_read(bm, bio_stm_read);
    BIO_meth_set_puts(bm, bio_stm_puts);
    BIO_meth_set_ctrl(bm, bio_stm_ctrl);
    BIO_meth_set_create(bm, bio_stm_new);
    BIO_meth_set_destroy(bm, bio_stm_free);
  }
#endif

  BIO *h = BIO_new(bm);
  if (!h) {
    return NULL;
  }

  BIO_set_data(h, stm);
  BIO_set_init(h, 1);

  return h;
}

/* vim:ts=2:sw=2:et:
 */

