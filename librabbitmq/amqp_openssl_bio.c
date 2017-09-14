/*
 * Portions created by Alan Antonuk are Copyright (c) 2017 Alan Antonuk.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */


#include "amqp_openssl_bio.h"
#include "amqp_socket.h"
#include "amqp.h"
#include "threads.h"

#include <errno.h>
#if ((defined(_WIN32)) || (defined(__MINGW32__)) || (defined(__MINGW64__)))
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <winsock2.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
#endif

#ifdef MSG_NOSIGNAL
# define AMQP_USE_AMQP_BIO
#endif

#if (OPENSSL_VERSION_NUMBER > 0x10100000L)
# define AMQP_OPENSSL_V110
#endif

#ifdef AMQP_USE_AMQP_BIO

#ifdef ENABLE_THREAD_SAFETY
static pthread_once_t bio_init_once = PTHREAD_ONCE_INIT;
#endif

static int bio_init_status = 0;
static BIO_METHOD* amqp_bio_method = NULL;

static int amqp_openssl_bio_should_retry(int res) {
  if (res == -1) {
    int err = amqp_os_socket_error();
    if (
#ifdef EWOULDBLOCK
        err == EWOULDBLOCK ||
#endif
#ifdef WSAEWOULDBLOCK
        err == WSAEWOULDBLOCK ||
#endif
#ifdef ENOTCONN
        err == ENOTCONN ||
#endif
#ifdef EINTR
        err == EINTR ||
#endif
#ifdef EAGAIN
        err == EAGAIN ||
#endif
#ifdef EPROTO
        err == EPROTO ||
#endif
#ifdef EINPROGRESS
        err == EINPROGRESS ||
#endif
#ifdef EALREADY
        err == EALREADY ||
#endif
        0) {
      return 1;
    }
  }
  return 0;
}

static int amqp_openssl_bio_write(BIO* b, const char *in, int inl) {
  int flags = 0;
  int fd;
  int res;

#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  BIO_get_fd(b, &fd);
  res = send(fd, in, inl, flags);

  BIO_clear_retry_flags(b);
  if (res <= 0 && amqp_openssl_bio_should_retry(res)) {
    BIO_set_retry_write(b);
  }

  return res;
}

static int amqp_openssl_bio_read(BIO* b, char* out, int outl) {
  int flags = 0;
  int fd;
  int res;

#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  BIO_get_fd(b, &fd);
  res = recv(fd, out, outl, flags);

  BIO_clear_retry_flags(b);
  if (res <= 0 && amqp_openssl_bio_should_retry(res)) {
    BIO_set_retry_read(b);
  }

  return res;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static int BIO_meth_set_write(BIO_METHOD *biom,
                              int (*wfn)(BIO *, const char *, int)) {
  biom->bwrite = wfn;
  return 0;
}

static int BIO_meth_set_read(BIO_METHOD *biom,
                              int (*rfn)(BIO *, char *, int)) {
  biom->bread = rfn;
  return 0;
}
#endif

static void amqp_openssl_bio_initialize(void) {
  if (NULL != amqp_bio_method) {
    return;
  }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  if (!(amqp_bio_method = OPENSSL_malloc(sizeof(BIO_METHOD)))) {
    bio_init_status = AMQP_STATUS_NO_MEMORY;
    return;
  }

  memcpy(amqp_bio_method, BIO_s_socket(), sizeof(BIO_METHOD));
#else
  if (!(amqp_bio_method = BIO_meth_new(BIO_TYPE_SOCKET, "amqp_bio_method"))) {
    bio_init_status = AMQP_STATUS_NO_MEMORY;
    return;
  }

  BIO_METHOD* meth = BIO_s_socket();
  BIO_meth_set_create(amqp_bio_method, BIO_meth_get_create(meth));
  BIO_meth_set_destroy(amqp_bio_method, BIO_meth_get_destroy(meth));
  BIO_meth_set_ctrl(amqp_bio_method, BIO_meth_get_ctrl(meth));
  BIO_meth_set_callback_ctrl(amqp_bio_method, BIO_meth_get_callback_ctrl(meth));
  BIO_meth_set_read(amqp_bio_method, BIO_meth_get_read(meth));
  BIO_meth_set_write(amqp_bio_method, BIO_meth_get_write(meth));
  BIO_meth_set_gets(amqp_bio_method, BIO_meth_get_gets(meth));
  BIO_meth_set_puts(amqp_bio_method, BIO_meth_get_puts(meth));

#endif
  BIO_meth_set_write(amqp_bio_method, amqp_openssl_bio_write);
  BIO_meth_set_read(amqp_bio_method, amqp_openssl_bio_read);

  bio_init_status = AMQP_STATUS_OK;
}

#endif  /* AMQP_USE_AMQP_BIO */

int amqp_openssl_bio_init(void) {
#ifdef AMQP_USE_AMQP_BIO
#ifdef ENABLE_THREAD_SAFETY
  pthread_once(&bio_init_once, amqp_openssl_bio_initialize);
#else
  amqp_openssl_bio_initialize();
#endif
  return bio_init_status;
#else
  return AMQP_STATUS_OK;
#endif
}

void amqp_openssl_bio_destroy(void) {
#ifdef AMQP_USE_AMQP_BIO
#ifdef AMQP_OPENSSL_V110
  BIO_meth_free(amqp_bio_method);
#else
  OPENSSL_free(amqp_bio_method);
#endif
  amqp_bio_method = NULL;
  bio_init_once = PTHREAD_ONCE_INIT;
#endif
}

BIO_METHOD* amqp_openssl_bio(void) {
#ifdef AMQP_USE_AMQP_BIO
  return amqp_bio_method;
#else
  return BIO_s_socket();
#endif
}
