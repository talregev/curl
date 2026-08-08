#ifndef HEADER_CURL_MBEDTLS_H
#define HEADER_CURL_MBEDTLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Hoi-Ho Chan, <hoiho.chan@gmail.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_MBEDTLS

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#ifdef MBEDTLS_X509_CRL_PARSE_C
#include <mbedtls/x509_crl.h>
#endif

#include "urldata.h"

struct alpn_spec;
struct ssl_peer;

extern const struct Curl_ssl Curl_ssl_mbedtls;

struct mbed_ssl_backend_data {
  mbedtls_ssl_context ssl;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt clicert;
#ifdef MBEDTLS_X509_CRL_PARSE_C
  mbedtls_x509_crl crl;
#endif
  mbedtls_pk_context pk;
  mbedtls_ssl_config config;
#ifdef MBEDTLS_SSL_ALPN
  const char *protocols[3];
#endif
  int *ciphersuites;
  struct Curl_cfilter *verify_cf;
  struct Curl_easy *verify_data;
  size_t send_blocked_len;
  BIT(initialized); /* mbedtls_ssl_context is initialized */
  BIT(sent_shutdown);
  BIT(send_blocked);
};

CURLcode Curl_mbedtls_ctx_init(struct mbed_ssl_backend_data *backend,
                               struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct ssl_peer *peer,
                               const struct alpn_spec *alpns,
                               bool quic);

void Curl_mbedtls_ctx_free(struct mbed_ssl_backend_data *backend);

size_t Curl_mbedtls_version(char *buffer, size_t size);

#endif /* USE_MBEDTLS */
#endif /* HEADER_CURL_MBEDTLS_H */
