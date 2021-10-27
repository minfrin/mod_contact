/**
 *    Copyright (C) 2021 Graham Leggett <minfrin@sharp.fm>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * mod_multipart - Apache httpd multipart parser module
 *
 * The Apache mod_multipart module provides a set of filters that
 * can parse and interpret multipart MIME content.
 */

/**
 * @file mod_multipart.h
 * @brief Multipart filters and buckets.
 *
 * @defgroup MOD_MULTIPART mod_multipart
 * @ingroup  APACHE_MODS
 * @{
 */

#ifndef MOD_CONTACT_H_
#define MOD_CONTACT_H_


#include <apr_buckets.h>
//#include <apr_encode.h>
//#include <apr_escape.h>
//#include <apr_hash.h>
//#include <apr_lib.h>
//#include <apr_strings.h>

#include "httpd.h"
//#include "http_config.h"
//#include "http_core.h"
//#include "http_log.h"
//#include "http_protocol.h"
//#include "http_request.h"
//#include "util_script.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The CONTACT bucket type.  This bucket represents the headers that will be
 * added to the email. If this bucket is still available when the pool is
 * cleared, the metadata is cleared.
 *
 * When read, this bucket expands into the headers of the message, containing
 * at least the to, from and subject.
 */
AP_DECLARE_DATA extern const apr_bucket_type_t ap_bucket_type_contact;

/**
 * Determine if a bucket is a CONTACT bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define AP_BUCKET_IS_CONTACT(e)        ((e)->type == &ap_bucket_type_contact)

/**
 * Make the bucket passed in a CONTACT bucket
 * @param b The bucket to make into an CONTACT bucket
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_contact_make(apr_bucket *b, request_rec *r,
        apr_table_t *headers);

/**
 * Create a bucket referring to contact metadata.
 *
 * @param list The freelist from which this bucket should be allocated
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_contact_create(apr_bucket_alloc_t *list, request_rec *r,
        apr_table_t *headers);

/**
 * A bucket referring to the headers of a message.
 */
typedef struct ap_bucket_contact {
    /** The contact bucket must be able to be easily morphed to a heap
     * bucket if the pool gets cleaned up before all references are
     * destroyed.  This apr_bucket_heap structure is populated automatically
     * when the pool gets cleaned up, and subsequent calls to pool_read()
     * will result in the apr_bucket in question being morphed into a
     * regular heap bucket.  (To avoid having to do many extra refcount
     * manipulations and b->data manipulations, the ap_bucket_contact
     * struct actually *contains* the apr_bucket_heap struct that it
     * will become as its first element; the two share their
     * apr_bucket_refcount members.)
     */
    apr_bucket_heap  heap;
    /** Used while writing out the headers */
    char *end;
    /** The request the data was allocated from.  When the pool
     * is cleaned up, this gets set to NULL as an indicator
     * to pool_read() that the data is now on the heap and
     * so it should morph the bucket into a regular heap
     * bucket before continuing.
     */
    request_rec *r;
    /** The freelist this structure was allocated from, which is
     * needed in the cleanup phase in order to allocate space on the heap
     */
    apr_bucket_alloc_t *list;
    /** The headers to be sent */
    apr_table_t *headers;
} ap_bucket_contact;


#ifdef __cplusplus
}
#endif

#endif /* MOD_CONTACT_H_ */
/** @} */
