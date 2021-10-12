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
 * mod_contact - Apache httpd contact module
 *
 * The Apache mod_contact module provides a service that accepts
 * a form POST and optional file uploads, and sends the contents
 * of the form as an email.
 *
 */

#include <apr_encode.h>
#include <apr_hash.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include "httpd.h"
//#include "http_config.h"
//#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "ap_expr.h"

module AP_MODULE_DECLARE_DATA contact_module;

#define DEFAULT_COMMAND "/usr/sbin/sendmail"
#define DEFAULT_ARGUMENT "-t"

#define MULTIPART_READ_BLOCKSIZE      16384    /* used for reading input blocks */
#define CONTACT_READ_BLOCKSIZE        16384    /* used for reading input blocks */


typedef struct
{
    const char *command;
    int command_set;
    apr_array_header_t *args;
    int args_set;
    apr_array_header_t *addresses;
    const char *to;
    int to_set;
    const char *from;
    int from_set;
    apr_hash_t *fields;
    const char *message;
    int message_set;
    const char *file;
    int file_set;
    ap_expr_info_t *sender;
    int sender_set;
} contact_config_rec;

/**
 * Split a brigade based on the provided boundary, or metadata buckets,
 * whichever are encountered first.
 *
 * If the boundary is found, all buckets prior to the boundary are passed
 * into bbOut, and APR_SUCCESS is returned.
 *
 * If a metadata bucket is found, or if the boundary is not found within
 * the limit specified by maxbytes, all prior buckets are passed into bbOut,
 * and APR_INCOMPLETE is returned.
 *
 * If the boundary is NULL or the empty string, APR_EINVAL is returned.
 *
 * If an error is encountered, the APR error code will be returned.
 *
 * @param bbOut The bucket brigade that will have the LF line appended to.
 * @param bbIn The input bucket brigade to search for a LF-line.
 * @param block The blocking mode to be used to split the line.
 * @param boundary The boundary string.
 * @param boundary_len The length of the boundary string.
 * @param maxbytes The maximum bytes to read.
 */
apr_status_t apr_brigade_split_boundary(apr_bucket_brigade *bbOut,
                                        apr_bucket_brigade *bbIn,
                                        apr_read_type_e block,
                                        const char *boundary,
                                        apr_ssize_t boundary_len,
                                        apr_off_t maxbytes)
{
    apr_off_t outbytes = 0;

    if (!boundary || !boundary[0]) {
        return APR_EINVAL;
    }

    while (!APR_BRIGADE_EMPTY(bbIn)) {

        const char *pos;
        const char *str;
        apr_bucket *e, *next, *prev;
        apr_off_t inbytes = 0;
        apr_size_t len;
        apr_status_t rv;

        /* We didn't find a boundary within the maximum line length. */
        if (outbytes >= maxbytes) {
            return APR_INCOMPLETE;
        }

        e = APR_BRIGADE_FIRST(bbIn);

        /* We hit a metadata bucket, stop and let the caller handle it */
        if (APR_BUCKET_IS_METADATA(e)) {
            return APR_INCOMPLETE;
        }

        rv = apr_bucket_read(e, &str, &len, block);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        inbytes += len;

        /*
         * Fast path.
         *
         * If we have at least one boundary worth of data, do an optimised
         * substring search for the boundary, and split quickly if found.
         */
        if (len >= boundary_len) {

            apr_size_t off;
            apr_size_t leftover;

            pos = strnstr(str, boundary, len);

            /* definitely found it, we leave */
            if (pos != NULL) {

                off = pos - str;

                /* everything up to the boundary */
                if (off) {

                    apr_bucket_split(e, off);
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(bbOut, e);

                    e = APR_BRIGADE_FIRST(bbIn);
                }

                /* cut out the boundary */
                apr_bucket_split(e, boundary_len);
                apr_bucket_delete(e);

                return APR_SUCCESS;
            }

            /* any partial matches at the end? */
            leftover = boundary_len - 1;
            off = (len - leftover);

            while (leftover) {
                if (!strncmp(str + off, boundary, leftover)) {

                    if (off) {

                    	apr_bucket_split(e, off);
                        APR_BUCKET_REMOVE(e);
                        APR_BRIGADE_INSERT_TAIL(bbOut, e);

                        e = APR_BRIGADE_FIRST(bbIn);
                    }

                    outbytes += off;
                    inbytes -= off;

                    goto skip;
                }
                off++;
                leftover--;
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(bbOut, e);

            outbytes += len;

            continue;

        }

        /*
         * Slow path.
         *
         * We need to read ahead at least one boundary worth of data so
         * we can search across the bucket edges.
         */
        else {

            apr_size_t off = 0;

            /* find all definite non matches */
            while (len) {
                if (!strncmp(str + off, boundary, len)) {

                    if (off) {

                    	apr_bucket_split(e, off);
                        APR_BUCKET_REMOVE(e);
                        APR_BRIGADE_INSERT_TAIL(bbOut, e);

                        e = APR_BRIGADE_FIRST(bbIn);
                    }

                    inbytes -= off;

                    goto skip;
                }
                off++;
                len--;
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(bbOut, e);
            continue;

        }

        /*
         * If we reach skip, it means the bucket in e is:
         *
         * - shorter than the boundary
         * - matches the boundary up to the bucket length
         * - might match more buckets
         *
         * Read further buckets and check whether the boundary matches all
         * the way to the end. If so, we have a match. If no match, shave off
         * one byte and continue round to try again.
         */
skip:
// ????
        for (next = APR_BUCKET_NEXT(e);
                inbytes < boundary_len && next != APR_BRIGADE_SENTINEL(bbIn);
                next = APR_BUCKET_NEXT(next)) {

            const char *str;
            apr_size_t off;
            apr_size_t len;

            rv = apr_bucket_read(next, &str, &len, block);

            if (rv != APR_SUCCESS) {
                return rv;
            }

            off = boundary_len - inbytes;

            if (len > off) {

                /* not a match, bail out */
                if (strncmp(str, boundary + inbytes, off)) {
                    break;
                }

                /* a match! remove the boundary and return */
                apr_bucket_split(next, off);

                e = APR_BUCKET_NEXT(next);

                for (prev = APR_BRIGADE_FIRST(bbIn);
                        prev != e;
                        prev = APR_BRIGADE_FIRST(bbIn)) {

                    apr_bucket_delete(prev);

                }

                return APR_SUCCESS;

            }
            if (len == off) {

                /* not a match, bail out */
                if (strncmp(str, boundary + inbytes, off)) {
                    break;
                }

                /* a match! remove the boundary and return */
                e = APR_BUCKET_NEXT(next);

                for (prev = APR_BRIGADE_FIRST(bbIn);
                        prev != e;
                        prev = APR_BRIGADE_FIRST(bbIn)) {

                    apr_bucket_delete(prev);

                }

                return APR_SUCCESS;

            }
            else if (len) {

                /* not a match, bail out */
                if (strncmp(str, boundary + inbytes, len)) {
                    break;
                }

                /* still hope for a match */
                inbytes += len;
            }

        }

        /*
         * If we reach this point, the bucket e did not match the boundary
         * in the subsequent buckets.
         *
         * Bump one byte off, and loop round to search again.
         */
        apr_bucket_split(e, 1);
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bbOut, e);

        outbytes++;

    }

    return APR_INCOMPLETE;
}

/**
 * Search for a character within a string, ignoring quoted sections.
 */
static const char *ap_strnchr_quoted(const char *s, int c, apr_size_t n)
{
    int inquotes = 0;
    int escaped = 0;

    if (!s) {
        return NULL;
    }

    while (n && *s) {

        if (escaped) {
            s++;
            n--;
            escaped = 0;
            continue;
        }

        if (*s == '\\') {
            escaped = 1;
            s++;
            n--;
            continue;
        }

        if (*s == '"') {
            inquotes = !inquotes;
            s++;
            n--;
            continue;
        }

        if (!inquotes && *s == c) {
            return s;
        }

        s++;
        n--;
    };

    return NULL;
}

static const char *ap_pstrndup_quoted(apr_pool_t *a, const char *s, apr_size_t n)
{
    char *dest, *d;

    apr_size_t len = 0;
    apr_size_t off = 0;

    int inquotes = 0;
    int escaped = 0;

    if (!s) {
        return NULL;
    }

    while (n > off && s[off]) {

        if (escaped) {
            len++;
            off++;
            escaped = 0;
            continue;
        }

        if (s[off] == '\\') {
            escaped = 1;
            off++;
            continue;
        }

        if (s[off] == '"') {
            inquotes = !inquotes;
            off++;
            continue;
        }

        len++;
        off++;
    };

    dest = d = apr_palloc(a, len + 1);

    off = 0;

    while (n > off && s[off]) {

        if (escaped) {
            escaped = 0;
            *d++ = s[off++];
            continue;
        }

        if (s[off] == '\\') {
            escaped = 1;
            off++;
            continue;
        }

        if (s[off] == '"') {
            inquotes = !inquotes;
            off++;
            continue;
        }

        *d++ = s[off++];
    };

    *d = 0;

    return dest;
}

static const char *ap_header_vparse(apr_pool_t *p, const char *header,
        va_list vp)
{
    char *argk;
    const char **argv;

    const char *token;
    const char *params;
    const char *next;

    apr_size_t len;

    if (!header) {
        return NULL;
    }

    len = strlen(header);

    params = ap_strnchr_quoted(header, ';', len);
    if (!params) {
        return header;
    }
    else {
        len -= (params - header);
        header = ap_pstrndup_quoted(p, header, params - header);
    }

    do {

        argk = va_arg(vp, char *);
        if (!argk) {
            break;
        }

        argv = va_arg(vp, const char **);
        if (!argv) {
            break;
        }

        token = params;
        do {

            const char *equals;

            /* skip the semicolon from last time, and any trailing whitespace */
            while (*(++token) && apr_isspace(*token));

            next = ap_strnchr_quoted(token, ';', len - (token - params));
            if (!next) {

                apr_size_t l = strlen(token);

                /* now for the name / value pair */
                equals = ap_strnchr_quoted(token, '=', l);

                if (equals && !strncasecmp(token, argk, equals - token)) {
                    *argv = ap_pstrndup_quoted(p, equals + 1,
                            len - (equals - params) - 1);
                }

                break;
            }
            else {

                /* now for the name / value pair */
                equals = ap_strnchr_quoted(token, '=', next - token);

                if (equals && !strncasecmp(token, argk, equals - token)) {
                    *argv = ap_pstrndup_quoted(p, equals + 1, next - equals - 1);
                }

                token = next;
            }

        } while (1);

    } while (1);

    return header;
}

static const char *ap_header_parse(apr_pool_t *p, const char *header, ...)
{
    const char *h;

    va_list vp;
    va_start(vp, header);
    h = ap_header_vparse(p, header, vp);
    va_end(vp);

    return h;
}

static const char *ap_escape_header_extension(apr_pool_t *p, const char *header)
{
    /**
     * Implement
     *
     * https://datatracker.ietf.org/doc/html/rfc2231
     * https://datatracker.ietf.org/doc/html/rfc5987
     */

// FIXME

    return header;
}

typedef struct multipart_t {
    /** The pool for this part */
    apr_pool_t *pool;
    /** The multipart/subtype used by this part */
    const char *subtype;
    /** The boundary string used by this part.
     */
    char    *boundary;
    /** The length of the boundary */
    apr_size_t  boundary_len;
    /** The headers of the boundary */
    apr_table_t *headers;
    /** Nesting level of the parts */
    int level;
    /** Number of parts using this memory */
    int refcount;
} multipart_t;

typedef struct part_t {
    /** The pool for this part */
    apr_pool_t *pool;
    /** The headers of this part */
    apr_table_t *headers;
    /** The content type, if present */
    const char *ct;
    /** The content type boundary, if present */
    const char *ct_boundary;
    /** The content type charset, if present */
    const char *ct_charset;
    /** The content type encoding, if present */
    const char *cte;
    /** The content disposition, if present */
    const char *dsp;
    /** The disposition filename, if present */
    const char *dsp_filename;
    /** The disposition creation-date, if present */
    const char *dsp_create;
    /** The disposition modification-date, if present */
    const char *dsp_mod;
    /** The disposition read-date, if present */
    const char *dsp_read;
    /** The disposition size, if present */
    const char *dsp_size;
    /** The disposition name, if present */
    const char *dsp_name;
} part_t;

static void multipart_ref(multipart_t *mp)
{
	mp->refcount++;
}

static void multipart_unref(multipart_t *mp)
{
	mp->refcount--;
    if (!mp->refcount) {
        apr_pool_destroy(mp->pool);
    }
}

/**
 * The MULTIPART bucket type.  This bucket represents the metadata of and start
 * of a part in a multipart message. If this bucket is still available when the
 * pool is cleared, the metadata is cleared.
 *
 * The content of the part follows this bucket as regular buckets, and ends at
 * the next MULTIPART bucket, or EOS, whichever is seen first.
 */
AP_DECLARE_DATA extern const apr_bucket_type_t ap_bucket_type_multipart;

/**
 * Determine if a bucket is a MULTIPART bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define AP_BUCKET_IS_MULTIPART(e)        ((e)->type == &ap_bucket_type_multipart)

/**
 * Make the bucket passed in a MULTIPART bucket
 * @param b The bucket to make into an MULTIPART bucket
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_multipart_make(apr_bucket *b, multipart_t *multipart, part_t *part);

/**
 * Create a bucket referring to multipart metadata.
 *
 * @param list The freelist from which this bucket should be allocated
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_multipart_create(apr_bucket_alloc_t *list, multipart_t *multipart,
        part_t *part);

/** @see apr_bucket_pool */
typedef struct ap_bucket_multipart ap_bucket_multipart;

/**
 * A bucket referring to the start of a multipart part.
 */
struct ap_bucket_multipart {
    /** Number of buckets using this memory */
    apr_bucket_refcount  refcount;
    /** The content of the multipart */
    multipart_t *multipart;
    /** The content of the part */
    part_t *part;
};

AP_DECLARE(apr_bucket *) ap_bucket_multipart_make(apr_bucket *b,
        multipart_t *multipart, part_t *part)
{
    ap_bucket_multipart *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->multipart = multipart;
    h->part = part;

    multipart_ref(multipart);

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_multipart;
    return b;
}

AP_DECLARE(apr_bucket*) ap_bucket_multipart_create(apr_bucket_alloc_t *list,
        multipart_t *multipart, part_t *part)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b = ap_bucket_multipart_make(b, multipart, part);
    return b;
}

static void multipart_bucket_destroy(void *data)
{
    ap_bucket_multipart *h = data;

    if (apr_bucket_shared_destroy(h)) {
        if (h->part) {
            apr_pool_destroy(h->part->pool);
            h->part = NULL;
        }
        if (h->multipart) {
        	multipart_unref(h->multipart);
            h->multipart = NULL;
        }
        apr_bucket_free(h);
    }
}

static apr_status_t multipart_bucket_read(apr_bucket *b, const char **str,
        apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_multipart = {
    "MULTIPART", 5, APR_BUCKET_METADATA,
    multipart_bucket_destroy,
    multipart_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

typedef enum multipart_state_e {
    MULTIPART_PREAMBLE,
    MULTIPART_BOUNDARY,
    MULTIPART_HEADER,
    MULTIPART_BODY,
    MULTIPART_EPILOG
} multipart_state_e;

typedef struct multipart_ctx_t
{
    apr_bucket_brigade *in;
    apr_bucket_brigade *filtered;
    apr_bucket_brigade *out;
    apr_array_header_t *multiparts;
    multipart_t *multipart;
    part_t *part;
    apr_off_t remaining;
    multipart_state_e state;
    int seen_eos:1;
} multipart_ctx;

static apr_status_t multipart_cleanup(void *data)
{
	multipart_ctx *ctx = data;

    apr_array_pop(ctx->multiparts);

    if (ctx->multiparts->nelts) {
    	ctx->multipart = APR_ARRAY_IDX(ctx->multiparts, ctx->multiparts->nelts - 1, multipart_t *);
    }
    else {
    	ctx->multipart = NULL;
    }
    return APR_SUCCESS;
}

static multipart_t *multipart_push(multipart_ctx *ctx,
        const char *subtype, const char *boundary)
{
    apr_pool_t *pool;

    multipart_t **pmp;
    multipart_t *mp;

    apr_pool_create(&pool, ctx->multiparts->pool);

    mp = apr_pcalloc(pool, sizeof(multipart_t));
    mp->pool = pool;
    mp->subtype = apr_pstrdup(pool, subtype);
    mp->boundary = apr_pstrdup(pool, boundary);
    mp->boundary_len = strlen(boundary);
    mp->level = ctx->multiparts->nelts;

    pmp = apr_array_push(ctx->multiparts);
    *pmp = mp;

    apr_pool_cleanup_register(pool, ctx, multipart_cleanup,
                              apr_pool_cleanup_null);

    ctx->multipart = mp;

    return mp;
}

static void multipart_parse_headers(part_t *part, const char *key,
        const char *value)
{

    if (strncasecmp(key, "Content-", 8)) {
        return;
    }
    key += 8;

    if (!strcasecmp(key, "Type")) {

        /* https://datatracker.ietf.org/doc/html/rfc2045#section-5 */

        part->ct = ap_header_parse(part->pool, value, "boundary",
                &part->ct_boundary, "charset", &part->ct_charset, NULL);

    } else if (!strcasecmp(key, "Transfer-Encoding")) {

        /* https://datatracker.ietf.org/doc/html/rfc2045#section-6 */

        part->cte = ap_header_parse(part->pool, value, NULL);

    } else if (!strcasecmp(key, "Disposition")) {

        /* https://www.ietf.org/rfc/rfc2183.txt
         * https://datatracker.ietf.org/doc/html/rfc7578#section-4.2
         */

        part->dsp = ap_header_parse(part->pool, value, "filename",
                &part->dsp_filename, "creation-date", &part->dsp_create,
                "modification-date", &part->dsp_mod, "read-date",
                &part->dsp_read, "size", &part->dsp_size, "name",
                &part->dsp_name, NULL);

    }

}

/* This is the multipart filter */
static apr_status_t multipart_in_filter(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    apr_bucket *e, *after;
    request_rec *r = f->r;
    multipart_ctx *ctx = f->ctx;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (!ctx) {

        const char *ct;
        const char *type;
        const char *boundary;

        /*
         * Boundary is limited to 70 characters in rfc2046 section 5.1.1.
         *
         * We allocate the carriage return, line feed, first two dash
         * characters, then 70 characters, then a trailing nul.
         */
//        char subtype[256];
//        char boundary[75] = CRLF "--";

        ct = apr_table_get(r->headers_in, "Content-Type");

        /* only work on main request/no subrequests */
        if (!ap_is_initial_req(r)) {
            goto bypass;
        }

        /* multipart only, and with a boundary */
#if 0
        if (ct
                && (sscanf(ct,
                        "multipart/%250[a-z-]; boundary=\"%70[0-9a-zA-Z'()+_,./:=? -]\"",
                        subtype, boundary + 4) == 2
                        || sscanf(ct,
                                "multipart/%250[a-z-]; boundary=%70[0-9a-zA-Z'()+_,./:=?-]",
                                subtype, boundary + 4) == 2)) {
            /* ok */
        } else {
            goto bypass;
        }
#endif

        type = ap_header_parse(r->pool, ct, "boundary",
                &boundary, NULL);

        if (!type || strcasecmp(type, "multipart/form-data")) {
            goto bypass;
        }

        if (!boundary || !boundary[0]) {
// FIXME error
            goto bypass;
        }

        boundary =
                apr_pstrcat(r->pool, CRLF "--", boundary, NULL);

        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->in = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->filtered = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->out = apr_brigade_create(r->pool, f->c->bucket_alloc);

        ctx->multiparts = apr_array_make(r->pool, 1, sizeof(ap_bucket_multipart *));

        multipart_push(ctx, type + 10, boundary);

        multipart_ref(ctx->multipart);
    }

    /* if our buffer is empty, read off the network until the buffer is full */
    if (APR_BRIGADE_EMPTY(ctx->out)) {

        int rv;

        rv = ap_get_brigade(f->next, ctx->in, AP_MODE_READBYTES, block,
                MULTIPART_READ_BLOCKSIZE);

        /* if an error was received, bail out now. If the error is
          * EAGAIN and we have not yet seen an EOS, we will definitely
          * be called again, at which point we will send our buffered
          * data. Instead of sending EAGAIN, some filters return an
          * empty brigade instead when data is not yet available. In
          * this case, we drop through and pass buffered data, if any.
          */
         if (APR_STATUS_IS_EAGAIN(rv)
             || (rv == APR_SUCCESS
                 && block == APR_NONBLOCK_READ
                 && APR_BRIGADE_EMPTY(ctx->in))) {
             if (APR_BRIGADE_EMPTY(ctx->out)) {
                 return rv;
             }
             goto skip;
         }
         if (APR_SUCCESS != rv) {
             return rv;
         }

         while (1) {
             int seen_metadata = 0;

             /*
              * leading metadata buckets are passed through as is, and we
              * pass them back immediately. The EOS is detected here.
              */
             for (e = APR_BRIGADE_FIRST(ctx->in);
                  e != APR_BRIGADE_SENTINEL(ctx->in) && APR_BUCKET_IS_METADATA(e);
                  e = APR_BUCKET_NEXT(e))
             {

                 if (APR_BUCKET_IS_EOS(e)) {
                     APR_BRIGADE_CONCAT(ctx->out, ctx->in);
                     ctx->seen_eos = 1;
                     goto skip;
                 }
                 else {
                     APR_BUCKET_REMOVE(e);
                     APR_BRIGADE_INSERT_TAIL(ctx->out, e);
                 }

                 seen_metadata = 1;
             }

             if (seen_metadata) {
                 break;
             }

             if (APR_BRIGADE_EMPTY(ctx->in)) {
                 break;
             }

             /*
              * Our brigade has at least one data bucket in it, let's process
              * that bucket.
              */
             switch (ctx->state) {
             case MULTIPART_PREAMBLE: {

                 /* discard everything until the first boundary, which does
                  * not necessarily have a leading CRLF
                  */
                rv = apr_brigade_split_boundary(ctx->filtered, ctx->in, block,
                        ctx->multipart->boundary + 2,
                        ctx->multipart->boundary_len - 2,
                        MULTIPART_READ_BLOCKSIZE);

                 if (rv == APR_INCOMPLETE) {
                     /* no boundary yet, throw away the preamble so far */
                     apr_brigade_cleanup(ctx->filtered);
                     goto skip;
                 }
                 else if (rv == APR_SUCCESS) {
                     /* we found a boundary, throw away the preamble
                      * expect zero or more headers.
                      */
                     apr_brigade_cleanup(ctx->filtered);

                     /* drop through to boundary */
                     ctx->state = MULTIPART_BOUNDARY;

                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_BOUNDARY: {

                 /* If we see whitespace CRLF, headers are coming up.
                  *
                  * If we see dash dash CRLF, the epilog is coming up.
                  */

                 /* read the bit after the boundary */
                 rv = apr_brigade_split_boundary(ctx->filtered, ctx->in, block,
                         CRLF, 2, HUGE_STRING_LEN);

                 if (rv == APR_INCOMPLETE) {
                     /* no CRLF found within a reasonable distance, stream
                      * is bogus */
                     apr_brigade_cleanup(ctx->filtered);


                     // FIXME error handling

                     goto skip;
                 }
                 else if (rv == APR_SUCCESS) {

                     char header[HUGE_STRING_LEN];
                     apr_size_t len = HUGE_STRING_LEN;

                     /* the bit after the boundary */
                     apr_brigade_flatten(ctx->filtered, header, &len);

                     /* found a double dash? */
                     if (len >= 2 && !strncmp(header, "--", 2)) {

                         apr_brigade_cleanup(ctx->filtered);

                         /* drop into epilog */
                         ctx->state = MULTIPART_EPILOG;

                         continue;
                     }

                     /* found whitespace? */
                     else {

                         int off = 0;

                         while (off < len && apr_isspace(header[off++]));

                         if (off == len) {

                             apr_pool_t *pool;

                             apr_pool_create(&pool, r->pool);

                             ctx->part = apr_pcalloc(pool, sizeof(part_t));
                             ctx->part->pool = pool;
                             ctx->part->headers = apr_table_make(pool, 2);

                             /* drop into header */
                             ctx->state = MULTIPART_HEADER;

                         }

                     }


                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_HEADER: {

                 /* read a header */
                 rv = apr_brigade_split_boundary(ctx->filtered, ctx->in, block,
                         CRLF, 2, HUGE_STRING_LEN);

                 if (rv == APR_INCOMPLETE) {
                     /* header too long */
                     apr_brigade_cleanup(ctx->filtered);


                     // FIXME error handling

                     goto skip;
                 }
                 else if (rv == APR_SUCCESS) {

                     char header[HUGE_STRING_LEN];
                     apr_size_t len = HUGE_STRING_LEN;

                     /* we found a header! how exciting */
                     apr_brigade_flatten(ctx->filtered, header, &len);

                     /* parse the header */
                     if (len) {

                         const char *key;
                         char *value = memchr(header, ':', len);

                         if (value) {

                             int off = value - header;
                             key = apr_pstrndup(ctx->part->pool, header, off);
                             while (++off <= len && apr_isspace(header[off]));
                             value = apr_pstrndup(ctx->part->pool, header + off,
                                     len - off);

                             apr_table_setn(ctx->part->headers, key, value);

                             /* parse some common headers, like content type */
                             multipart_parse_headers(ctx->part, key, value);

                             apr_brigade_cleanup(ctx->filtered);

                             break;
                         }
                         else {
                             // corrupt header line

                             // FIXME error handling

                         }

                     }
                     /* empty header, next up a body */
                     else {

                         /* push a multipart bucket and return it */
                         e = ap_bucket_multipart_create(
                                 r->connection->bucket_alloc, ctx->multipart, ctx->part);
                         APR_BRIGADE_INSERT_TAIL(ctx->out, e);

                         ctx->part = NULL;

                         apr_brigade_cleanup(ctx->filtered);
                         ctx->state = MULTIPART_BODY;
                     }

                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_BODY: {

                 /* pass body downstream until the boundary */
                 rv = apr_brigade_split_boundary(ctx->out, ctx->in, block,
                         ctx->multipart->boundary, ctx->multipart->boundary_len,
                         MULTIPART_READ_BLOCKSIZE);

                 /* no boundary yet, pass down */
                 if (rv == APR_INCOMPLETE) {
                     break;
                 }

                 /* we found a boundary, pass rest of the body and expect zero
                  * or more headers.
                  */
                 else if (rv == APR_SUCCESS) {
                     ctx->state = MULTIPART_BOUNDARY;

                     /* loop round into header */
                     break;
                 }
                 else {
                     return rv;
                 }

             }
             /* no break */
             case MULTIPART_EPILOG: {

                 multipart_unref(ctx->multipart);

                 while (!APR_BRIGADE_EMPTY(ctx->in)) {
                     e = APR_BRIGADE_FIRST(ctx->in);

                     if (APR_BUCKET_IS_METADATA(e)) {
                         break;
                     }
                     else {
                         apr_bucket_delete(e);
                     }

                 }

             }
             }


        }
    }

skip:

    /* give the caller the data they asked for from the buffer */
    apr_brigade_partition(ctx->out, readbytes, &after);
    e = APR_BRIGADE_FIRST(ctx->out);
    while (e != after) {
        if (APR_BUCKET_IS_EOS(e)) {
            /* last bucket read, step out of the way */
            ap_remove_input_filter(f);
        }
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = APR_BRIGADE_FIRST(ctx->out);
    }

    return APR_SUCCESS;

bypass:
    ap_remove_input_filter(f);
    return ap_get_brigade(f->next, bb, mode, block, readbytes);

}










static int send_error(request_rec *r, int res, apr_status_t status,
        const char *message)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *e;

    int rv;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "%s", message);

    if ((rv = ap_discard_request_body(r)) != OK) {
        return rv;
    }

    bb = apr_brigade_create(r->pool, c->bucket_alloc);

    // FIXME
    status = apr_brigade_printf(bb, NULL, NULL, "error");

    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    status = ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);

    return res;
}

static void *create_contact_dir_config(apr_pool_t *p, char *d)
{
    contact_config_rec *conf = apr_pcalloc(p, sizeof(contact_config_rec));

    const char **array;

    conf->command = DEFAULT_COMMAND;
    conf->args = apr_array_make(p, 8, sizeof(const char * const *));
    conf->addresses = apr_array_make(p, 8, sizeof(const char * const *));
    conf->fields = apr_hash_make(p);

    array = apr_array_push(conf->args);

    *array = DEFAULT_ARGUMENT;

    return conf;
}

static void *merge_contact_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    contact_config_rec *new = (contact_config_rec *) apr_pcalloc(p,
            sizeof(contact_config_rec));
    contact_config_rec *add = (contact_config_rec *) addv;
    contact_config_rec *base = (contact_config_rec *) basev;

    new->command = (add->command_set == 0) ? base->command : add->command;
    new->command_set = add->command_set || base->command_set;
    new->args = (add->args_set == 0) ? base->args
            : add->args;
    new->args_set = add->args_set || base->args_set;
    new->addresses = apr_array_append(p, add->addresses, base->addresses);
    new->to = (add->to_set == 0) ? base->to : add->to;
    new->to_set = add->to_set || base->to_set;
    new->from = (add->from_set == 0) ? base->from
            : add->from;
    new->from_set = add->from_set || base->from_set;
    new->message = (add->message_set == 0) ? base->message
            : add->message;
    new->message_set = add->message_set || base->message_set;
    new->file = (add->file_set == 0) ? base->file
            : add->file;
    new->file_set = add->file_set || base->file_set;
    new->sender = (add->sender_set == 0) ? base->sender
            : add->sender;
    new->sender_set = add->sender_set || base->sender_set;

    return new;
}

static const char *set_command(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;

    conf->command = arg;
    conf->command_set = 1;

    return NULL;
}

static const char *set_args(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;
    const char **array = apr_array_push(conf->args);

    *array = arg;

    conf->args_set = 1;

    return NULL;
}

static const char *set_addresses(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;
    const char **array = apr_array_push(conf->addresses);

    *array = arg;

    return NULL;
}

static const char *set_to(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;

    conf->to = arg;
    conf->to_set = 1;

    return NULL;
}

static const char *set_from(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;

    conf->from = arg;
    conf->from_set = 1;

    return NULL;
}

static const char *set_field(cmd_parms *cmd, void *dconf, const char *arg1,
        const char *arg2)
{
    contact_config_rec *conf = dconf;

    if (!arg2) {
        arg2 = arg1;
    }

    apr_hash_set(conf->fields, arg1, APR_HASH_KEY_STRING, arg2);

    return NULL;
}

static const char *set_message(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;

    conf->message = arg;
    conf->message_set = 1;

    return NULL;
}

static const char *set_file(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;

    conf->file = arg;
    conf->file_set = 1;

    return NULL;
}

static const char *set_sender(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->sender = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);;
    conf->sender_set = 1;

    return NULL;
}

static const command_rec contact_cmds[] =
{
AP_INIT_TAKE1("ContactCommand",
        set_command, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to the name and path of the sendmail binary."),
AP_INIT_ITERATE(
        "ContactArguments", set_args, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to arguments to pass to the sendmail binary."),
AP_INIT_ITERATE(
        "ContactAddresses", set_addresses, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to valid sender email addresses that will be accepted."),
AP_INIT_TAKE1("ContactTo",
        set_to, NULL, RSRC_CONF | ACCESS_CONF,
        "The form parameter containing the to address."),
AP_INIT_TAKE1("ContactFrom",
        set_from, NULL, RSRC_CONF | ACCESS_CONF,
        "The form parameter containing the from address."),
AP_INIT_TAKE12("ContactField",
        set_field, NULL, RSRC_CONF | ACCESS_CONF,
        "The form parameter containing a field, and optional field name."),
AP_INIT_TAKE1("ContactMessage",
        set_message, NULL, RSRC_CONF | ACCESS_CONF,
        "The form parameter containing the message."),
AP_INIT_TAKE1("ContactFile",
        set_file, NULL, RSRC_CONF | ACCESS_CONF,
        "The form parameter containing file attachments."),
AP_INIT_TAKE1("ContactSender",
        set_sender, NULL, RSRC_CONF | ACCESS_CONF,
        "Expression resolving to the sender email address."),
{ NULL } };



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
ap_bucket_contact_make(apr_bucket *b, apr_pool_t *pool,
        apr_table_t *headers);

/**
 * Create a bucket referring to multipart metadata.
 *
 * @param list The freelist from which this bucket should be allocated
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_contact_create(apr_bucket_alloc_t *list, apr_pool_t *pool,
        apr_table_t *headers);

/** @see apr_bucket_pool */
typedef struct ap_bucket_contact ap_bucket_contact;

/**
 * A bucket referring to the headers of a message.
 */
struct ap_bucket_contact {
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
    /** The pool the data was allocated from.  When the pool
     * is cleaned up, this gets set to NULL as an indicator
     * to pool_read() that the data is now on the heap and
     * so it should morph the bucket into a regular heap
     * bucket before continuing.
     */
    apr_pool_t *pool;
    /** The freelist this structure was allocated from, which is
     * needed in the cleanup phase in order to allocate space on the heap
     */
    apr_bucket_alloc_t *list;
    /** The headers to be sent */
    apr_table_t *headers;
};

static apr_status_t contact_bucket_cleanup(void *data)
{
    ap_bucket_contact *h = data;

    /* if pool is cleaned up before the bucket, gracefully zero
     * out the pool and headers so we become of zero length.
     */
    h->headers = NULL;
    h->pool = NULL;

    return APR_SUCCESS;
}

AP_DECLARE(apr_bucket *) ap_bucket_contact_make(apr_bucket *b,
        apr_pool_t *pool, apr_table_t *headers)
{
    ap_bucket_contact *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->headers = headers;

    h->pool = pool;
    h->list = b->list;

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_contact;

    /* pre-initialize heap bucket member */
    h->heap.alloc_len     = 0;
    h->heap.base = h->end = NULL;
    h->heap.base          = NULL;
    h->heap.free_func     = apr_bucket_free;

    apr_pool_cleanup_register(h->pool, h, contact_bucket_cleanup,
                              apr_pool_cleanup_null);
    return b;
}

AP_DECLARE(apr_bucket*) ap_bucket_contact_create(apr_bucket_alloc_t *list,
        apr_pool_t *pool, apr_table_t *headers)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b = ap_bucket_contact_make(b, pool, headers);
    return b;
}

static void contact_bucket_destroy(void *data)
{
    ap_bucket_contact *h = data;

    if (apr_bucket_shared_destroy(h)) {

        /* if bucket is cleaned up before the pool, we deregister the
         * cleanuo and vanish from existence.
         */
        if (h->pool) {
            apr_pool_cleanup_kill(h->pool, h, contact_bucket_cleanup);
        }
        apr_bucket_free(h);
    }
}

int contact_bucket_count(void *rec, const char *key,
        const char *value);
int contact_bucket_do(void *rec, const char *key,
        const char *value);

int contact_bucket_count(void *rec, const char *key,
        const char *value)
{
    ap_bucket_contact *h = rec;

    h->heap.alloc_len += strlen(key) + strlen(": ") + strlen(value)
            + strlen(CRLF);

    return 1;
}

int contact_bucket_do(void *rec, const char *key,
        const char *value)
{
    ap_bucket_contact *h = rec;

    h->end = stpcpy(h->end, key);
    h->end = stpcpy(h->end, ": ");
    h->end = stpcpy(h->end, value);
    h->end = stpcpy(h->end, CRLF);

    return 1;
}

void contact_bucket_set_header(apr_bucket *contact, const char *header,
        apr_bucket_brigade *bb)
{
    ap_bucket_contact *h = contact->data;

    char value[HUGE_STRING_LEN + 1] = {0};
    apr_size_t len = HUGE_STRING_LEN;

    apr_brigade_flatten(bb, value, &len);

    apr_table_set(h->headers, header, value);

    apr_brigade_cleanup(bb);
}

static apr_status_t contact_bucket_read(apr_bucket *b, const char **str,
        apr_size_t *len, apr_read_type_e block)
{
    ap_bucket_contact *h = b->data;

    if (!h->heap.base && h->headers) {

        /* render headers, morph into heap bucket */
        h->heap.alloc_len = strlen(CRLF);
        apr_table_do(contact_bucket_count, h, h->headers, NULL);
        h->heap.base = h->end = apr_bucket_alloc(h->heap.alloc_len, h->list);
        apr_table_do(contact_bucket_do, h, h->headers, NULL);
        h->end = stpcpy(h->end, CRLF);
        b->length = h->heap.alloc_len;
        b->type = &apr_bucket_type_heap;
        h->headers = NULL;
        h->pool = NULL;
    }

    *str = h->heap.base + b->start;
    *len = b->length;
    return APR_SUCCESS;
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_contact = {
    "CONTACT", 5, APR_BUCKET_DATA,
    contact_bucket_destroy,
    contact_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_shared_split,
    apr_bucket_shared_copy
};




typedef enum contact_state_e {
    CONTACT_NONE,
    CONTACT_HEADER,
    CONTACT_BODY,
    CONTACT_ATTACHMENT
} contact_state_e;

typedef struct contact_ctx
{
    apr_bucket_brigade *in;
    apr_bucket_brigade *out;
    apr_bucket_brigade *filtered;
    apr_bucket *contact;
    const char *boundary;
    apr_table_t *headers;
    const char *header;
    const char *dsp;
    char base64[57];
    int base64_off;
    int seen_eos:1;
    int in_header:1;
    int in_mime:1;
    int in_base64:1;
    int ignore:1;
    contact_state_e state:2;
} contact_ctx;

static apr_status_t contact_base64(contact_ctx *ctx, apr_bucket_brigade *out,
		apr_bucket *e, int close)
{

	do {

		const char *str;
		apr_size_t len = sizeof(ctx->base64) - ctx->base64_off;

		if (!len || close) {

			char buf[79];
			apr_size_t buf_len;

			apr_encode_base64(buf, ctx->base64, ctx->base64_off, APR_ENCODE_NONE,
					&buf_len);

			ctx->base64_off = 0;
			len = sizeof(ctx->base64);

			apr_brigade_write(out, NULL, NULL, buf, buf_len);

			apr_brigade_puts(out, NULL, NULL, CRLF);
		}

		if (e) {

			if (APR_BUCKET_IS_METADATA(e)) {
				APR_BUCKET_REMOVE(e);
				APR_BRIGADE_INSERT_TAIL(out, e);

				return APR_SUCCESS;
			}

			else {
				apr_size_t l;
				apr_status_t rv;

				rv = apr_bucket_read(e, &str, &l, APR_BLOCK_READ);

				if (rv != APR_SUCCESS) {
					return rv;
				}

				if (l > len) {
					apr_bucket *next;

					memcpy(ctx->base64 + ctx->base64_off, str, len);
					ctx->base64_off += len;

					apr_bucket_split(e, len);
					next = APR_BUCKET_NEXT(e);
					apr_bucket_delete(e);
					e = next;
				}
				else {
					memcpy(ctx->base64 + ctx->base64_off, str, l);
					ctx->base64_off += l;

					apr_bucket_delete(e);
					e = NULL;
				}

			}
		}

	} while (e);

	return APR_SUCCESS;
}

static int init_contact(ap_filter_t * f)
{
    contact_ctx *ctx;

    apr_uint64_t val[2];

    ap_random_insecure_bytes(&val, sizeof(val));

    ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
    ctx->in = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    ctx->filtered = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    ctx->out = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    ctx->headers = apr_table_make(f->r->pool, 4);
    ctx->contact = ap_bucket_contact_create(
             f->r->connection->bucket_alloc, f->r->pool, ctx->headers);
    ctx->boundary = apr_psprintf(f->r->pool, "%0" APR_UINT64_T_HEX_FMT
            "%0" APR_UINT64_T_HEX_FMT, val[0], val[1]);

    apr_table_setn(ctx->headers, "Content-Type",
            apr_psprintf(f->r->pool, "multipart/mixed; boundary=\"%s\"",
                    ctx->boundary));

    return OK;
}

/*
 * Mappings:
 *
 * Text-foo: text
 * plain-bar: text
 *
 * mixed-
 */
static apr_status_t
contact_in_filter(ap_filter_t * f, apr_bucket_brigade * bb,
                 ap_input_mode_t mode, apr_read_type_e block,
                 apr_off_t readbytes)
{
    apr_bucket *e, *after;
    apr_status_t rv = APR_SUCCESS;
    contact_ctx *ctx = f->ctx;
    int seen_eos = 0;

    contact_config_rec *conf = ap_get_module_config(f->r->per_dir_config,
            &contact_module);

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* read parts until we run out */
//    do {

        if (APR_BRIGADE_EMPTY(ctx->in)) {
            rv = ap_get_brigade(f->next, ctx->in, mode, block,
                    CONTACT_READ_BLOCKSIZE);
        }

        /* if an error was received, bail out now. If the error is
         * EAGAIN and we have not yet seen an EOS, we will definitely
         * be called again, at which point we will send our buffered
         * data. Instead of sending EAGAIN, some filters return an
         * empty brigade instead when data is not yet available. In
         * this case, we drop through and pass buffered data, if any.
         */
        if (APR_STATUS_IS_EAGAIN(rv)
            || (rv == APR_SUCCESS
                && block == APR_NONBLOCK_READ
                && APR_BRIGADE_EMPTY(ctx->in))) {
            return APR_EAGAIN;
        }
        if (APR_SUCCESS != rv) {
            return rv;
        }

        while (!APR_BRIGADE_EMPTY(ctx->in)) {

            const char *str;
            apr_size_t len;

            e = APR_BRIGADE_FIRST(ctx->in);

            if (APR_BUCKET_IS_EOS(e)) {

                /* finish off any previous header */
                if (ctx->in_header) {
                    contact_bucket_set_header(ctx->contact, ctx->header,
                            ctx->filtered);
                    ctx->header = NULL;
                    ctx->in_header = 0;
                }

                /* send contact bucket if unsent */
                if (ctx->contact) {
                    APR_BRIGADE_INSERT_TAIL(ctx->out, ctx->contact);
                    ctx->contact = NULL;
                }

                /* close off base64 */
                if (ctx->in_base64) {
                	contact_base64(ctx, ctx->out, NULL, 1);
                    ctx->in_base64 = 0;
                }

                /* write out mime end if needed */
                if (ctx->in_mime) {
                    apr_brigade_printf(ctx->out, NULL, NULL,
                            CRLF "--%s--" CRLF CRLF, ctx->boundary);
                    ctx->in_mime = 0;
                }

                APR_BRIGADE_CONCAT(ctx->out, ctx->in);
                ctx->seen_eos = 1;
                break;
            }

            if (APR_BUCKET_IS_FLUSH(e)) {
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(ctx->out, e);
                break;
            }

            /*
             * Multipart buckets represent the start of each form element,
             * as well as the end of the previous form element.
             */
            if (AP_BUCKET_IS_MULTIPART(e)) {

                ap_bucket_multipart *h = e->data;

                /* stop ignoring data */
                ctx->ignore = 0;

                /* finish off any previous header */
                if (ctx->in_header) {
                    contact_bucket_set_header(ctx->contact, ctx->header,
                            ctx->filtered);
                    ctx->header = NULL;
                    ctx->in_header = 0;
                }

                if (ctx->in_base64) {
                    contact_base64(ctx, ctx->out, NULL, 1);
                    ctx->in_base64 = 0;
                }

                if (strcasecmp(h->multipart->subtype, "form-data")) {
                    /* not form-data - skip */
                }

                else if (!h->part->dsp_name || !h->part->dsp_name[0]) {
                    /* name missing - skip */
                }

                /* the to address */
                else if ((ctx->state == CONTACT_NONE ||
                        ctx->state == CONTACT_HEADER)
                        && h->part->dsp_name
                        && !strcmp(h->part->dsp_name, "contact-header-to")) {
                    ctx->header = "To";
                    ctx->state = CONTACT_HEADER;
                }

                /* the from address */
                else if ((ctx->state == CONTACT_NONE ||
                        ctx->state == CONTACT_HEADER)
                        && h->part->dsp_name
                        && !strcmp(h->part->dsp_name, "contact-header-from")) {
                    ctx->header = "From";
                    ctx->state = CONTACT_HEADER;
                }

                /* the subject address */
                else if ((ctx->state == CONTACT_NONE
                        || ctx->state == CONTACT_HEADER)
                        && h->part->dsp_name
                        && !strcmp(h->part->dsp_name, "contact-header-subject")) {
                    ctx->header = "Subject";
                    ctx->state = CONTACT_HEADER;
                }

                /* the body field */
                else if ((ctx->state == CONTACT_NONE || ctx->state == CONTACT_HEADER
                        || ctx->state == CONTACT_BODY)
                        && h->part->dsp_name
                        && !strncmp(h->part->dsp_name,
                                "contact-body-", 13)) {

                    /* send contact bucket if unsent */
                    if (ctx->contact) {
                        APR_BRIGADE_INSERT_TAIL(ctx->out, ctx->contact);
                        ctx->contact = NULL;
                    }

                    /* write out mime start */
                    if (ctx->state == CONTACT_NONE
                            || ctx->state == CONTACT_HEADER) {
                        apr_brigade_printf(ctx->out, NULL, NULL,
                                CRLF "--%s" CRLF, ctx->boundary);
                        apr_brigade_puts(ctx->out, NULL, NULL,
                        		"Content-Transfer-Encoding: base64" CRLF CRLF);
                        ctx->in_mime = 1;
                    }

                    /* write out body start */
                    apr_brigade_printf(ctx->filtered, NULL, NULL,
                            "%s:" CRLF, h->part->dsp_name + 13);

                    APR_BRIGADE_PREPEND(ctx->in, ctx->filtered);

                    ctx->in_base64 = 1;

                    ctx->state = CONTACT_BODY;
                }

                /* the attachment field */
                else if ((ctx->state == CONTACT_NONE || ctx->state == CONTACT_HEADER
                        || ctx->state == CONTACT_BODY
                        || ctx->state == CONTACT_ATTACHMENT)
                        && h->part->dsp_name
                        && (!strncmp(h->part->dsp_name,
                                "contact-attachment-", 19)
                                || !strncmp(h->part->dsp_name,
                                        "contact-inline-", 15))) {
//                    ctx->dsp = h->part->dsp_name + 19;

                    /* send contact bucket if unsent */
                    if (ctx->contact) {
                        APR_BRIGADE_INSERT_TAIL(ctx->out, ctx->contact);
                        ctx->contact = NULL;
                    }

                    /* write out mime start */
                    apr_brigade_printf(ctx->out, NULL, NULL,
                            CRLF "--%s" CRLF, ctx->boundary);

                    if (h->part->ct) {
                        apr_brigade_puts(ctx->out, NULL, NULL, "Content-Type: ");
                        apr_brigade_puts(ctx->out, NULL, NULL, h->part->ct);
                        if (h->part->ct_boundary) {
                            apr_brigade_printf(ctx->out, NULL, NULL,
                                    "; boundary=\"%s\"", h->part->ct_boundary);
                        }
                        if (h->part->ct_charset) {
                            apr_brigade_printf(ctx->out, NULL, NULL,
                                    "; charset=\"%s\"", h->part->ct_charset);
                        }
                        apr_brigade_puts(ctx->out, NULL, NULL,
                                CRLF);
                    }

                    if (h->part->dsp) {
                        apr_brigade_puts(ctx->out, NULL, NULL, "Content-Disposition: ");
                        if (h->part->dsp_name[8] == 'a' || h->part->dsp_name[8] == 'A') {
                            apr_brigade_puts(ctx->out, NULL, NULL, "attachment");
                        }
                        else {
                            apr_brigade_puts(ctx->out, NULL, NULL, "inline");
                        }
                        if (h->part->dsp_filename) {
                            apr_brigade_printf(ctx->out, NULL, NULL,
                                    "; filename=\"%s\"", h->part->dsp_filename);
                        }
                        if (h->part->dsp_create) {
                            apr_brigade_printf(ctx->out, NULL, NULL,
                                    "; creation-date=\"%s\"", h->part->dsp_create);
                        }
                        if (h->part->dsp_mod) {
                            apr_brigade_printf(ctx->out, NULL, NULL,
                                    "; modification-date=\"%s\"", h->part->dsp_mod);
                        }
                        if (h->part->dsp_read) {
                            apr_brigade_printf(ctx->out, NULL, NULL,
                                    "; read-date=\"%s\"", h->part->dsp_read);
                        }
                        if (h->part->dsp_size) {
                            apr_brigade_printf(ctx->out, NULL, NULL,
                                    "; size=\"%s\"", h->part->dsp_size);
                        }
                        apr_brigade_puts(ctx->out, NULL, NULL,
                                CRLF);
                    }

                    apr_brigade_puts(ctx->out, NULL, NULL,
                    		"Content-Transfer-Encoding: base64" CRLF CRLF);

                    ctx->in_mime = 1;

                    ctx->in_base64 = 1;

                    ctx->state = CONTACT_ATTACHMENT;
                }

                else {
                    // ignore multipart, and moan

                    ctx->ignore = 1;
                }

                apr_bucket_delete(e);
                continue;
            }

            if (APR_BUCKET_IS_METADATA(e)) {
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(ctx->out, e);
                continue;
            }

            if (ctx->ignore) {
                APR_BUCKET_REMOVE(e);
                apr_bucket_delete(e);
                continue;
            }

            if (ctx->state == CONTACT_HEADER) {

                /*
                 * Chop our bucket up into single lines,
                 * and send each line with our header.
                 */

                rv = apr_brigade_split_boundary(ctx->filtered, ctx->in, block,
                        CRLF, 2, CONTACT_READ_BLOCKSIZE);

                if (rv == APR_INCOMPLETE) {
                    ctx->in_header = 1;
                    continue;
                }
                else if (rv == APR_SUCCESS) {

                    contact_bucket_set_header(ctx->contact, ctx->header,
                            ctx->filtered);

                    ctx->in_header = 0;
                    continue;
                }
                else {
                    return rv;
                }

            }

            if (ctx->state == CONTACT_BODY || ctx->state == CONTACT_ATTACHMENT) {

                /* we convert bodies and attachments to base64, do this here */
                rv = apr_bucket_read(e, &str, &len, block);

                if (rv != APR_SUCCESS) {
                    return rv;
                }

                contact_base64(ctx, ctx->out, e, 0);

                continue;
            }

            /* ordinary data, just pass it through */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->out, e);

        }

//    } while (!ctx->seen_eos);

    /* give the caller the data they asked for from the buffer */
    apr_brigade_partition(ctx->out, readbytes, &after);
    e = APR_BRIGADE_FIRST(ctx->out);
    while (e != after) {
        if (APR_BUCKET_IS_EOS(e)) {
            /* last bucket read, step out of the way */
            ap_remove_input_filter(f);
        }
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = APR_BRIGADE_FIRST(ctx->out);
    }

    return APR_SUCCESS;
}

static int contact_get(request_rec *r)
{

    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    if (!conf->command) {

        /* no command, give up */
        return send_error(r, APR_SUCCESS, HTTP_INTERNAL_SERVER_ERROR,
                "sendmail command not specified");

    }

    return DECLINED;
}

static int contact_post(request_rec *r)
{
    const char * const *args;
    const char * const *env;
    apr_procattr_t *procattr;
    apr_proc_t *proc;
    char *buf;
    apr_bucket_brigade *bb;

    apr_size_t len;
    apr_status_t status;
    int exitcode;
    apr_exit_why_e exitwhy;

    int seen_contact, seen_eos, child_stopped_reading = 0;

    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    if (!conf->command) {

        /* no command, give up */
        return send_error(r, APR_SUCCESS, HTTP_INTERNAL_SERVER_ERROR,
                "sendmail command not specified");
    }

    env = (const char * const *) ap_create_environment(r->pool,
            r->subprocess_env);

    buf = apr_pcalloc(r->pool, sizeof(char *) * (conf->args->nelts + 2));
    args = memcpy(buf, &conf->command, sizeof(char *));
    memcpy(buf + sizeof(char *), conf->args->elts, sizeof(char *)
            * conf->args->nelts);


    if (((status = apr_procattr_create(&procattr, r->pool)) != APR_SUCCESS) ||
            ((status = apr_procattr_io_set(procattr, APR_CHILD_BLOCK,
                    APR_CHILD_BLOCK, APR_CHILD_BLOCK)) != APR_SUCCESS) ||
            ((status = apr_procattr_dir_set(procattr, ap_make_dirstr_parent(
                    r->pool, conf->command))) != APR_SUCCESS) ||
            ((status = apr_procattr_cmdtype_set(procattr, APR_PROGRAM_ENV))
                    != APR_SUCCESS) ||
            ((status = apr_procattr_detach_set(procattr, 0)) != APR_SUCCESS) ||
            ((status = apr_procattr_addrspace_set(procattr, 0))
                    != APR_SUCCESS)) {

        return send_error(r, status, HTTP_INTERNAL_SERVER_ERROR,
                apr_psprintf(r->pool,
                "couldn't set child process attributes: %s", conf->command));
    }

    proc = apr_pcalloc(r->pool, sizeof(*proc));

    status = apr_proc_create(proc, conf->command, args, env, procattr,
            r->pool);
    if (status != APR_SUCCESS) {

        return send_error(r, status, HTTP_INTERNAL_SERVER_ERROR,
                apr_psprintf(r->pool, "Could not run '%s'",
                conf->command));
    }

    apr_pool_note_subprocess(r->pool, proc, APR_KILL_AFTER_TIMEOUT);

    if (!proc->in) {

        return send_error(r, APR_EBADF, HTTP_INTERNAL_SERVER_ERROR,
                "Timeout could not be set on command");
    }
    apr_file_pipe_timeout_set(proc->in, r->server->timeout);

    if (!proc->out) {

        return send_error(r, APR_EBADF, HTTP_INTERNAL_SERVER_ERROR,
                "Timeout could not be set on command");
    }
    apr_file_pipe_timeout_set(proc->out, r->server->timeout);

    if (!proc->err) {

        return send_error(r, APR_EBADF, HTTP_INTERNAL_SERVER_ERROR,
                "Timeout could not be set on command");
    }
    apr_file_pipe_timeout_set(proc->err, r->server->timeout);

    /* set up the contact filter */
    seen_contact = 0;
    seen_eos = 0;

    /* read message from the filter */
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    do {

        status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                APR_BLOCK_READ, HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {
            if (APR_STATUS_IS_TIMEUP(status)) {
                return send_error(r, status, HTTP_REQUEST_TIME_OUT,
                        "Timeout during reading request entity data");
            }
            return send_error(r, status, HTTP_INTERNAL_SERVER_ERROR,
                    "Error reading request entity data");
        }

        while (!APR_BRIGADE_EMPTY(bb)) {

            apr_bucket *e;

            e = APR_BRIGADE_FIRST(bb);

            const char *data;

            if (AP_BUCKET_IS_CONTACT(e)) {
                seen_contact = 1;
            }

            else if (APR_BUCKET_IS_EOS(e)) {
                seen_eos = 1;
                apr_bucket_delete(e);
                break;
            }

            else if (APR_BUCKET_IS_FLUSH(e)) {
                apr_file_flush(proc->in);
                apr_bucket_delete(e);
                continue;
            }

            /* If the child stopped, we still must read to EOS. */
            if (child_stopped_reading) {
                apr_bucket_delete(e);
                continue;
            }

            /* if no contact bucket? send headers manually */
            if (!seen_contact) {
// FIXME
                seen_contact = 1;
            }

            /* read */
            apr_bucket_read(e, &data, &len, APR_BLOCK_READ);

            /* Keep writing data to the child until done or too much time
             * elapses with no progress or an error occurs.
             */
            status = apr_file_write_full(proc->in, data, len, NULL);

            if (status != APR_SUCCESS) {

                /* silly script stopped reading, soak up remaining message */
                child_stopped_reading = 1;

            }

            apr_bucket_delete(e);
        }

    } while (!seen_eos);

    /* Is this flush really needed? */
    apr_file_flush(proc->in);
    apr_file_close(proc->in);

    status = APR_SUCCESS;
    while (APR_SUCCESS == status) {
        char err[MAX_STRING_LEN];

        status = apr_file_read_full(proc->err, err, sizeof(err), &len);

        if (status == APR_SUCCESS && len > 0) {
// FIXME: log successful sending of email
            //            log_message(r, status, apr_psprintf(r->pool, "%s: %s",
//                    conf->command, apr_pstrmemdup(r->pool, err, len)));
        }

    }

    /* how did sendmail do? */
    apr_proc_wait(proc, &exitcode, &exitwhy, APR_WAIT);
    if (exitcode || APR_PROC_EXIT != exitwhy) {
        return send_error(
                r,
                APR_SUCCESS, HTTP_INTERNAL_SERVER_ERROR,
                apr_psprintf(
                        r->pool,
                        "%s %s with code %d",
                        conf->command,
                        APR_PROC_EXIT == exitwhy ? "exited normally"
                                : APR_PROC_SIGNAL == exitwhy ? "exited due to a signal"
                                        : APR_PROC_SIGNAL_CORE == exitwhy ? "exited and dumped a core file"
                                                : "exited", exitcode));
    }

    /* did the client bail out? */
    if (child_stopped_reading) {
        return send_error(r, status, HTTP_INTERNAL_SERVER_ERROR,
                "Sendmail stopped reading message, aborting");
    }

    /* add a Location header to the message status */
//    if (conf->dsn_location) {
//        apr_table_set(r->headers_out, "Location", apr_pstrcat(r->pool,
//                conf->dsn_location, "/", ap_escape_path_segment(r->pool,
//                        message_id), "/", NULL));
//        return HTTP_SEE_OTHER;
//    }

    return HTTP_OK;
}

static int contact_handler(request_rec *r)
{

    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    if (!conf) {
        return DECLINED;
    }

    if (strcmp(r->handler, "contact")) {
        return DECLINED;
    }

    ap_allow_methods(r, 1, "POST", "GET", NULL);

    if (!strcmp(r->method, "GET")) {
        return contact_get(r);
    }
    else if (!strcmp(r->method, "POST")) {
        return contact_post(r);
    }
    else {
        return HTTP_METHOD_NOT_ALLOWED;
    }

}



static void register_hooks(apr_pool_t *p)
{
    ap_register_input_filter("CONTACT", contact_in_filter, init_contact,
                             AP_FTYPE_RESOURCE);
    ap_hook_handler(contact_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_input_filter("MULTIPART", multipart_in_filter, NULL,
                              AP_FTYPE_CONTENT_SET);
}

module AP_MODULE_DECLARE_DATA contact_module =
{
    STANDARD20_MODULE_STUFF,
    create_contact_dir_config,  /* dir config creater */
    merge_contact_dir_config,   /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    contact_cmds,               /* command apr_table_t */
    register_hooks              /* register hooks */
};
