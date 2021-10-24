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
 * Example configuration:
 *
 * <IfModule !multipart_module>
 *   LoadModule multipart_module modules/mod_multipart.so
 * </IfModule>
 * <IfModule !contact_module>
 *   LoadModule contact_module modules/mod_contact.so
 * </IfModule>
 *
 * <Location /contact/hello/>
 *   SetHandler contact
 *   SetInputFilter CONTACT;MULTIPART
 *   ContactStylesheet /contact/contact.xsd
 * #  ContactToMatch ^hello@example.com$
 * #  ContactFromMatch ^webmaster@hostingprovider.com$
 *   ContactTo recipient@destination.com
 *   ContactFrom webmaster@hostingprovider.com
 *   ContactArguments -t
 * </Location>
 *
 */

#include <apu_version.h>
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 7)
#include <apr_encode.h>
#else
#include <apr_base64.h>
#endif

#include <apr_escape.h>
#include <apr_hash.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include "httpd.h"
//#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "ap_expr.h"

#include "mod_multipart.h"

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"

module AP_MODULE_DECLARE_DATA contact_module;

#define DEFAULT_COMMAND "/usr/sbin/sendmail"
#define DEFAULT_ARGUMENT "-t"

#define MULTIPART_READ_BLOCKSIZE      16384    /* used for reading input blocks */
#define CONTACT_READ_BLOCKSIZE        16384    /* used for reading input blocks */
#define CONTACT_NAMESPACE             "https://github.com/minfrin/mod_contact"

typedef struct
{
    int stylesheet_set:1;
    int command_set:1;
    int args_set:1;
    int to_set:1;
    int to_match_set:1;
    int from_set:1;
    int from_match_set:1;
    int sender_set:1;
    int replyto_set:1;
    ap_expr_info_t *stylesheet;
    const char *command;
    apr_array_header_t *args;
    ap_expr_info_t *to;
    ap_regex_t *to_match;
    ap_expr_info_t *from;
    ap_regex_t *from_match;
    ap_expr_info_t *sender;
    ap_expr_info_t *replyto;
    int should_write_form;
} contact_config_rec;

#define APR_BUCKETS_STRING -1

#if 0
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
#endif


#ifndef HAVE_APR_BRIGADE_SPLIT_BOUNDARY

#define APR_BUCKETS_STRING -1

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
 * @param boundary_len The length of the boundary string. If set to
 *        APR_BUCKETS_STRING, the length will be calculated.
 * @param maxbytes The maximum bytes to read.
 */
apr_status_t apr_brigade_split_boundary(apr_bucket_brigade *bbOut,
                                        apr_bucket_brigade *bbIn,
                                        apr_read_type_e block,
                                        const char *boundary,
                                        apr_size_t boundary_len,
                                        apr_off_t maxbytes)
{
    apr_off_t outbytes = 0;
    apr_off_t ignore = 0;

    if (!boundary || !boundary[0]) {
        return APR_EINVAL;
    }

    if (APR_BUCKETS_STRING == boundary_len) {
        boundary_len = strlen(boundary);
    }

    /*
     * While the call describes itself as searching for a boundary string,
     * what we actually do is search for anything that is definitely not
     * a boundary string, and allow that not-boundary data to pass through.
     *
     * If we find data that might be a boundary, we try read more data in
     * until we know for sure.
     */
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
        if ((len - ignore) >= boundary_len) {

            apr_size_t off;
            apr_size_t leftover;

            pos = memmem(str + ignore, len - ignore, boundary, boundary_len);

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
                if (!memcmp(str + off, boundary, leftover)) {

                    if (off) {

                        apr_bucket_split(e, off);
                        APR_BUCKET_REMOVE(e);
                        APR_BRIGADE_INSERT_TAIL(bbOut, e);
                        ignore = 0;

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
            ignore = 0;

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

            apr_size_t off = ignore;

            len -= ignore;

            /* find all definite non matches */
            while (len) {
                if (!memcmp(str + off, boundary, len)) {

                    if (off) {

                        apr_bucket_split(e, off);
                        APR_BUCKET_REMOVE(e);
                        APR_BRIGADE_INSERT_TAIL(bbOut, e);
                        ignore = 0;

                        outbytes += off;

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
            ignore = 0;

            outbytes += off;

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
                if (memcmp(str, boundary + inbytes, off)) {
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
                if (memcmp(str, boundary + inbytes, off)) {
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
                if (memcmp(str, boundary + inbytes, len)) {
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
        ignore++;

    }

    return APR_INCOMPLETE;
}
#endif






static void send_open(request_rec *r, apr_bucket_brigade *bb, int res)
{
    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    conf->should_write_form = 1;

    ap_set_content_type(r, "text/xml");

    r->status = res;

    apr_brigade_puts(bb, NULL, NULL,
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>"
            CRLF);

    if (conf->stylesheet) {
        const char *err = NULL, *stylesheet;

        stylesheet = ap_expr_str_exec(r, conf->stylesheet, &err);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                            "Failure while evaluating the stylesheet URL expression for '%s', "
                            "stylesheet ignored: %s", r->uri, err);
        }
        else {
            apr_brigade_puts(bb, NULL, NULL, "<?xml-stylesheet type=\"text/xsl\" href=\"");
            apr_brigade_puts(bb, NULL, NULL, ap_escape_html(r->pool, stylesheet));
            apr_brigade_puts(bb, NULL, NULL, "\"?>" CRLF);
        }

    }

    apr_brigade_puts(bb, NULL, NULL,
            "<contact xmlns=\"" CONTACT_NAMESPACE "\"><form>");

    ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
}

static void send_close(request_rec *r, apr_bucket_brigade *bb, int res,
        const char *message)
{
    conn_rec *c = r->connection;
    apr_bucket *e;

    const char *error = apr_table_get(r->notes, "error-notes");

    apr_brigade_printf(bb, NULL, NULL, "</form><code>%d</code>"
            "<status>%s</status><message>%s</message></contact>" CRLF, res,
            ap_get_status_line(res),
            apr_pescape_entity(r->pool, error ? error : message, 0));

    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
}

static int send_error(request_rec *r, apr_bucket_brigade *bb, int res,
        apr_status_t status, const char *message)
{
    int rv;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "%s", message);

    send_open(r, bb, res);

    if ((rv = ap_discard_request_body(r)) != OK) {
        return rv;
    }

    send_close(r, bb, res, message);

    return OK;
}

static void contact_form_open(request_rec *r, const char *name)
{
    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    if (conf->should_write_form) {
        ap_rputs("<input name=\"", r);
        ap_rputs(apr_pescape_entity(r->pool, name, 0), r);
        ap_rputs("\">", r);
    }
}

static void contact_form_write(request_rec *r, apr_bucket *e)
{
    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    if (conf->should_write_form) {
        const char *str;
        apr_size_t len;

        if (APR_SUCCESS == apr_bucket_read(e, &str, &len, APR_BLOCK_READ) && len > 0) {

            apr_size_t elen;

            if (APR_SUCCESS == apr_escape_entity(NULL, str, len, 1, &elen)) {
                char *buf = apr_palloc(r->pool, elen);
                apr_escape_entity(buf, str, len, 1, &elen);
                ap_rwrite(buf, elen, r);
            }
            else {
                ap_rwrite(str, len, r);
            }
        }
    }
}

static void contact_form_brigade(request_rec *r, apr_bucket_brigade *bb)
{
    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    if (conf->should_write_form) {
        apr_bucket *e;

        for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb); e
                = APR_BUCKET_NEXT(e)) {
            contact_form_write(r, e);
        }
    }
}

static void contact_form_close(request_rec *r)
{
    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    if (conf->should_write_form) {
        ap_rputs("</input>", r);
    }
}

static void *create_contact_dir_config(apr_pool_t *p, char *d)
{
    contact_config_rec *conf = apr_pcalloc(p, sizeof(contact_config_rec));

    const char **array;

    conf->command = DEFAULT_COMMAND;
    conf->args = apr_array_make(p, 8, sizeof(const char * const *));

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

    new->stylesheet = (add->stylesheet_set == 0) ? base->stylesheet : add->stylesheet;
    new->stylesheet_set = add->stylesheet_set || base->stylesheet_set;
    new->command = (add->command_set == 0) ? base->command : add->command;
    new->command_set = add->command_set || base->command_set;
    new->args = (add->args_set == 0) ? base->args
            : add->args;
    new->args_set = add->args_set || base->args_set;
    new->to = (add->to_set == 0) ? base->to : add->to;
    new->to_set = add->to_set || base->to_set;
    new->to_match = (add->to_match_set == 0) ? base->to_match : add->to_match;
    new->to_match_set = add->to_match_set || base->to_match_set;
    new->from = (add->from_set == 0) ? base->from
            : add->from;
    new->from_set = add->from_set || base->from_set;
    new->from_match = (add->from_match_set == 0) ? base->from_match : add->from_match;
    new->from_match_set = add->from_match_set || base->from_match_set;
    new->sender = (add->sender_set == 0) ? base->sender
            : add->sender;
    new->sender_set = add->sender_set || base->sender_set;
    new->replyto = (add->replyto_set == 0) ? base->replyto
            : add->replyto;
    new->replyto_set = add->replyto_set || base->replyto_set;

    return new;
}

static const char *set_stylesheet(cmd_parms *cmd, void *dconf, const char *stylesheet)
{
    contact_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->stylesheet = ap_expr_parse_cmd(cmd, stylesheet, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", stylesheet, "': ",
                expr_err, NULL);
    }

    conf->stylesheet_set = 1;

    return NULL;
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

static const char *set_to(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->to = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);;
    conf->to_set = 1;

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool, "Cannot parse expression '",
                arg, "': ", expr_err, NULL);
    }

    return NULL;
}

static const char *set_to_match(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;

    conf->to_match = ap_pregcomp(cmd->pool, arg, AP_REG_EXTENDED | AP_REG_ICASE);
    conf->to_match_set = 1;

    if (!conf->to_match) {
        return apr_pstrcat(cmd->temp_pool, "Cannot parse regular expression '",
                arg, "'", NULL);
    }

    return NULL;
}

static const char *set_from(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->from = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);;
    conf->from_set = 1;

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool, "Cannot parse expression '",
                arg, "': ", expr_err, NULL);
    }

    return NULL;
}

static const char *set_from_match(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;

    conf->from_match = ap_pregcomp(cmd->pool, arg, AP_REG_EXTENDED | AP_REG_ICASE);
    conf->from_match_set = 1;

    if (!conf->from_match) {
        return apr_pstrcat(cmd->temp_pool, "Cannot parse regular expression '",
                arg, "'", NULL);
    }

    return NULL;
}

static const char *set_sender(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->sender = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);;
    conf->sender_set = 1;

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool, "Cannot parse expression '",
                arg, "': ", expr_err, NULL);
    }

    return NULL;
}

static const char *set_replyto(cmd_parms *cmd, void *dconf, const char *arg)
{
    contact_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->replyto = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);;
    conf->replyto_set = 1;

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool, "Cannot parse expression '",
                arg, "': ", expr_err, NULL);
    }

    return NULL;
}

static const command_rec contact_cmds[] =
{
AP_INIT_TAKE1("ContactStylesheet", set_stylesheet, NULL,
        RSRC_CONF | ACCESS_CONF,
        "Set the XSLT stylesheet to be used when rendering the output."),
AP_INIT_TAKE1("ContactCommand",
        set_command, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to the name and path of the sendmail binary."),
AP_INIT_ITERATE(
        "ContactArguments", set_args, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to arguments to pass to the sendmail binary."),
AP_INIT_TAKE1("ContactTo",
        set_to, NULL, RSRC_CONF | ACCESS_CONF,
        "Expression resolving to the To address. Overridden by 'contact-header-to' in a form."),
AP_INIT_TAKE1("ContactToMatch",
        set_to_match, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to a regular expression that the To address must match."),
AP_INIT_TAKE1("ContactFrom",
        set_from, NULL, RSRC_CONF | ACCESS_CONF,
        "Expression resolving to the From address. Overridden by 'contact-header-from' in a form."),
AP_INIT_TAKE1("ContactFromMatch",
        set_from_match, NULL, RSRC_CONF | ACCESS_CONF,
        "Set to a regular expression that the From address must match."),
AP_INIT_TAKE1("ContactSender",
        set_sender, NULL, RSRC_CONF | ACCESS_CONF,
        "Expression resolving to the Sender email address. Overridden by 'contact-header-sender' in a form."),
AP_INIT_TAKE1("ContactReplyTo",
        set_replyto, NULL, RSRC_CONF | ACCESS_CONF,
        "Expression resolving to the Reply-To email address. Overridden by 'contact-header-replyto' in a form."),
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
ap_bucket_contact_make(apr_bucket *b, request_rec *r,
        apr_table_t *headers);

/**
 * Create a bucket referring to multipart metadata.
 *
 * @param list The freelist from which this bucket should be allocated
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket*)
ap_bucket_contact_create(apr_bucket_alloc_t *list, request_rec *r,
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
};

static apr_status_t contact_bucket_cleanup(void *data)
{
    ap_bucket_contact *h = data;

    /* if pool is cleaned up before the bucket, gracefully zero
     * out the pool and headers so we become of zero length.
     */
    h->headers = NULL;
    h->r = NULL;

    return APR_SUCCESS;
}

AP_DECLARE(apr_bucket *) ap_bucket_contact_make(apr_bucket *b,
        request_rec *r, apr_table_t *headers)
{
    ap_bucket_contact *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->headers = headers;

    h->r = r;
    h->list = b->list;

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_contact;

    /* pre-initialize heap bucket member */
    h->heap.alloc_len     = 0;
    h->heap.base = h->end = NULL;
    h->heap.base          = NULL;
    h->heap.free_func     = apr_bucket_free;

    apr_pool_cleanup_register(h->r->pool, h, contact_bucket_cleanup,
                              apr_pool_cleanup_null);
    return b;
}

AP_DECLARE(apr_bucket*) ap_bucket_contact_create(apr_bucket_alloc_t *list,
        request_rec *r, apr_table_t *headers)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b = ap_bucket_contact_make(b, r, headers);
    return b;
}

static void contact_bucket_destroy(void *data)
{
    ap_bucket_contact *h = data;

    if (apr_bucket_shared_destroy(h)) {

        /* if bucket is cleaned up before the pool, we deregister the
         * cleanuo and vanish from existence.
         */
        if (h->r) {
            apr_pool_cleanup_kill(h->r->pool, h, contact_bucket_cleanup);
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

    if (!strcasecmp(key, "To")) {

        contact_config_rec *conf = ap_get_module_config(h->r->per_dir_config,
                &contact_module);

        if (conf->to_match && ap_regexec(conf->to_match, value, 0, NULL, 0)) {

            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, h->r,
                    "contact: To address '%s' does not match ContactToMatch filter, ignoring.",
                    value);

            apr_table_setn(h->r->notes, "verbose-error-to", "*");

            apr_table_setn(h->r->notes, "error-notes",
                    apr_pescape_entity(h->r->pool,
                            apr_pstrcat(h->r->pool, "To address '", value,
                                "' is not valid, giving up.", NULL),
                                0));

            return 0;
        }

    }

    if (!strcasecmp(key, "From")) {

        contact_config_rec *conf = ap_get_module_config(h->r->per_dir_config,
                &contact_module);

        if (conf->from_match && ap_regexec(conf->from_match, value, 0, NULL, 0)) {

            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, h->r,
                    "contact: From address '%s' does not match ContactFromMatch filter, ignoring.",
                    value);

            apr_table_setn(h->r->notes, "verbose-error-to", "*");

            apr_table_setn(h->r->notes, "error-notes",
                    apr_pescape_entity(h->r->pool,
                            apr_pstrcat(h->r->pool, "From address '", value,
                                "' is not valid, giving up.", NULL),
                                0));

            return 0;
        }

    }

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
    request_rec *r = h->r;
    const char *from = NULL;
    const char *received = NULL;

    int ok = 1;

    if (!h->heap.base && h->headers) {

        contact_config_rec *conf = ap_get_module_config(h->r->per_dir_config,
                &contact_module);

        const char *expr_err = NULL;

        /* if headers are missing, set them from our config */

        if (conf->to && !apr_table_get(h->headers, "To")) {

            apr_table_set(h->headers, "To",
                    ap_expr_str_exec(h->r, conf->to, &expr_err));

            if (expr_err) {

                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, h->r,
                        "contact: To expression cannot be set: %s",
                        expr_err);

                apr_table_setn(h->r->notes, "verbose-error-to", "*");
                apr_table_setn(h->r->notes, "error-notes", "To expression "
                                " is not valid, giving up.");

            }

        }

        if (conf->from && !(from = apr_table_get(h->headers, "From"))) {

            apr_table_set(h->headers, "From",
                    (from = ap_expr_str_exec(h->r, conf->from, &expr_err)));

            if (expr_err) {

                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, h->r,
                        "contact: From expression cannot be set: %s",
                        expr_err);

                apr_table_setn(h->r->notes, "verbose-error-to", "*");
                apr_table_setn(h->r->notes, "error-notes", "From expression "
                                " is not valid, giving up.");

            }

        }

        if (conf->sender && !apr_table_get(h->headers, "Sender")) {

            apr_table_set(h->headers, "Sender",
                    ap_expr_str_exec(h->r, conf->sender, &expr_err));

            if (expr_err) {

                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, h->r,
                        "contact: Sender expression cannot be set: %s",
                        expr_err);

                apr_table_setn(h->r->notes, "verbose-error-to", "*");
                apr_table_setn(h->r->notes, "error-notes", "Sender expression "
                                " is not valid, giving up.");

            }

        }

        if (conf->replyto && !apr_table_get(h->headers, "Reply-To")) {

            apr_table_set(h->headers, "Reply-To",
                    ap_expr_str_exec(h->r, conf->replyto, &expr_err));

            if (expr_err) {

                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, h->r,
                        "contact: Reply-To expression cannot be set: %s",
                        expr_err);

                apr_table_setn(h->r->notes, "verbose-error-to", "*");
                apr_table_setn(h->r->notes, "error-notes", "Reply-To expression "
                                " is not valid, giving up.");

            }

        }

        /* add a received header */
        if (from) {
            char date_str[APR_RFC822_DATE_LEN];

            ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_DOUBLE_REV,
                    NULL);
            apr_rfc822_date(date_str, apr_time_now());

            received = apr_pstrcat(r->pool, "Received: from [",
                r->connection->client_ip, "] (",
                r->connection->remote_host ? r->connection->remote_host
                        : r->connection->client_ip, " [", r->connection->client_ip,
                "])\n\t", r->user ? "(Authenticated sender: " : "",
                r->user ? r->user : "", r->user ? ")\n\t" : "", "by ",
                r->server->server_hostname ? r->server->server_hostname
                        : r->connection->local_ip, " (mod_contact)\n\tfor ", from,
                "; ", date_str, CRLF, NULL);

        }

        /* render headers, morph into heap bucket */
        h->heap.alloc_len = strlen(CRLF);
        if (received) {
            h->heap.alloc_len += strlen(received);
        }
        apr_table_do(contact_bucket_count, h, h->headers, NULL);
        h->heap.base = h->end = apr_bucket_alloc(h->heap.alloc_len, h->list);
        if (received) {
            h->end = stpcpy(h->end, received);
        }
        ok = apr_table_do(contact_bucket_do, h, h->headers, NULL);
        h->end = stpcpy(h->end, CRLF);
        b->length = h->heap.alloc_len;
        b->type = &apr_bucket_type_heap;
        h->headers = NULL;
        h->r = NULL;
    }

    *str = h->heap.base + b->start;
    *len = b->length;

    if (ok) {
        return APR_SUCCESS;
    }
    else {
        return APR_EINVAL;
    }
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
    int in_form:1;
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

            char buf[79+1];
            apr_size_t buf_len;

#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 7)
            apr_encode_base64(buf, ctx->base64, ctx->base64_off, APR_ENCODE_NONE,
                    &buf_len);
#else
            buf_len = apr_base64_encode(buf, ctx->base64, ctx->base64_off) - 1;
#endif

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
    request_rec *r = f->r;

    apr_uint64_t val[2];

    ap_random_insecure_bytes(&val, sizeof(val));

    ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    ctx->in = apr_brigade_create(r->pool, f->c->bucket_alloc);
    ctx->filtered = apr_brigade_create(r->pool, f->c->bucket_alloc);
    ctx->out = apr_brigade_create(r->pool, f->c->bucket_alloc);
    ctx->headers = apr_table_make(r->pool, 4);
    ctx->contact = ap_bucket_contact_create(
             r->connection->bucket_alloc, r, ctx->headers);
    ctx->boundary = apr_psprintf(r->pool, "%0" APR_UINT64_T_HEX_FMT
            "%0" APR_UINT64_T_HEX_FMT, val[0], val[1]);

    apr_table_setn(ctx->headers, "MIME-Version", "1.0");

    apr_table_setn(ctx->headers, "Content-Type",
            apr_psprintf(r->pool, "multipart/mixed; boundary=\"%s\"",
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

                if (ctx->in_form) {
                    contact_form_close(f->r);
                    ctx->in_form = 0;
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

                /* finish off any previous body */
                if (ctx->state == CONTACT_BODY) {
                    apr_bucket *b = apr_bucket_immortal_create(CRLF, 2,
                            f->c->bucket_alloc);
                    contact_base64(ctx, ctx->out, b, 0);
                }

                if (ctx->in_base64) {
                    contact_base64(ctx, ctx->out, NULL, 1);
                    ctx->in_base64 = 0;
                }

                if (ctx->in_form) {
                    contact_form_close(f->r);
                    ctx->in_form = 0;
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
                    ctx->in_form = 1;
                }

                /* the from address */
                else if ((ctx->state == CONTACT_NONE ||
                        ctx->state == CONTACT_HEADER)
                        && h->part->dsp_name
                        && !strcmp(h->part->dsp_name, "contact-header-from")) {
                    ctx->header = "From";
                    ctx->state = CONTACT_HEADER;
                    ctx->in_form = 1;
                }

                /* the sender address */
                else if ((ctx->state == CONTACT_NONE ||
                        ctx->state == CONTACT_HEADER)
                        && h->part->dsp_name
                        && !strcmp(h->part->dsp_name, "contact-header-sender")) {
                    ctx->header = "Sender";
                    ctx->state = CONTACT_HEADER;
                    ctx->in_form = 1;
                }

                /* the replyto address */
                else if ((ctx->state == CONTACT_NONE ||
                        ctx->state == CONTACT_HEADER)
                        && h->part->dsp_name
                        && !strcmp(h->part->dsp_name, "contact-header-replyto")) {
                    ctx->header = "Reply-To";
                    ctx->state = CONTACT_HEADER;
                    ctx->in_form = 1;
                }

                /* the subject address */
                else if ((ctx->state == CONTACT_NONE
                        || ctx->state == CONTACT_HEADER)
                        && h->part->dsp_name
                        && !strcmp(h->part->dsp_name, "contact-header-subject")) {
                    ctx->header = "Subject";
                    ctx->state = CONTACT_HEADER;
                    ctx->in_form = 1;
                }

                /* the body field */
                else if ((ctx->state == CONTACT_NONE || ctx->state == CONTACT_HEADER
                        || ctx->state == CONTACT_BODY)
                        && h->part->dsp_name
                        && !strncmp(h->part->dsp_name,
                                "contact-body-", 13)) {

                    apr_bucket *b;

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
                                "Content-Type: text/plain; charset=\"UTF-8\"" CRLF);
                        apr_brigade_puts(ctx->out, NULL, NULL,
                                "Content-Transfer-Encoding: base64" CRLF CRLF);
                        ctx->in_mime = 1;
                    }

                    /* write out body start */
                    b = apr_bucket_heap_create(h->part->dsp_name + 13,
                            strlen(h->part->dsp_name + 13), NULL, f->c->bucket_alloc);
                    contact_base64(ctx, ctx->out, b, 0);
                    b = apr_bucket_immortal_create(":" CRLF, 3,
                            f->c->bucket_alloc);
                    contact_base64(ctx, ctx->out, b, 0);

                    ctx->in_base64 = 1;
                    ctx->in_form = 1;
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

                if (ctx->in_form) {
                    contact_form_open(f->r, h->part->dsp_name);
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

                    if (ctx->in_form) {
                        contact_form_brigade(f->r, ctx->filtered);
                    }

                    continue;
                }
                else if (rv == APR_SUCCESS) {

                    if (ctx->in_form) {
                        contact_form_brigade(f->r, ctx->filtered);
                    }

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

                if (ctx->in_form) {
                    contact_form_write(f->r, e);
                }

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

    apr_bucket_brigade *bbOut;

    bbOut = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    if (!conf->command) {

        /* no command, give up */
        return send_error(r, bbOut, APR_SUCCESS, HTTP_INTERNAL_SERVER_ERROR,
                "sendmail command not specified");

    }

    send_open(r, bbOut, HTTP_OK);
    send_close(r, bbOut, HTTP_OK, "");

    return OK;
}

static int contact_post(request_rec *r)
{
    const char * const *args;
    const char * const *env;
    apr_procattr_t *procattr;
    apr_proc_t *proc;
    char **buf;
    apr_bucket_brigade *bb;
    apr_bucket_brigade *bbOut;
    const char *message = "Message sent successfully";

    apr_size_t len;
    apr_status_t status;
    int code = HTTP_OK;
    int exitcode;
    apr_exit_why_e exitwhy;

    int seen_contact, seen_eos, child_stopped_reading = 0;

    contact_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &contact_module);

    bbOut = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    if (!conf->command) {

        /* no command, give up */
        return send_error(r, bbOut, APR_SUCCESS, HTTP_INTERNAL_SERVER_ERROR,
                "sendmail command not specified");
    }

    env = (const char * const *) ap_create_environment(r->pool,
            r->subprocess_env);

    buf = apr_pcalloc(r->pool, sizeof(char *) * (conf->args->nelts + 2));
    args = memcpy(buf, &conf->command, sizeof(char *));
    memcpy(buf + 1, conf->args->elts, sizeof(char *)
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

        return send_error(r, bbOut, status, HTTP_INTERNAL_SERVER_ERROR,
                apr_psprintf(r->pool,
                "couldn't set child process attributes: %s", conf->command));
    }

    proc = apr_pcalloc(r->pool, sizeof(*proc));

    status = apr_proc_create(proc, conf->command, args, env, procattr,
            r->pool);
    if (status != APR_SUCCESS) {

        return send_error(r, bbOut, status, HTTP_INTERNAL_SERVER_ERROR,
                apr_psprintf(r->pool, "Could not run '%s'",
                conf->command));
    }

    apr_pool_note_subprocess(r->pool, proc, APR_KILL_AFTER_TIMEOUT);

    if (!proc->in) {

        return send_error(r, bbOut, APR_EBADF, HTTP_INTERNAL_SERVER_ERROR,
                "Timeout could not be set on command");
    }
    apr_file_pipe_timeout_set(proc->in, r->server->timeout);

    if (!proc->out) {

        return send_error(r, bbOut, APR_EBADF, HTTP_INTERNAL_SERVER_ERROR,
                "Timeout could not be set on command");
    }
    apr_file_pipe_timeout_set(proc->out, r->server->timeout);

    if (!proc->err) {

        return send_error(r, bbOut, APR_EBADF, HTTP_INTERNAL_SERVER_ERROR,
                "Timeout could not be set on command");
    }
    apr_file_pipe_timeout_set(proc->err, r->server->timeout);

    /* set up the contact filter */
    seen_contact = 0;
    seen_eos = 0;

    /* we're committed from this point */
    send_open(r, bbOut, HTTP_ACCEPTED);

    /* read message from the filter */
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    do {

        status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                APR_BLOCK_READ, HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {

            code = ap_map_http_request_error(status, HTTP_BAD_REQUEST);

            message = "Error while reading request";

            break;
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

    if (HTTP_OK == code) {
        /* success! close out gracefully */
        apr_file_flush(proc->in);
        apr_file_close(proc->in);
    }
    else {
        /* close in the cleanup, after the term has been ack'ed */
        apr_proc_kill(proc, SIGTERM);
    }

    /* soak up stderr from sendmail */
    status = APR_SUCCESS;
    while (APR_SUCCESS == status) {
        char err[MAX_STRING_LEN];

        status = apr_file_read_full(proc->err, err, sizeof(err), &len);

        if (status == APR_SUCCESS && len > 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "contact: %*s",
                    (int) len, err);
        }

    }

    /* how did sendmail do? */
    apr_proc_wait(proc, &exitcode, &exitwhy, APR_WAIT);
    if (exitcode || APR_PROC_EXIT != exitwhy) {

        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, "%s %s with code %d",
            conf->command,
            APR_PROC_EXIT == exitwhy ? "exited normally" :
            APR_PROC_SIGNAL == exitwhy ? "exited due to a signal" :
            APR_PROC_SIGNAL_CORE == exitwhy ?
                    "exited and dumped a core file" : "exited", exitcode);

        message = apr_psprintf(r->pool, "sendmail exited with code %d", exitcode);
        code = HTTP_BAD_REQUEST;

        send_close(r, bbOut, code, message);

        return OK;
    }

    /* did the client bail out? */
    else if (child_stopped_reading) {
        send_close(r, bbOut, HTTP_INTERNAL_SERVER_ERROR,
                "Sendmail stopped reading message, aborting");
        return OK;
    }

    /* we're done */
    send_close(r, bbOut, HTTP_OK, "Message accepted");

    /* add a Location header to the message status */
//    if (conf->dsn_location) {
//        apr_table_set(r->headers_out, "Location", apr_pstrcat(r->pool,
//                conf->dsn_location, "/", ap_escape_path_segment(r->pool,
//                        message_id), "/", NULL));
//        return HTTP_SEE_OTHER;
//    }

    return OK;
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
