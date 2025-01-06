/*
 * ModSecurity connector for nginx, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"
#include <string.h>
#include "tokenizer.c"
#include <tensorflow/c/c_api.h>
#include "ngx_http_modsecurity_common.h"

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_modsecurity_resolv_header_server(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_date(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_content_length(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_content_type(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_last_modified(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_connection(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_str_t name, off_t offset);
static ngx_int_t ngx_http_modsecurity_resolv_header_vary(ngx_http_request_t *r, ngx_str_t name, off_t offset);

ngx_http_modsecurity_header_out_t ngx_http_modsecurity_headers_out[] = {

    { ngx_string("Server"),
            offsetof(ngx_http_headers_out_t, server),
            ngx_http_modsecurity_resolv_header_server },

    { ngx_string("Date"),
            offsetof(ngx_http_headers_out_t, date),
            ngx_http_modsecurity_resolv_header_date },

    { ngx_string("Content-Length"),
            offsetof(ngx_http_headers_out_t, content_length_n),
            ngx_http_modsecurity_resolv_header_content_length },

    { ngx_string("Content-Type"),
            offsetof(ngx_http_headers_out_t, content_type),
            ngx_http_modsecurity_resolv_header_content_type },

    { ngx_string("Last-Modified"),
            offsetof(ngx_http_headers_out_t, last_modified),
            ngx_http_modsecurity_resolv_header_last_modified },

    { ngx_string("Connection"),
            0,
            ngx_http_modsecurity_resolv_header_connection },

    { ngx_string("Transfer-Encoding"),
            0,
            ngx_http_modsecurity_resolv_header_transfer_encoding },

    { ngx_string("Vary"),
            0,
            ngx_http_modsecurity_resolv_header_vary },

#if 0
    { ngx_string("Content-Encoding"),
            offsetof(ngx_http_headers_out_t, content_encoding),
            NGX_TABLE },

    { ngx_string("Cache-Control"),
            offsetof(ngx_http_headers_out_t, cache_control),
            NGX_ARRAY },

    { ngx_string("Location"),
            offsetof(ngx_http_headers_out_t, location),
            NGX_TABLE },

    { ngx_string("Content-Range"),
            offsetof(ngx_http_headers_out_t, content_range),
            NGX_TABLE },

    { ngx_string("Accept-Ranges"),
            offsetof(ngx_http_headers_out_t, accept_ranges),
            NGX_TABLE },

    returiders_out[i].name 1;
    { ngx_string("WWW-Authenticate"),
            offsetof(ngx_http_headers_out_t, www_authenticate),
            NGX_TABLE },

    { ngx_string("Expires"),
            offsetof(ngx_http_headers_out_t, expires),
            NGX_TABLE },
#endif
    { ngx_null_string, 0, 0 }
};


#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
int
ngx_http_modsecurity_store_ctx_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value)
{
    ngx_http_modsecurity_ctx_t     *ctx;
    ngx_http_modsecurity_conf_t    *mcf;
    ngx_http_modsecurity_header_t  *hdr;

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL || ctx->sanity_headers_out == NULL) {
        return NGX_ERROR;
    }

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->sanity_checks_enabled == NGX_CONF_UNSET)
    {
        return NGX_OK;
    }

    hdr = ngx_array_push(ctx->sanity_headers_out);
    if (hdr == NULL) {
        return NGX_ERROR;
    }

    hdr->name.data = ngx_pnalloc(r->pool, name->len);
    hdr->value.data = ngx_pnalloc(r->pool, value->len);
    if (hdr->name.data == NULL || hdr->value.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(hdr->name.data, name->data, name->len);
    hdr->name.len = name->len;
    ngx_memcpy(hdr->value.data, value->data, value->len);
    hdr->value.len = value->len;

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_http_modsecurity_resolv_header_server(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    static char ngx_http_server_full_string[] = NGINX_VER;
    static char ngx_http_server_string[] = "nginx";

    ngx_http_core_loc_conf_t *clcf = NULL;
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_str_t value;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens) {
            value.data = (u_char *)ngx_http_server_full_string;
            value.len = sizeof(ngx_http_server_full_string);
        } else {
            value.data = (u_char *)ngx_http_server_string;
            value.len = sizeof(ngx_http_server_string);
        }
    } else {
        ngx_table_elt_t *h = r->headers_out.server;
        value.data = h->value.data;
        value.len =  h->value.len;
    }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) value.data,
        value.len);
}


static ngx_int_t
ngx_http_modsecurity_resolv_header_date(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_str_t date;

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (r->headers_out.date == NULL) {
        date.data = ngx_cached_http_time.data;
        date.len = ngx_cached_http_time.len;
    } else {
        ngx_table_elt_t *h = r->headers_out.date;
        date.data = h->value.data;
        date.len = h->value.len;
    }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &date);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) date.data,
        date.len);
}


static ngx_int_t
ngx_http_modsecurity_resolv_header_content_length(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_str_t value;
    char buf[NGX_INT64_LEN+2];

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (r->headers_out.content_length_n > 0)
    {
        ngx_sprintf((u_char *)buf, "%O%Z", r->headers_out.content_length_n);
        value.data = (unsigned char *)buf;
        value.len = strlen(buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif
        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) value.data,
            value.len);
    }

    return 1;
}


static ngx_int_t
ngx_http_modsecurity_resolv_header_content_type(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (r->headers_out.content_type.len > 0)
    {

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modsecurity_store_ctx_header(r, &name, &r->headers_out.content_type);
#endif

        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) r->headers_out.content_type.data,
            r->headers_out.content_type.len);
    }

    return 1;
}


static ngx_int_t
ngx_http_modsecurity_resolv_header_last_modified(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    u_char buf[1024], *p;
    ngx_str_t value;

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (r->headers_out.last_modified_time == -1) {
        return 1;
    }

    p = ngx_http_time(buf, r->headers_out.last_modified_time);

    value.data = buf;
    value.len = (int)(p-buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) value.data,
        value.len);
}


static ngx_int_t
ngx_http_modsecurity_resolv_header_connection(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_http_core_loc_conf_t *clcf = NULL;
    char *connection = NULL;
    ngx_str_t value;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        connection = "upgrade";
    } else if (r->keepalive) {
        connection = "keep-alive";
        if (clcf->keepalive_header)
        {
            u_char buf[1024];
            ngx_sprintf(buf, "timeout=%T%Z", clcf->keepalive_header);
            ngx_str_t name2 = ngx_string("Keep-Alive");

            value.data = buf;
            value.len = strlen((char *)buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
            ngx_http_modsecurity_store_ctx_header(r, &name2, &value);
#endif

            msc_add_n_response_header(ctx->modsec_transaction,
                (const unsigned char *) name2.data,
                name2.len,
                (const unsigned char *) value.data,
                value.len);
        }
    } else {
        connection = "close";
    }

    value.data = (u_char *) connection;
    value.len = strlen(connection);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) value.data,
        value.len);
}

static ngx_int_t
ngx_http_modsecurity_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;

    if (r->chunked) {
        ngx_str_t value = ngx_string("chunked");

        ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) value.data,
            value.len);
    }

    return 1;
}

static ngx_int_t
ngx_http_modsecurity_resolv_header_vary(ngx_http_request_t *r, ngx_str_t name, off_t offset)
{
#if (NGX_HTTP_GZIP)
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_http_core_loc_conf_t *clcf = NULL;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (r->gzip_vary && clcf->gzip_vary) {
        ngx_str_t value = ngx_string("Accept-Encoding");

        ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) value.data,
            value.len);
    }
#endif

    return 1;
}

ngx_int_t
ngx_http_modsecurity_header_filter_init(void)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_modsecurity_header_filter;

    return NGX_OK;
}

void NoOpDeallocator(void* data, size_t a, void* b) {};

ngx_int_t
ngx_http_modsecurity_header_filter(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
    int ret = 0;
    ngx_uint_t status;
    char *http_response_ver;
    ngx_pool_t *old_pool;


/* XXX: if NOT_MODIFIED, do we need to process it at all?  see xslt_header_filter() */

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    dd("header filter, recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("something really bad happened or ModSecurity is disabled. going to the next filter.");
        return ngx_http_next_header_filter(r);
    }
    // fprintf(stderr," First return2");

    if (ctx->intervention_triggered) {
        return ngx_http_next_header_filter(r);
    }

/* XXX: can it happen ?  already processed i mean */
/* XXX: check behaviour on 'ModSecurity off' */

    if (ctx && ctx->processed)
    {
        /*
         * FIXME: verify if this request is already processed.
         */
        dd("Already processed... going to the next header...");
        return ngx_http_next_header_filter(r);
    }

    /*
     * Lets ask nginx to keep the response body in memory
     *
     * FIXME: I don't see a reason to keep it `1' when SecResponseBody is disabled.
     */
    r->filter_need_in_memory = 1;

    ctx->processed = 1;
    /*
     *
     * Assuming ModSecurity module is running immediately before the
     * ngx_http_header_filter, we will be able to populate ModSecurity with
     * headers from the headers_out structure.
     *
     * As ngx_http_header_filter place a direct call to the
     * ngx_http_write_filter_module, we cannot hook between those two. In order
     * to enumerate all headers, we first look at the headers_out structure,
     * and later we look into the ngx_list_part_t. The ngx_list_part_t must be
     * checked. Other module(s) in the chain may added some content to it.
     *
     */
    for (i = 0; ngx_http_modsecurity_headers_out[i].name.len; i++)
    {
        dd(" Sending header to ModSecurity - header: `%.*s'.",
            (int) ngx_http_modsecurity_headers_out[i].name.len,
            ngx_http_modsecurity_headers_out[i].name.data);

                ngx_http_modsecurity_headers_out[i].resolver(r,
                    ngx_http_modsecurity_headers_out[i].name,
                    ngx_http_modsecurity_headers_out[i].offset);
    }

    for (i = 0 ;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modsecurity_store_ctx_header(r, &data[i].key, &data[i].value);
#endif

        /*
         * Doing this ugly cast here, explanation on the request_header
         */
        msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) data[i].key.data,
            data[i].key.len,
            (const unsigned char *) data[i].value.data,
            data[i].value.len);
    }

    /* prepare extra paramters for msc_process_response_headers() */
    if (r->err_status) {
        status = r->err_status;
    } else {
        status = r->headers_out.status;
    }

    /*
     * NGINX always sends HTTP response with HTTP/1.1, except cases when
     * HTTP V2 module is enabled, and request has been posted with HTTP/2.0.
     */
    http_response_ver = "HTTP 1.1";
#if (NGX_HTTP_V2)
    if (r->stream) {
        http_response_ver = "HTTP 2.0";
    }
#endif

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_response_headers(ctx->modsec_transaction, status, http_response_ver);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    
    ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
    //fprintf(stderr,"\nResult of ngx_http_modsecurity_process_intervention: %i", ret );
    if (r->error_page) {
        // fprintf(stderr,"\nIn if 1");
        return ngx_http_next_header_filter(r);
    }
    if (ret > 0) {
        // fprintf(stderr,"\nIn if 2");
        return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module, ret);
    }
    ///// Tokenizer ////
    char KEYWORDS_IN_TRAINING[100][20] = {"style", "sub", "textarea", "table", "ls", "order", "rollback", "alter", "top", "basefont", "tr", "section", "cp", "blockquote", "by", "summary", "group", "bdi", "delay", "desc", "commit", "track", "doctype", "time", "where", "span", "alert", "abbr", "drop", "bdo", "delete", "strong", "base", "tbody", "like", "thead", "from", "small", "tfoot", "br", "xp_cmdshell", "dir", "strike", "area", "limit", "acronym", "title", "sup", "all", "body", "pwd", "savepoint", "null", "set", "transaction", "article", "cat", "create", "mv", "tail", "aside", "select", "address", "truncate", "into", "update", "head", "button", "b", "a", "th", "deletescript", "replace", "waitfor", "audio", "td", "source", "applet", "big", "insert", "distinct", "more" };
    char *punctuations = "/+?&;=,()<>*!$#|^{}\\~@.`[]:'\"";
    // Read pattern from file //
    char line[322][100];
    char fname[100] = "/home/dyn/tokenizer/token.txt";
    FILE *fptr =  fopen(fname, "r");
    if(fptr==NULL)
    {
        // fprintf(stderr,"File does not exist");
        //return NULL;
    }
    int number_line = 0;
    // fprintf(stderr,"\n\n Read pattern from file %s into an array :\n", fname);
    while(fgets(line[number_line], 100, fptr))
	{
        line[number_line][strlen(line[number_line]) - 1] = '\0';
        number_line++;
    }
    //// Read extension from file ///
    char extname[100] = "/home/dyn/tokenizer/extension.txt";
    char ext[2445][100];
    FILE *ext_ptr = fopen(extname,"r");
    if(ext_ptr==NULL)
    {
        printf("File extension.txt does not exist");
    }
    int ext_line_number = 0;
    while(fgets(ext[ext_line_number], 100, ext_ptr))
	{
        ext[ext_line_number][strlen(ext[ext_line_number]) - 1] = '\0';
        ext_line_number++;
    }
    int len_path = r->uri.len;
    // fprintf(stderr,"\ncopy_to_string_1");
    char* path = copy_to_string(r->uri.data, len_path);
    char* parse_path = handle_path(path,len_path,punctuations);
    int len_path_arr = 0;
    int* token_path = tokenizer_path(parse_path, line, number_line, punctuations, ext, ext_line_number, &len_path_arr);

    int len_param = r->args.len;
    // fprintf(stderr,"\nLen of param: %i", len_param);
    int len_param_arr = 0;
    int* token_param;
    // fprintf(stderr,"\ncopy_to_string_2");
    if(len_param > 0)
    {
        char* param = copy_to_string(r->args.data, len_param);
        // fprintf(stderr,"\nTest");
        char* parse_param = handle_data(param,len_param,punctuations);
        // fprintf(stderr,"\nTest2\n");
        int len_param_arr = 0;
        token_param = tokenizer_data(parse_param, line, number_line, &len_param_arr, punctuations, KEYWORDS_IN_TRAINING);
        free(param);
        free(parse_param); 
    }
    else{
        token_param = NULL;
    }
    // fprintf(stderr,"\ncopy_to_string_3");
    int len_tokenizer = len_path_arr + len_param_arr;
    float final_tokenizer[340];
    for(int i =0; i<340 ; i++)
    {
        if(i < len_path_arr)
            final_tokenizer[i] = (float)token_path[i];
        else if( i>=len_path_arr && i < len_tokenizer)
            final_tokenizer[i] = (float)token_param[i-len_path_arr];
        else 
            final_tokenizer[i] = 0.0;
    }
    //fprintf(stderr,"Len of tokenizer: %f %f %f %f %f abctest", final_tokenizer[0], final_tokenizer[1], final_tokenizer[2], final_tokenizer[3], final_tokenizer[4]);


    /////////

    /*
     * Proxies will not like this... but it is necessary to unset
     * the content length in order to manipulate the content of
     * response body in ModSecurity.
     *
     * This header may arrive at the client before ModSecurity had
     * a change to make any modification. That is why it is necessary
     * to set this to -1 here.
     *
     * We need to have some kind of flag the decide if ModSecurity
     * will make a modification or not. If not, keep the content and
     * make the proxy servers happy.
     *
     */

    /*
     * The line below is commented to make the spdy test to work
     */
     //r->headers_out.content_length_n = -1;

    //Load TF//
    // fprintf(stderr,"\nIn line 639");
    TF_Graph* Graph = TF_NewGraph();
    // fprintf(stderr,"\nIn line 641");
    TF_Status* Status = TF_NewStatus();
    // fprintf(stderr,"\nIn line 643");
    TF_SessionOptions* SessionOpts = TF_NewSessionOptions();
    // fprintf(stderr,"\nIn line 645");
    TF_Buffer* RunOpts = NULL;
    
    const char* saved_model_dir = "/home/dyn/Downloads/save_model/model_final_95/";
    const char* tags = "serve";
    int ntags = 1;
    // fprintf(stderr,"\nIn line 651");
    TF_Session* Session = TF_LoadSessionFromSavedModel(SessionOpts, RunOpts, saved_model_dir, &tags, ntags, Graph, NULL, Status);
    int NumInputs = 1;
    // fprintf(stderr,"\nIn line 650");
    TF_Output* Input = (TF_Output*)malloc(sizeof(TF_Output) * NumInputs);
    //int a = [1,2,3]
    // fprintf(stderr,"\nIn line 653");
    TF_Output t0 = {TF_GraphOperationByName(Graph, "serving_default_input_1"), 0};
    if(t0.oper == NULL)
        printf("ERROR: Failed TF_GraphOperationByName serving_default_input_1\n");
    else
	printf("TF_GraphOperationByName serving_default_input_1 is OK\n");
    
    Input[0] = t0;
    int NumOutputs = 1;
    // fprintf(stderr,"\nIn line 662");
    TF_Output* Output = (TF_Output*)malloc(sizeof(TF_Output) * NumOutputs);

    TF_Output t2 = {TF_GraphOperationByName(Graph, "StatefulPartitionedCall"), 0};
    if(t2.oper == NULL)
        printf("ERROR: Failed TF_GraphOperationByName StatefulPartitionedCall\n");
    else	
	printf("TF_GraphOperationByName StatefulPartitionedCall is OK\n");
    
    Output[0] = t2;

    // Allocate data for inputs & outputs
    TF_Tensor** InputValues = (TF_Tensor**)malloc(sizeof(TF_Tensor*)*NumInputs);
    TF_Tensor** OutputValues = (TF_Tensor**)malloc(sizeof(TF_Tensor*)*NumOutputs);

    int ndims = 2;
    int64_t dims[] = {1,340};
    //float data1[340] = {4 , 2, 6, 20, 9, 1, 3, 5, 1, 5, 1, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} ;
    int ndata = sizeof(float)*1*340 ;// This is tricky, it number of bytes not number of element

    TF_Tensor* int_tensor = TF_NewTensor(TF_FLOAT, dims, ndims, final_tokenizer, ndata, &NoOpDeallocator, 0);
    if (int_tensor != NULL)
    {
        printf("TF_NewTensor is OK\n");
    }
    else
	printf("ERROR: Failed TF_NewTensor\n");
    
    InputValues[0] = int_tensor;
    
    // //Run the Session
    TF_SessionRun(Session, NULL, Input, InputValues, NumInputs, Output, OutputValues, NumOutputs, NULL, 0,NULL , Status);

    if(TF_GetCode(Status) == TF_OK)
    {
        printf("Session is OK\n");
    }
    else
    {
        printf("%s",TF_Message(Status));
    }

    //Free memory
    TF_DeleteGraph(Graph);
    TF_DeleteSession(Session, Status);
    TF_DeleteSessionOptions(SessionOpts);
    TF_DeleteStatus(Status);

    

    void* buff = TF_TensorData(OutputValues[0]);
    float* offsets = (float*)buff;
    //fprintf(stderr,"Just for testing");

    if(offsets[0] > offsets[1]){
        //ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"block by module A");
        // fprintf(stderr,"Block by ML model!");
        // fprintf(stderr,"Percent of 0: %f and percent of 1: %f",offsets[0], offsets[1]);
        r->keepalive = 0 ;
        return NGX_HTTP_FORBIDDEN;
        }
    // fprintf(stderr," Final return2");
    return ngx_http_next_header_filter(r);
}
