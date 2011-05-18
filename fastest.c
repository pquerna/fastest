/**
 * Copyright 2011 Paul Querna
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
 */

/**

Mission: write the following Node.js application[1], in C:

var http = require('http'), url = require('url');
http.createServer(function(request, response) {
	response.writeHead(200, {"Content-Type":"text/xml"});
	var urlObj = url.parse(request.url, true);
	var value = urlObj.query["value"];
	if (value === undefined){
		response.end("<http_test><error>no value specified</error></http_test>");
	} else {
		response.end("<http_test><value>" + value + "</value></http_test>");
	}
}).listen(8080);

[1] - From <http://www.ostinelli.net/a-comparison-between-misultin-mochiweb-cowboy-nodejs-and-tornadoweb/>

Status:
 - libuv basics working.
 - http-parser... works (hack).
 - it responds with the correct values
  - doesn't really do keep-alive/pipe lined requests.

*/

#include "libuv/uv.h"
#include "http-parser/http_parser.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define MAX_VALUE_LENGTH 100
static const char error_resp[] = \
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/xml\r\n"
  "Connection: keep-alive\r\n"
  "Transfer-Encoding: chunked\r\n"
  "\r\n"
  "39\r\n"
  "<http_test><error>no value specified</error></http_test>\n\r\n"
  "0\r\n\r\n";

#define SLEN(x) (sizeof (x) / sizeof (*(x)))

static const char value_respfmt[] = \
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/xml\r\n"
  "Connection: keep-alive\r\n"
  "Transfer-Encoding: chunked\r\n"
  "\r\n"
  "%x\r\n"
  "<http_test><value>%s</value></http_test>\n\r\n"
  "0\r\n\r\n";

#define MAX_RESP_LENGTH (SLEN(value_respfmt) + MAX_VALUE_LENGTH + 4 + 1)

#define TIME_REQUESTS

typedef struct http_baton_t {
  uv_req_t req;
  uv_buf_t buf;
  http_parser parser;
  int ready;
  int closed;
  size_t vlen;
  char valuebuf[MAX_VALUE_LENGTH + 1];
  char respbuf[MAX_RESP_LENGTH];
#ifdef TIME_REQUESTS
  struct timeval start;
#endif
} http_baton_t;


static int on_message_begin(http_parser* hp) {
  return 0;
}

static int on_path(http_parser* hp, const char *at, size_t length) {
  return 0;
}

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

static int on_query_string(http_parser* hp, const char *at, size_t length) {
  http_baton_t *r = (http_baton_t*)hp->data;
  ssize_t clen = MIN(MAX_VALUE_LENGTH - r->vlen, length);
  memcpy(r->valuebuf + r->vlen, at, clen);
  r->vlen += clen;
  return 0;
}

static int on_url(http_parser* hp, const char *at, size_t length) {
  return 0;
}

static int on_fragment(http_parser* hp, const char *at, size_t length) {
  return 0;
}

static int on_header_field(http_parser* hp, const char *at, size_t length) {
  return 0;
}

static int on_header_value(http_parser* hp, const char *at, size_t length) {
  return 0;
}

static int on_headers_complete(http_parser* hp) {
  return 0;
}

static int on_body(http_parser* hp, const char *at, size_t length) {
  return 0;
}

static int on_message_complete(http_parser* hp) {
  char *p;
  http_baton_t *r = (http_baton_t*)hp->data;
  r->ready = 1;
  r->valuebuf[r->vlen] = '\0';

  /* Hack, should do this 'right' */
  p = strstr(r->valuebuf, "value=");
  if (p) {
    p += 6;
    char *ep = strchr(p, '&');
    if (ep) {
      *ep = '\0';
    }
    memmove(r->valuebuf, p, strlen(p)+1);
  }
  else {
    r->vlen = 0;
  }
  return 0;
}

static http_parser_settings http_cbs = {
  on_message_begin,
  on_path,
  on_query_string,
  on_url,
  on_fragment,
  on_header_field,
  on_header_value,
  on_headers_complete,
  on_body,
  on_message_complete
};

static uv_handle_t server;


static void after_write(uv_req_t* req, int status);
static void after_read(uv_handle_t* handle, int nread, uv_buf_t buf);
static void on_close(uv_handle_t* peer, int status);
static void on_accept(uv_handle_t* handle);

static void after_write(uv_req_t* req, int status) {
  http_baton_t *r = req->handle->data;

  if (status) {
    uv_err_t err = uv_last_error();
    fprintf(stderr, "uv_write error: %s\n", uv_strerror(err));
  }

  if (!r->closed) {
    uv_close(req->handle);
    r->closed = 1;
  }
}

static void prepare_response(http_baton_t *r, const char *value)
{
  int len;

  if (value == NULL) {
    r->buf.base = (char*)error_resp;
    r->buf.len = SLEN(error_resp) + 1;
  }
  else {
    len = strlen(value);
    if (len > MAX_VALUE_LENGTH) {
      fprintf(stderr, "No. Too Long: %s\n", value);
      abort();
    }

    len += 39; // xml + trailing new line

    len = snprintf(&r->respbuf[0], MAX_RESP_LENGTH, value_respfmt, len, value);

    r->buf.base = &r->respbuf[0];
    r->buf.len = len;
  }



}
static void after_read(uv_handle_t* handle, int nread, uv_buf_t buf) {
  http_baton_t *r;
  size_t rv;
  r = (http_baton_t*) handle->data;

  if (nread < 0) {
    /* Error or EOF */
    //uv_last_error().code == UV_EOF

    if (buf.base) {
      free(buf.base);
    }

    if (!r->closed) {
      uv_close(handle);
      r->closed = 1;
    }

    return;
  }

  if (nread == 0) {
    /* Everything OK, but nothing read. */
    if (buf.base) {
      free(buf.base);
    }
    return;
  }

  rv = http_parser_execute(&r->parser, &http_cbs, buf.base, nread);
  /* TODO: better handling of rv */
  if (rv) {
    if (r->ready) {
      uv_req_init(&r->req, handle, after_write);
      prepare_response(r, r->vlen != 0 ? r->valuebuf : NULL);
      if (uv_write(&r->req, &r->buf, 1)) {
        /* TODO: error */
        abort();
      }
    }
  }

  if (buf.base) {
    free(buf.base);
  }
}


#define ELAPSED_IN_MS(t0, t1) (((t1.tv_sec - t0.tv_sec) * 1000) + ((t1.tv_usec / 1000) - (t0.tv_usec / 1000)))

static void on_close(uv_handle_t* handle, int status) {
  if (status != 0) {
    fprintf(stdout, "Socket error\n");
  }

  if (handle->data) {
#ifdef TIME_REQUESTS
  {
    http_baton_t *r = handle->data;
    uint64_t elapsed_ms;
    struct timeval end;
    gettimeofday(&end, NULL);
    elapsed_ms = ELAPSED_IN_MS(r->start, end);
    if (elapsed_ms > 100) {
      fprintf(stderr, "WARNING: Elapsed was %llums\n", elapsed_ms);
    }
  }
  //uv_close(&server);
#endif

    free(handle->data);
    handle->data = NULL;
  }

  free(handle);
}


static void on_accept(uv_handle_t* server) {
  http_baton_t *r;
  uv_handle_t* handle = (uv_handle_t*) malloc(sizeof *handle);
  handle->data = NULL;

  if (uv_accept(server, handle, on_close, handle)) {
    /* TODO: error */
    abort();
    free(handle);
  }
  else {
    r = (http_baton_t*) malloc(sizeof *r);

    http_parser_init(&r->parser, HTTP_REQUEST);
    r->parser.data = r;
    r->ready = 0;
    r->closed = 0;
    r->vlen = 0;
#ifdef TIME_REQUESTS
    gettimeofday(&r->start, NULL);
#endif

    handle->data = r;

    uv_read_start(handle, after_read);
  }
}


static void on_server_close(uv_handle_t* handle, int status) {
  /* TODO: error */
    exit(0);
}

static uv_buf_t alloc_cb(uv_handle_t* handle, size_t size) {
  uv_buf_t buf;
  buf.base = (char*)malloc(size);
  buf.len = size;
  return buf;
}

int main() {
  int rv;
  int port = 8080;
  struct sockaddr_in addr = uv_ip4_addr("0.0.0.0", port);

  fprintf(stdout, "Binding to 0.0.0.0:8080....\n");

  rv = uv_tcp_init(&server, on_server_close, NULL);
  if (rv) {
    /* TODO: Error codes */
    fprintf(stderr, "Socket creation error\n");
    return 1;
  }

  rv = uv_bind(&server, (struct sockaddr*) &addr);
  if (rv) {
    /* TODO: Error codes */
    fprintf(stderr, "Bind error\n");
    return 1;
  }

  rv = uv_listen(&server, 128, on_accept);
  if (rv) {
    /* TODO: Error codes */
    fprintf(stderr, "Listen error\n");
    return 1;
  }

  uv_init(alloc_cb);

  uv_run();
  return 0;
}
