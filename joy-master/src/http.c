/*
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file http.c
 *
 * \brief http data extraction implementation
 */
#include <ctype.h>
#include "http.h"
#include "p2f.h"      
#include "str_match.h" 
#include "anon.h"
#include <string.h> 
#include <stdlib.h>   
#include "p2f.h"

/*
 * change this flag is you want hexadecimal output
 */
#define NO_HEX_OUTPUT 1

/** user name match structure */
extern str_match_ctx  usernames_ctx;

/** max http length */
#define HTTP_LEN 2048

/** MAGIC determines the number of bytes of the HTTP message body that
 * will be grabbed off of the wire; the idea here is that the initial
 * bytes of that field may contain the file "magic number" that can
 * identify its type
 */
#define MAGIC 16

/*
 * declarations of functions that are internal to this file
 */
static unsigned int memcpy_up_to_crlfcrlf_plus_magic(char *dst, const char *src, unsigned int length);

#if NO_HEX_OUTPUT
static void http_header_print_as_object(zfile f, char *header, char *string, unsigned length);
#else
static void http_header_print_as_hex(zfile f, char *header, char *string, unsigned int len);
#endif

/*
 * high level HTTP handling functions
 */

/**
 * \fn void http_init (http_data_t *data)
 * \param data http data structure pointer
 * \return none
 */
void http_init (http_data_t *data) {
    data->header = NULL;
    data->header_length = 0;
}

/**
 * \fn void http_update (http_data_t *data,
      const void *http_start, 
      unsigned long bytes_in_msg,
      unsigned int report_http)
 * \param data pointer to http data structure
 * \param http_start http start pointer
 * \param bytes_in_msg number of bytes
 * \param report_http determine whether or not to examine http packets
 * \return none
 */
void http_update(http_data_t*data,
			const void *http_start, 
			unsigned long bytes_in_msg,
			unsigned int report_http) {
  
    if (report_http && (data->header == NULL)) {
        unsigned int len = (bytes_in_msg + MAGIC) < HTTP_LEN ? (bytes_in_msg + MAGIC) : HTTP_LEN;
        /*
         * note: we leave room for null termination in the data buffer
         */
       
        data->header = malloc(len);
        if (data->header == NULL) {
            return; 
        }
        memset(data->header, 0x0, len);
        data->header_length = memcpy_up_to_crlfcrlf_plus_magic(data->header, http_start, len);
    }
} 

/**
 * \fn void http_printf (const http_data_t *data, char *string, zfile f) 
 * \param data pointer to http data structure
 * \param string label to use for output
 * \param f file to send output to
 * \return none
 */
void http_printf (const http_data_t *data, char *string, zfile f) {

#if NO_HEX_OUTPUT
    if (data->header && data->header_length && (data->header_length < HTTP_LEN)) {
          // fprintf(stdout, "data length: %u\n", data->header_length);
          fflush(stdout);
          http_header_print_as_object(f, data->header, string, data->header_length);
    }

#else 

    if (data->header && data->header_length && (data->header_length < HTTP_LEN)) {
          http_header_print_as_hex(f, data->header, string, data->header_length);
          // fprintf(f, ",\n\t\t\t\"%s\": \"%s\"", string, data->header);
    }

#endif

}

/**
 * \fn void http_delete (http_data_t *data)
 * \param data pointer to the http data structure
 * \return none
 */
void http_delete (http_data_t *data) {
    free(data->header);
}

/*
 * internal functions
 */

/*
 * From RFC 2616, Section 4.1:
 *
 *      generic-message = start-line
 *                         *(message-header CRLF)
 *                         CRLF
 *                         [ message-body ]
 *
 *      start-line      = Request-Line | Status-Line
 * 
 *      Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
 *
 *      Method         = "OPTIONS"                ; Section 9.2
 *                     | "GET"                    ; Section 9.3
 *                     | "HEAD"                   ; Section 9.4
 *                     | "POST"                   ; Section 9.5
 *                     | "PUT"                    ; Section 9.6
 *                     | "DELETE"                 ; Section 9.7
 *                     | "TRACE"                  ; Section 9.8
 *                     | "CONNECT"                ; Section 9.9
 *                     | extension-method
 *      extension-method = token
 *
 *      Request-URI    = "*" | absoluteURI | abs_path | authority
 *
 *      Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
 *
 *     Status-Code    =
 *           "100"  ; Section 10.1.1: Continue
 *         | "101"  ; Section 10.1.2: Switching Protocols
 *         | "200"  ; Section 10.2.1: OK
 *         | "201"  ; Section 10.2.2: Created
 *         | "202"  ; Section 10.2.3: Accepted
 *         | "203"  ; Section 10.2.4: Non-Authoritative Information
 *         | "204"  ; Section 10.2.5: No Content
 *         | "205"  ; Section 10.2.6: Reset Content
 *         | "206"  ; Section 10.2.7: Partial Content
 *         | "300"  ; Section 10.3.1: Multiple Choices
 *         | "301"  ; Section 10.3.2: Moved Permanently
 *         | "302"  ; Section 10.3.3: Found
 *         | "303"  ; Section 10.3.4: See Other
 *         | "304"  ; Section 10.3.5: Not Modified
 *         | "305"  ; Section 10.3.6: Use Proxy
 *         | "307"  ; Section 10.3.8: Temporary Redirect
 *         | "400"  ; Section 10.4.1: Bad Request
 *         | "401"  ; Section 10.4.2: Unauthorized
 *         | "402"  ; Section 10.4.3: Payment Required
 *         | "403"  ; Section 10.4.4: Forbidden
 *         | "404"  ; Section 10.4.5: Not Found
 *         | "405"  ; Section 10.4.6: Method Not Allowed
 *         | "406"  ; Section 10.4.7: Not Acceptable
 *         | "407"  ; Section 10.4.8: Proxy Authentication Required
 *         | "408"  ; Section 10.4.9: Request Time-out
 *         | "409"  ; Section 10.4.10: Conflict
 *         | "410"  ; Section 10.4.11: Gone
 *         | "411"  ; Section 10.4.12: Length Required
 *         | "412"  ; Section 10.4.13: Precondition Failed
 *         | "413"  ; Section 10.4.14: Request Entity Too Large
 *         | "414"  ; Section 10.4.15: Request-URI Too Large
 *         | "415"  ; Section 10.4.16: Unsupported Media Type
 *         | "416"  ; Section 10.4.17: Requested range not satisfiable
 *         | "417"  ; Section 10.4.18: Expectation Failed
 *         | "500"  ; Section 10.5.1: Internal Server Error
 *         | "501"  ; Section 10.5.2: Not Implemented
 *         | "502"  ; Section 10.5.3: Bad Gateway
 *         | "503"  ; Section 10.5.4: Service Unavailable
 *         | "504"  ; Section 10.5.5: Gateway Time-out
 *         | "505"  ; Section 10.5.6: HTTP Version not supported
 *         | extension-code
 *
 *     extension-code = 3DIGIT
 *     Reason-Phrase  = *<TEXT, excluding CR, LF>
 *
 */

enum parse_state {
    non_crlf  = 0,
    first_cr  = 1,
    first_lf  = 2,
    second_cr = 3,
    second_lf = 4
};

static unsigned int memcpy_up_to_crlfcrlf_plus_magic (char *dst, const char *src, unsigned int length) {
    unsigned int i;
    enum parse_state state = non_crlf;
    unsigned int body_bytes = 0; 

    for (i=0; i<length; ++i) {
        /* reached the end of the src without finding crlfcrlf */
        if (i == (length - MAGIC)) {
           ++i;
           break;
        }

        /* copy the byte to destination */
        *(dst+i) = *(src+i);

        /*  found a CRLFCRLF; copy magic bytes of body then return */
        if (state == second_lf) {
            if (body_bytes < MAGIC) {
                // printf("body_bytes: %u\tMAGIC: %u\ti: %u\tlength: %u\n", body_bytes, MAGIC, i, length);
                ++body_bytes;
            } else {
                ++i;
                break;
            }
        }

        /* still parsing HTTP headers */
        else {
            /*
             * make string printable, by suppressing characters below SPACE
             * (32) and above DEL (127), inclusive, except for \r and \n
             */
            if ((*(dst+i) < 32 || *(dst+i) > 126) && *(dst+i) != '\r' && *(dst+i) != '\n') {
                *(dst+i) = '.';
            }
            /* avoid JSON confusion */
            if ((*(dst+i) == '"') || (*(dst+i) == '\\')) {
                *(dst+i) = '.';
            }

            /* advance lexer state  */
            if (*(src+i) == '\r') {
                if (state == non_crlf) {
                    state = first_cr;
                } else if (state == first_lf) {
                    state = second_cr;
                } 
            } else if (*(src+i) == '\n') {
                if (state == first_cr) {
                    state = first_lf;
                } else if (state == second_cr) {
                    state = second_lf;
                }
            } else {
                if (state != second_lf) {
                    state = non_crlf;
                }
            }
        }

    }
  
    return i;
}




/*
 * lexer for http headers
 */

enum http_type {
    http_done         = 0,
    http_method       = 1,
    http_header       = 2,
    http_request_line = 3,
    http_status_line  = 4,
    http_malformed    = 5
};

enum header_state {
    got_nothing = 0,
    got_header  = 1,
    got_value   = 2
};

#if NO_HEX_OUTPUT

static enum http_type http_get_next_line (char **saveptr,
				  unsigned int *length, char **token1, char **token2) {
    unsigned int i;
    enum parse_state state = non_crlf;
    enum header_state header_state = got_nothing;
    char *src = *saveptr;

    if (src == NULL) {
        return http_done;
    }

    *token1 = src;
    *token2 = NULL;
    for (i=0; i < *length; i++) {
      
        /* advance lexer state  */
        if (src[i] == '\r') {
            if (state == non_crlf) {
	              state = first_cr;
            } else if (state == first_lf) {
	              state = second_cr;
            } 
            src[i] = '.';  /* make printable, as a precaution */    

        } else if (src[i] == '\n') {
            if (state == first_cr) {
	              state = first_lf;
            } else if (state == second_cr) {
	              state = second_lf;
            }
            src[i] = '.';  /* make printable, as a precaution */    

        } else if (src[i] == ':') {
            if (header_state == got_nothing) {
	              src[i] = 0;      /* NULL terminate token */
	              header_state = got_header;
            }
            state = non_crlf;
        } else if (src[i] == ' ') {
            ;     /* ignore whitespace */
        } else {

            if (state == first_lf) {
	              src[i-2] = 0;    /* NULL terminate token */
	              *length = *length - i;
	              *saveptr = &src[i];
	              return http_header;
            }

            if (header_state == got_header) {
	              *token2 = &src[i];	
	              header_state = got_value;
            }
            state = non_crlf;
        }

        if (state == second_lf) {
            src[i-3] = 0;   /* NULL terminate token */
            *length = *length - i;
            *saveptr = &src[i];
            return http_done;
        }
    }
  
    *saveptr = NULL;
    return http_malformed;
}

enum start_line_state {
    got_none = 0,
    got_first = 1,
    started_second = 2,
    got_second = 3,
    started_third = 4,
    got_third = 5
};

static enum http_type http_get_start_line (char **saveptr,
				   unsigned int *length, char **token1, 
				   char **token2, char **token3) {
    unsigned int i;
    enum parse_state state = non_crlf;
    enum start_line_state start_state = got_none;
    char last_char = 0;
    enum http_type line_type = http_request_line;
    char *src = *saveptr;

    if (src == NULL) {
        return http_done;
    }

    *token1 = src;
    *token2 = *token3 = NULL;
    for (i=0; i < *length; i++) {
      
        /* advance lexer state  */
        if (src[i] == '\r') {
            if (state == non_crlf) {
	              state = first_cr;
            } else if (state == first_lf) {
	              state = second_cr;
            } 
            src[i] = '.';  /* make printable, as a precaution */    

        } else if (src[i] == '\n') {
            if (state == first_cr) {
	              state = first_lf;
            } else if (state == second_cr) {
	              state = second_lf;
            } 
            src[i] = '.';  /* make printable, as a precaution */    
      
        } else if (src[i] == ' ') {
            if (start_state == got_none) {
	              start_state = got_first;
            } else if (start_state == started_second) {
	              start_state = got_second;
            } 
            state = non_crlf;
        } else {

            if (state == first_lf) {
	              src[i-2] = 0;      /* NULL terminate token */
	              *length = *length - i;
	              *saveptr = &src[i];
	              if (start_state == started_third) {
	                  return line_type;  
	              } else {
	                  return http_malformed;
	              }
            }

            if (start_state == got_none) {
	              /*
	               * check for string "HTTP", which indicates a status line (not a response line)
	               */
	              if (last_char == 0 && src[i] == 'H') {
	                  last_char = 'H';
	              } else if ((last_char == 'H' || last_char == 'T') && src[i] == 'T') {
	                  last_char = 'T';
	              } else if (last_char == 'T' && src[i] == 'P') {
	                  line_type = http_status_line;
	              }
            } else if (start_state == got_first) {
	              src[i-1] = 0;      /* NULL terminate token */
	              *token2 = &src[i];	
	              start_state = started_second;
            } else if (start_state == got_second) {
	              src[i-1] = 0;      /* NULL terminate token */
	              *token3 = &src[i];
	              start_state = started_third;
            }
            state = non_crlf;
        }

        if (state == second_lf) {
            src[i-3] = 0;        /* NULL terminate token */
            *length = *length - i;
            *saveptr = &src[i];
            return http_done;
        }
    }
  
    *saveptr = NULL;
    return http_malformed;
}

static int http_header_select (char *h) {
  return 1;
}

#define PRINT_USERNAMES 1

static void http_header_print_as_object (zfile f, char *header, char *string, unsigned length) {
    char *token1, *token2, *token3, *saveptr;  
    unsigned int not_first_header = 0;
    enum http_type type = http_done;  
    struct matches matches;

    token1 = token2 = NULL; /* initialize just to avoid compiler warnings */

    zprintf(f, ",\"%s\":{", string);

    if (length < 4) {
        goto bail;
    }

    /*
     * parse start-line, and print as request/status as appropriate
     */
    saveptr = header;
    type = http_get_start_line(&saveptr, &length, &token1, &token2, &token3);
    if (type == http_request_line) {    
    
        zprintf(f, "\"method\":\"%s\",", token1);
        zprintf(f, "\"uri\":\"");
        if (usernames_ctx) {
            str_match_ctx_find_all_longest(usernames_ctx, (unsigned char*)token2, strlen(token2), &matches);      
            anon_print_uri_pseudonym(f, &matches, token2);
        } else {
            zprintf(f, "%s", token2);
        }
        zprintf(f, "\",");
        zprintf(f, "\"v\":\"%s\"", token3);

#if PRINT_USERNAMES
        /*
         * print out (anonymized) usernames found in URI
         */
        if (usernames_ctx) {
            zprintf(f, ",");
            zprintf_usernames(f, &matches, token2, is_special, anon_string);
        }
#endif

        not_first_header = 1;
    } else if (type == http_status_line) {    
        zprintf(f, "\"v\":\"%s\","
	          "\"code\":\"%s\"," "\"reason\":\"%s\"", 
	          token1, token2, token3);
        not_first_header = 1;
    }

    if (type != http_malformed && type != http_done) {

        /*
         * parse and print headers
         */ 
        do { 
            type = http_get_next_line(&saveptr, &length, &token1, &token2);
            if (type != http_malformed && http_header_select(token1)) {
	              if (not_first_header) {
	                  zprintf(f, ",");
	              } else {
	                  not_first_header = 1;
	              }
	              zprintf(f, "\"%s\":\"%s\"", token1, token2);
            }

        } while (type == http_header);
    }

    /*
     * part or all of the header is malformed, so print out that fact
     */
    if (type == http_malformed) {
        if (not_first_header) {
           zprintf(f, ",");
        } else {
           not_first_header = 1;
        }
        zprintf(f, "\"malformed\":%u", length);
    }

    /*
     * print out the initial bytes of the HTTP body
     */
    if (type == http_done && (MAGIC != 0) && (length != 0)) {
        if (not_first_header) {
            zprintf(f, ",");
        } 
        zprintf(f, "\"body\":");
        zprintf_raw_as_hex(f, saveptr, length); 
    }

    bail:  zprintf(f, "}");
}

#else

static void http_header_print_as_hex (zfile f, char *header, char *string, unsigned int len) {
    zprintf(f, ",\"%s\":", string);
    zprintf_raw_as_hex(f, header, len); 
}

#endif
