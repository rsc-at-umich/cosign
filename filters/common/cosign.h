/*
 * filters/common/cosign.h
 *
 * Copyright (c) 2002-2016 by the Regents of the University of Michigan
 * All Rights Reserved.
 *
 * See LICENSE
 */


#ifndef _COSIGN_FILTERS_COMMON_COSIGN_H_
#  define _COSIGN_FILTERS_COMMON_COSIGN_H 1

/* apache 1.3 & apache 2.0 lack ap_regex types and functions */
#  ifndef HAVE_AP_REGEX_H 
#    define ap_regex_t		regex_t
#    define ap_regmatch_t	regmatch_t

#    define AP_REG_EXTENDED	REG_EXTENDED
#    define AP_REG_NOMATCH	REG_NOMATCH
#  endif /* !HAVE_AP_REGEX_H */


typedef struct {
    char                *host;
    char                *service;
    char		*siteentry;
    char		**reqfv;
    int			reqfc;
    char		*suffix;
    int			fake;
    int			public;
    char                *redirect;
    char                *posterror;
    char		*validref;
    int			validredir;
    char		*referr;
#  ifndef LIGHTTPD
    ap_regex_t		*validpreg;
#  endif /* LIGHTTPD */
    unsigned short      port;
    int                 protect;
    int                 configured;
    int			checkip;
    struct connlist     **cl;
    SSL_CTX		*ctx;
    char		*cert;
    char		*key;
    char		*cadir;
    char		*filterdb;
    int			hashlen;
    char		*proxydb;
    char		*tkt_prefix;
    int                 http;
    int                 noappendport;
    int			proxy;
    int			expiretime;
    int			httponly_cookies;
    int			extendedhttpstatus;  /* Use extended 5xx status codes (below) */ 
    int			warnvalidatedelay;   /* Log warning if cookie validation takes too long */

  /*
   * These codes aren't terribly useful for error documents. Apache httpd
   * limits the maximum status codes that can be handled by "ErrorDocument". 
   */
#  define HTTP_COSIGN_INTERNAL_ERROR	535
#  define HTTP_COSIGN_NOT_CONFIG	(HTTP_COSIGN_INTERNAL_ERROR+1)	/* mod_cosign not configured */
#  define HTTP_COSIGN_BAD_CONFIG	(HTTP_COSIGN_INTERNAL_ERROR+2)	/* mod_cosign badly configured */
#  define HTTP_COSIGN_CLIENT		(HTTP_COSIGN_INTERNAL_ERROR+3)	/* Client did something DUMB */
#  define HTTP_COSIGN_VALIDATION_FAIL	(HTTP_COSIGN_INTERNAL_ERROR+4) /* Validation failed */
#  define HTTP_COSIGN_SERVER_FAIL	(HTTP_COSIGN_INTERNAL_ERROR+5)	/* Generic server failure */
#  define HTTP_COSIGN_SERVER_REFUSED	(HTTP_COSIGN_INTERNAL_ERROR+6) /* Server refused connection */
#  define HTTP_COSIGN_SERVER_CERT	(HTTP_COSIGN_INTERNAL_ERROR+7)	/* X509 Certificate failure */
#  define HTTP_COSIGN_LAST_STATUS	HTTP_COSIGN_SERVER_CERT

#  ifdef KRB
#    ifdef GSS
    int			gss;
#    endif /* GSS */
    int			krbtkt;
#  endif /* KRB */
} cosign_host_config;


/*
 * Keep track of weblogin/cosign backend servers.
 */
struct connlist {
    struct sockaddr_in  conn_sin;
    SNET                *conn_sn;
    unsigned int	conn_capa;
    unsigned int	conn_proto;
    struct connlist     *conn_next;
};

#  define COSIGN_ERROR		-1
#  define COSIGN_OK		0
#  define COSIGN_RETRY		1
#  define COSIGN_LOGGED_OUT	2

#  define IPCHECK_NEVER		0
#  define IPCHECK_INITIAL	1
#  define IPCHECK_ALWAYS	2

extern int cosign_cookie_valid( cosign_host_config *, char *, char **, struct sinfo *,
	char *, void * );
extern int cosign_check_cookie( char *, char **, struct sinfo *, cosign_host_config *,
	int, void * );
extern int teardown_conn( struct connlist **, void * );

#define COSIGN_CONN_NTOP_SIZE  100 /* "[ipv6]:port" max and wiggle room */

extern const char * cosign_conn_ntop( char *, size_t len, const struct connlist * );

extern const char * cosign_conn_toa( const struct connlist * ); /* Not thread safe. */

#endif /* _COSIGN_FILTERS_COMMON_COSIGN_H_ */
