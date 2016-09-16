/*
 * filters/common/connect.c
 *
 * Copyright (c) 2009,2016 Regents of The University of Michigan.
 * All Rights Reserved.
 *
 * See LICENSE
 */

#include "config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>


#define OPENSSL_DISABLE_OLD_DES_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <snet.h>

#ifdef LIGHTTPD
#include "base.h"
#include "logging.h"
#else /* !LIGHTTPD, Apache headers */
#include <httpd.h>
#include <http_log.h>
#endif /* LIGHTTPD */

#include "argcargv.h"
#include "sparse.h"
#include "cosign.h"
#include "mkcookie.h"
#include "cosignproto.h"
#include "rate.h"
#include "log.h"

#ifndef MIN
#define MIN(a,b)        ((a)<(b)?(a):(b))
#endif 

static int connect_sn( struct connlist *, cosign_host_config *, void * );
static void close_sn( struct connlist *, void * );
static void (*logger)( char * ) = NULL;

static struct timeval		timeout = { 10 * 60, 0 };

static struct rate   		checkpass = { 0 };
static struct rate   		checkfail = { 0 };
static struct rate   		checkunknown = { 0 };
static double             	rate;

struct capability		caps[] = {
    /* name, name length, mask, callback */
    { "FACTORS", 7, COSIGN_CAPA_FACTORS, NULL },
    { "REKEY",  5, COSIGN_CAPA_REKEY, NULL },
};


const char * 
cosign_conn_ntop( char *buff, size_t bufflen, const struct connlist *cl )
{
    char paddr[ COSIGN_CONN_NTOP_SIZE ]; /* Temp buffer for address */
    const char *p = (char *) NULL;
    char addr_family[32] = "unknown";	/* IPv4, IPv6, etc. */
    unsigned short port = 0;		/* Default: We don't know */


    if ( cl == (struct connlist *) NULL) {
        return( "" );
    }

    if (( buff == (char *) NULL ) || ( bufflen <= 4 )) {
        /* Parameter error */
        return ((char *) NULL);
    }

    paddr[0] = '\0';	/* Initialize string safely */

    /*
     *  Work out the address family.
     */

    switch (cl->conn_sin.sin_family) {
    case AF_UNSPEC:
        strcpy( addr_family, "unspec" );
	break;

    case AF_LOCAL:
        strcpy( addr_family, "Local" );
	break;

    case AF_INET:
        {
	    struct sockaddr_in *s_in = (struct sockaddr_in *) &(cl->conn_sin);

	    strcpy( addr_family, "IPv4" );
	    port = ntohs( s_in->sin_port );
	    p = inet_ntop( cl->conn_sin.sin_family, &(s_in->sin_addr),
			   paddr, sizeof(paddr) );
	}
	break;

    case AF_INET6:
        {
	    struct sockaddr_in6 *s_in6 = (struct sockaddr_in6 *) &(cl->conn_sin);
	
	    strcpy ( addr_family, "IPv6" );
	    port = ntohs ( s_in6->sin6_port );
	    p = inet_ntop( cl->conn_sin.sin_family, &(s_in6->sin6_addr),
			   paddr, sizeof(paddr) );
	}
	break;


    default:
        snprintf (addr_family, sizeof(addr_family), "unknown[%d]", cl->conn_sin.sin_family );
	break;
    }

    if ( p == (char *) NULL ) {
        snprintf( buff, bufflen, "%s", addr_family );
    }

    else if ( cl->conn_sin.sin_port == 0 ) {
        snprintf( buff, bufflen, "%s:[%s]", addr_family, p );

    }

    else {
        snprintf( buff, bufflen, "%s:[%s]:%d", addr_family, p,
		  ntohs( cl->conn_sin.sin_port ));
    }

    return buff;

} /* end of cosign_conn_ntop() */


    const char *
    cosign_conn_ntoa( const struct connlist *cl )
{
#  define CONN_LIST_NTOA_BUFFERS 3
      static unsigned int pos = 0;
      static char buffer[ CONN_LIST_NTOA_BUFFERS ][ COSIGN_CONN_NTOP_SIZE ];
      const char *out = cosign_conn_ntop( buffer[ pos ],
					  COSIGN_CONN_NTOP_SIZE,
					  cl );

      /* If we used the buffer, position to next */
      if ( out != buffer[pos] ) {
	  pos++;
	  pos = pos % CONN_LIST_NTOA_BUFFERS;
      }

      return( out );
      
} /* end of cosign_conn_ntoa() */


    static int
netcheck_cookie( char *scookie, char **rekey, struct sinfo *si,
	struct connlist *conn, void *s, cosign_host_config *cfg )
{
    int			i, j, ac, rc, mf, fc = cfg->reqfc;
    char		*p, *line, **av, **fv = cfg->reqfv;
    char		*rekeyed_cookie = NULL;
    char		*cmd = "CHECK";
    struct timeval      tv;
    SNET		*sn = conn->conn_sn;
    extern int		errno;
    char                pconn[ COSIGN_CONN_NTOP_SIZE ];
    static const char   _func_[] = "netcheck_cookie";

    /* REKEY service-cookie */
    if ( rekey != NULL && COSIGN_CONN_SUPPORTS_REKEY( conn )) {
	cmd = "REKEY";
    }

    if ( (rc = snet_writef( sn, "%s %s\r\n", cmd, scookie )) < 0 ) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s to %s: snet_writef( '%s ...', ...) failed code %d",
		    _func_, cosign_conn_ntop(pconn, sizeof(pconn), conn ), cmd, rc );
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	if ( !snet_eof( sn )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s to %s: snet_getline_multi(): %d %s",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ),
		    errno, strerror( errno ));
	}
	return( COSIGN_ERROR );
    }

    switch( *line ) {
    case '2':
	if (( rate = rate_tick( &checkpass )) != 0.0 ) {
	    cosign_log( APLOG_NOTICE, s,
		    "mod_cosign: STATS CHECK %s: PASS %.5f / sec",
			cosign_conn_ntop( pconn, sizeof(pconn), conn ), 
			rate );
	}
	break;

    case '4':
	if (( rate = rate_tick( &checkfail )) != 0.0 ) {
	    cosign_log( APLOG_NOTICE, s,
		    "mod_cosign: STATS CHECK %s: FAIL %.5f / sec",
			cosign_conn_ntop( pconn, sizeof(pconn), conn ),
			rate );
	}
	return( COSIGN_LOGGED_OUT );

    case '5':
	/* choose another connection */
	if (( rate = rate_tick( &checkunknown )) != 0.0 ) {
	    cosign_log( APLOG_NOTICE, s,
		    "mod_cosign: STATS CHECK %s: UNKNOWN %.5f / sec",
			cosign_conn_ntop( pconn, sizeof(pconn), conn ),
			rate );
	}
	return( COSIGN_RETRY );

    default:
        cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: '%s'", _func_,
		    cosign_conn_ntop( pconn, sizeof(pconn), conn), line );
	return( COSIGN_ERROR );
    }

    if (( ac = argcargv( line, &av )) < 4 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s with %s: wrong num of args(%d): '%s'",
		_func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ),
		ac, line );
	return( COSIGN_ERROR );
    }

    if ( rekey != NULL && COSIGN_CONN_SUPPORTS_REKEY( conn )) {
	/* last factor is penultimate argument */
	mf = ac - 1;
    } else {
	/* last factor is last argument */
	mf = ac;
    }

    /* I guess we check some sizing here :) */
    if ( strlen( av[ 1 ] ) >= sizeof( si->si_ipaddr )) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: IP address too long",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ));
	return( COSIGN_ERROR );
    }
    strcpy( si->si_ipaddr, av[ 1 ] );
    if ( strlen( av[ 2 ] ) >= sizeof( si->si_user )) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: username too long",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ));
	return( COSIGN_ERROR );
    }
    strcpy( si->si_user, av[ 2 ] );

    si->si_protocol = conn->conn_proto;
    if ( COSIGN_PROTO_SUPPORTS_FACTORS( conn->conn_proto )) {
	for ( i = 0; i < fc; i++ ) {
	    for ( j = 3; j < mf; j++ ) {
		if ( strcmp( fv[ i ], av[ j ] ) == 0 ) {
		    break;
		}
		if ( cfg->suffix != NULL ) {
		    if (( p = strstr( av[ j ], cfg->suffix )) != NULL ) {
		        if (( strlen( p )) == ( strlen( cfg->suffix ))) {
			    *p = '\0';
			    rc = strcmp( fv[ i ], av[ j ] );
			    *p = *cfg->suffix;

			    if ( rc == 0 ) {
			        if ( cfg->fake == 1 ) {
				    break;
				}

				cosign_log( APLOG_ERR, s, 
					    "mod_cosign: %s with %s: factor %s "
					    "matches with suffix %s, but suffix " 
					    "matching is OFF", _func_,
					    cosign_conn_ntop( pconn, sizeof(pconn), conn ),
					    av[ j ], cfg->suffix );

				return( COSIGN_ERROR );
				
			    }
			}
		    }
		}
	    }

	    if ( j >= mf ) {
		/* a required factor wasn't in the check line */
		break;
	    }
	}
	if ( i < fc ) {
	    /* we broke out early */
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s: we broke out early", _func_,
			cosign_conn_ntop (pconn, sizeof(pconn),  conn ));
	    return( COSIGN_RETRY );
	}

	if ( strlen( av[ 3 ] ) + 1 > sizeof( si->si_factor )) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s: factor %s too long", _func_,
			cosign_conn_ntop( pconn, sizeof(pconn), conn ), av[ 3 ] );
	    return( COSIGN_ERROR );
	}
	strcpy( si->si_factor, av[ 3 ] );


	for ( i = 4; i < mf; i++ ) {
	    if ( strlen( av[ i ] ) + 1 + 1 >
		    sizeof( si->si_factor ) - strlen( si->si_factor )) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s: factor %s too long",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ),
			av[ i ] );
		return( COSIGN_ERROR );
	    }
	    strcat( si->si_factor, " " );
	    strcat( si->si_factor, av[ i ] );
	}
    }

    if ( strlen( av[ 3 ] ) >= sizeof( si->si_realm )) {
        cosign_log( APLOG_ERR, s,
		"mod_cosign: %s with %s: realm too long",
		_func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ));
	return( COSIGN_ERROR );
    }
    strcpy( si->si_realm, av[ 3 ] );

#ifdef KRB
    *si->si_krb5tkt = '\0';
#endif /* KRB */

    if ( rekey != NULL && COSIGN_CONN_SUPPORTS_REKEY( conn )) {
	if ( strncmp( av[ ac - 1 ], "cosign-", strlen( "cosign-" )) != 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: "
		    "bad rekeyed cookie \"%s\"",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ),
		    av[ ac - 1 ] );
	    return( COSIGN_ERROR );
	}

	if (( rekeyed_cookie = strdup( av[ ac - 1 ] )) == NULL ) {
	    /*???
	     *??? if strdup() fails here, why should anything after it work?
	      ???*/
	    cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: "
		    "strdup() rekeyed cookie: %s",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), conn ),
		    strerror( errno ));
	    return( COSIGN_ERROR );
	}
	*rekey = rekeyed_cookie;
    }

    return( COSIGN_OK );
}

    static int
netretr_proxy( char *scookie, struct sinfo *si, SNET *sn, char *proxydb,
	void *s )
{
    int			fd;
    int			rc;
    char		*line;
    char                path[ MAXPATHLEN ], tmppath[ MAXPATHLEN ];
    struct timeval      tv;
    FILE                *tmpfile;
    static const char   _func_[] = "netretr_proxy";

    /* RETR service-cookie cookies */
    if ( (rc = snet_writef( sn, "RETR %s cookies\r\n", scookie )) < 0 ) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s: snet_writef('RETR ... cookies', ...) failed (%d)",
		    _func_, rc);
	return( COSIGN_ERROR );
    }

    /* name our file and open tmp file */
    if ( snprintf( path, sizeof( path ), "%s/%s", proxydb, scookie ) >=
            sizeof( path )) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s: cookie path too long", _func_);
        return( COSIGN_ERROR );
    }

    if ( gettimeofday( &tv, NULL ) < 0 ) {
        cosign_log( APLOG_ERR, s,
		  "mod_cosign: %s: gettimeofday() failed! %d: %s",
		  _func_, errno, strerror( errno ));
	return( COSIGN_ERROR );
    }

    if ( snprintf( tmppath, sizeof( tmppath ), "%s/%x%x.%i",
	    proxydb, (int)tv.tv_sec, (int)tv.tv_usec, (int)getpid()) >=
	    sizeof( tmppath )) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s: tmppath too long", _func_);
        return( COSIGN_ERROR );
    }

    if (( fd = open( tmppath, O_CREAT|O_EXCL|O_WRONLY, 0644 )) < 0 ) {
        cosign_log( APLOG_ERR, s, 
		    "mod_cosign: %s: open( '%s', ...) failed, %d %s",
		    _func_, tmppath, errno, strerror( errno ));
        return( COSIGN_ERROR );
    }

    if (( tmpfile = fdopen( fd, "w" )) == NULL ) {
        cosign_log (APLOG_ERR, s,
		    "mod_cosign: %s: fdopen (%d {'%s'}, 'w') failed, %d %s",
		    _func_, fd, tmppath, errno, strerror( errno ) );
        if ( unlink( tmppath ) != 0 ) {
	    cosign_log (APLOG_ERR, s,
		    "mod_cosign: %s: unlink('%s') failed, %d %s",
			_func_, tmppath, errno, strerror( errno ));
	}
        return( COSIGN_ERROR );
    }

    tv = timeout;
    do {
	if (( line = snet_getline( sn, &tv )) == NULL ) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s: snet_getline() failed", _func_ );
	    return ( COSIGN_ERROR );
	}

	switch( *line ) {
	case '2':
	    break;

	case '4':
	  cosign_log( APLOG_ERR, s, "mod_cosign: %s: %s", _func_, line );
	    return( COSIGN_LOGGED_OUT );

	case '5':
	    /* choose another connection */
	  cosign_log( APLOG_ERR, s, "mod_cosign: %s: 5xx", _func_ );
	    return( COSIGN_RETRY );

	default:
	    cosign_log( APLOG_ERR, s, "mod_cosign: %s: %s", _func_, line );
	    return( COSIGN_ERROR );
	}

	if ( strlen( line ) < 3 ) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s: short line: '%s'", _func_, line );
	    return( COSIGN_ERROR );
	}
        if ( !isdigit( (int)line[ 1 ] ) ||
                !isdigit( (int)line[ 2 ] )) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s: bad response(1): '%s'", _func_, line );
	    return( COSIGN_ERROR );
        }

	if ( line[ 3 ] != '\0' &&
		line[ 3 ] != ' ' &&
		line [ 3 ] != '-' ) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s: bad response(2): '%s'", _func_, line );
	    return( COSIGN_ERROR );
	}

	if ( line[ 3 ] == '-' ) {
	    fprintf( tmpfile, "x%s\n", &line[ 4 ] );
	}

    } while ( line[ 3 ] == '-' );

    if ( fclose ( tmpfile ) != 0 ) {
        cosign_log( APLOG_ERR, s, 
		"mod_cosign: %s: fclose( {'%s'} ) failed, %d %s",
		_func_, tmppath, errno, strerror( errno ));

        if ( unlink( tmppath ) != 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s: unlink( '%s' ) failed, %d %s",
		    _func_, tmppath, errno, strerror( errno ));
        }
        return( COSIGN_ERROR );
    }

    if ( link( tmppath, path ) != 0 ) {
        cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: link( '%s', '%s' ) failed, %d %s",
		    _func_, tmppath, path, errno, strerror( errno )); 

        if ( unlink( tmppath ) != 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s: unlink( '%s' ) failed, %d %s",
		    _func_, tmppath, errno, strerror( errno ));
        }
        return( COSIGN_ERROR );
    }

    if ( unlink( tmppath ) != 0 ) {
        cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: unlink( '%s' ) failed, %d %s",
		_func_, tmppath, errno, strerror( errno ));
    }

    return( COSIGN_OK );
}

#ifdef KRB
    static int
netretr_ticket( char *scookie, struct sinfo *si, SNET *sn, char *tkt_prefix,
	void *s )
{
    char		*line;
    char                tmpkrb[ 16 ], krbpath [ MAXPATHLEN ];
    char		buf[ 8192 ];
    int			fd; 
    int			rc;
    size_t              size = 0;
    ssize_t             rr;
    struct timeval      tv;
    extern int		errno;
    static const char   _func_[] = "netretr_ticket";

    /* clear it, in case we can't get it later */
    *si->si_krb5tkt = '\0';

    /* RETR service-cookie TicketType */
    if ( (rc = snet_writef( sn, "RETR %s tgt\r\n", scookie )) < 0 ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: snet_writef('RETR ... tgt', ...) failed, code %d",
		_func_, rc);
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline_multi( sn, logger, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: snet_getline_multi() failed, %d %s",
		_func_, errno, ,strerror( errno ));
	return( COSIGN_ERROR );
    }

    switch( *line ) {
    case '2':
	break;

    case '4':
      cosign_log( APLOG_ERR, s, "mod_cosign: %s: '%s'", _func_, line );
	return( COSIGN_LOGGED_OUT );

    case '5':
	/* choose another connection */
      cosign_log( APLOG_ERR, s, "mod_cosign: %s: 5xx", _func_ );
	return( COSIGN_RETRY );

    default:
      cosign_log( APLOG_ERR, s, "mod_cosign: %s: '%s'", _func_, line );
	return( COSIGN_ERROR );
    }

    if ( mkcookie( sizeof( tmpkrb ), tmpkrb ) != 0 ) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s: mkcookie failed", _func_ );
	return( COSIGN_ERROR );
    }

    if ( snprintf( krbpath, sizeof( krbpath ), "%s/%s",
	    tkt_prefix, tmpkrb ) >= sizeof( krbpath )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: krbpath too long (> %d)", _func_,
		sizeof( krbpath ));
	return( COSIGN_ERROR );
    }

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: snet_getline() failed for %s", _func_,
		scookie );
        return( COSIGN_ERROR );
    }
    size = atoi( line );

    if (( fd = open( krbpath, O_WRONLY | O_CREAT | O_EXCL, 0600 )) < 0 ) {
        cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: open( '%s', ...) failed, %d %s",
		_func_, ktbpath, errno, strerror( errno ));
        return( COSIGN_ERROR );
    }

    /* Get file from server */
    while ( size > 0 ) {
        tv = timeout;
        if (( rr = snet_read( sn, buf, (int)MIN( sizeof( buf ), size ),
                &tv )) <= 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s: retrieve tgt failed: %s", _func_, strerror( errno ));
            goto error2;
        }
        if ( write( fd, buf, (size_t)rr ) != rr ) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s: write( %d {'%s'}, ..., %d) failed, %d %s"
			_func_, fd, krbpath, rr, errno, strerror( errno )); 
            goto error2;
        }
        size -= rr;
    }

    if ( close( fd ) != 0 ) {
        cosign_log( APLOG_ERR, s,
		"mod_cosign: %s: close( %d {'%s'} ) failed, %d %s", 
		_func_, fd, krbpath, errno, strerror( errno ));
        goto error1;
    }

    if ( size != 0 ) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: retrieve tickets: size from server did "
		    "not match size read from server" );
	goto error1;
    }

    tv = timeout;
    if (( line = snet_getline( sn, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: retrieve for %s failed: %s",
		scookie, strerror( errno ));
        goto error1;
    }
    if ( strcmp( line, "." ) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s: Missing period. '%s'",
		    _func_, line );
        goto error1;
    }

    /* copy the path to the ticket file */
    if ( strlen( krbpath ) >= sizeof( si->si_krb5tkt )) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: netretr_ticket: krb5tkt path too long" );
	goto error1;
    }
    strcpy( si->si_krb5tkt, krbpath );

    return( COSIGN_OK );

error2:
    close( fd );
error1:
    unlink( krbpath );
    return( COSIGN_ERROR );
}
#endif /* KRB */

    int
teardown_conn( struct connlist **cur, void *s )
{

    /* close down all children on exit */
    for ( ; cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn != NULL  ) {
	    close_sn( *cur, s );
	}
    }
    return( 0 );
}

    int
cosign_check_cookie( char *scookie, char **rekey, struct sinfo *si,
	cosign_host_config *cfg, int first, void *s )
{
    struct connlist	**cur, *tmp;
    int			rc = COSIGN_ERROR, retry = 0;
    static const char   _func_[] = "cosign_check_cookie";
    char                pconn[ COSIGN_CONN_NTOP_SIZE ];


    /* use connection, then shuffle if there is a problem
     * what happens if they are all bad?
     */
    for ( cur = cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn == NULL ) {
	    continue;
	}

	switch ( rc = netcheck_cookie( scookie, rekey, si, *cur, s, cfg )) {
	case COSIGN_OK :
	case COSIGN_LOGGED_OUT :
	    goto done;

	case COSIGN_RETRY :
	    retry = 1;
	    break;

	default:
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: netcheck_cookie() unknown return: %d",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), *cur ),
		    rc );
	    /* ** FALL THROUGH ** */

	case COSIGN_ERROR :
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
	          cosign_log( APLOG_ERR, s,
			  "mod_cosign: %s with %s: snet_close() failed",
			  _func_, cosign_conn_ntop( pconn, sizeof(pconn), *cur ));
	    }
	    (*cur)->conn_sn = NULL;
	    break;
	}
    }

    /* all are closed or we didn't like their answer */
    for ( cur = cfg->cl; *cur != NULL; cur = &(*cur)->conn_next ) {
	if ( (*cur)->conn_sn != NULL ) {
	    continue;
	}
	if (( rc = connect_sn( *cur, cfg, s )) != 0 ) {
	    continue;
	}

	switch ( rc = netcheck_cookie( scookie, rekey, si, *cur, s, cfg )) {
	case COSIGN_OK :
	case COSIGN_LOGGED_OUT :
	    goto done;

	case COSIGN_RETRY :
	    retry = 1;
	    break;

	default:
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: netcheck_cookie() (2) unknown return: %d",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), *cur ), rc );

	    /* ** FALL THROUGH ** */

	case COSIGN_ERROR :
	    if ( snet_close( (*cur)->conn_sn ) != 0 ) {
		cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s: snet_close() failed %d",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), *cur ),
			rc);
	    }
	    (*cur)->conn_sn = NULL;
	    break;
	}
    }

    if ( retry ) {
	return( COSIGN_RETRY );
    }
    return( COSIGN_ERROR );


done:
    if ( cur != cfg->cl ) {
	tmp = *cur;
	*cur = (*cur)->conn_next;
	tmp->conn_next = *(cfg->cl);
	*(cfg->cl) = tmp;
    }
    if ( rekey && *rekey ) {
	/* use the rekeyed cookie to request tickets and proxy cookies */
	scookie = *rekey;
    }

    if ( rc == COSIGN_LOGGED_OUT ) {
	return( COSIGN_RETRY );
    }

    
    if (( first ) && ( cfg->proxy == 1 )) {
          if ( netretr_proxy( scookie, si, (*(cfg->cl))->conn_sn,
		    cfg->proxydb, s ) != COSIGN_OK ) {
	      cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: netretr_proxy() can't retrieve proxy cookies",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), *(cfg->cl) ));
	  }
    }

#ifdef KRB
    if (( first ) && ( cfg->krbtkt == 1 )) {
        if ( netretr_ticket( scookie, si, (*(cfg->cl))->conn_sn, 
		     cfg->tkt_prefix, s ) != COSIGN_OK ) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s: netretr_ticket() can't retrieve kerberos ticket",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), *(cfg->cl) ));
	}
    }
#endif /* KRB */

    return( COSIGN_OK );
}

/*
 * parse and store server capabilities.
 *
 * cosignd capabilities are sent to client in a whitespace separated list
 * bounded by square brackets:
 * 
 * "220 2 Collaborative Web Single Sign-On [COSIGNv3 FACTORS=5 REKEY ...]"
 *
 * the capability list must begin with "[COSIGNv<protocol_number>".
 */
    static int
capa_parse( int capac, char **capav, struct connlist *cl, void *s )
{
    char		*tmp = NULL;
    int			i, j, len;
    int			ncapa;
    char                pconn[ COSIGN_CONN_NTOP_SIZE ];
    static const char   _func_[] = "capa_parse";
          
    if ( capac < 1 ) {
        cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: No capability list (%d)",
		  _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), capac );
	return( -1 );
    }

    if ( strncmp( capav[ 0 ], "[COSIGNv", strlen( "[COSIGNv" )) != 0 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: unexpected output from "
		"server (expected \"[COSIGNv\", got \"%s\")",
		_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl), 
		capav[ 0 ] );
	return( -1 );
    }

    /* get protocol version */
    capav[ 0 ] += strlen( "[COSIGNv" );
    errno = 0;
    cl->conn_proto = strtol( capav[ 0 ], &tmp, 10 );
    if ( errno ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s unexpected output from "
		    "server %s (expected integer, got \"%s\")",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ),
		    capav[0] );
	return( -1 );
    }

    if ( tmp ) {
	if ( *tmp != '\0' ) {
	    if ( strcmp( tmp, "]" ) == 0 ) {
		/* all server gave was "[COSIGNv3]" */
		return( 0 );
	    }
	    cosign_log( APLOG_ERR, s, 
			"mod_cosign: %s from %s: bad protocol value: \"%s\"",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ),
			tmp );
	    return( -1 );
	}

	/*
	 * if *tmp == '\0', the protocol was a valid integer, and
	 * there are more capabilities to process.
	 */
    }
    capac--;
    capav++;

    ncapa = sizeof( caps ) / sizeof( caps[ 0 ] );
    for ( i = 0; i < capac; i++ ) {
	for ( j = 0; j < ncapa; j++ ) {
	    if ( cl->conn_capa & caps[ j ].capa_mask ) {
		/* avoid the strncasecmp, if possible */
		continue;
	    }
	    if ( strncasecmp( capav[ i ], caps[ j ].capa_name,
			      caps[ j ].capa_nlen ) == 0 ) {
		break;
	    }
	}
	if ( j >= ncapa ) {
	    cosign_log( APLOG_INFO, s, 
		    "mod_cosign: unrecognized capability from server %s: \"%s\"",
		    cosign_conn_ntop( pconn, sizeof(pconn), cl ), capav[ i ] );
	    continue;
	}

	cl->conn_capa |= caps[ j ].capa_mask;

	/*
	 * check for capability list termination. capav[ i ] is at least
	 * capa_nlen chars long, as tested by strncasecmp above.
	 */
	tmp = ( capav[ i ] + caps[ j ].capa_nlen );

#ifdef notdef
	/* process any attached values (CAPA=VAL) if callback is non-NULL */
	if ( *tmp == '=' && caps[ j ].capa_cb != NULL ) {
	    tmp++;
	    if (( len = strlen( tmp )) > 0 ) {
		if ( tmp[ len - 1 ] == ']' ) {
		    len--;
		}
		if ( (*(caps[ j ].capa_cb))( j, tmp, len, s ) != 0 ) {
		    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s:  failed to process capability pair '%s'",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ),
			capav[ i ] );
		    return( -1 );
		}
		tmp += len;
	    }
	}
#endif /* notdef */

	if ( *tmp == ']' ) {
	    /* end of list */
	    break;
	}
    }
    if ( tmp == NULL || *tmp != ']' ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: warning: no terminating "
		    "\']\' in capability list from server",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
    }

    return( 0 );
}

    static int
connect_sn( struct connlist *cl, cosign_host_config *cfg, void *s )
{
    int			sock, zero = 0, ac = 0, state;
    int                 delay;
    int			rc;
    char		*line, buf[ 1024 ], **av;
    X509		*peer;
    struct timeval      tv;
    struct protoent	*proto;
    time_t              start = time( NULL );
    time_t              now;
    char                pconn[ COSIGN_CONN_NTOP_SIZE ];
    static const char   _func_[] = "connect_sn";
    

    errno = 0;

    if (( sock = socket( PF_INET, SOCK_STREAM, 0 )) < 0 ) {
      cosign_log( APLOG_ERR, s,
		  "mod_cosign: %s with %s: socket() failed:%d %s",
		  _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl), 
		  errno, strerror( errno ) );
	return( -1 );
    }

    if (( proto = getprotobyname( "tcp" )) != NULL ) {
	if ( setsockopt( sock, proto->p_proto, TCP_NODELAY,
		&zero, sizeof( zero )) < 0 ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: setsockopt(%d,...TCP_NODELAY) failed: %d %s",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), sock,
		    errno, strerror( errno ));
	}
    }

    if ( connect( sock, ( struct sockaddr *)&cl->conn_sin,
	    sizeof( struct sockaddr_in )) != 0 ) {
        int save_errno = errno;

	now = time( NULL );
	delay = now - start;

        cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: connect(%d, ...) failed after %d seconds: %d %s",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), sock, delay,
		    save_errno, strerror(save_errno));
	(void)close( sock );
	return( -1 );
    }

    if (( cl->conn_sn = snet_attach( sock, 1024 * 1024 ) ) == NULL ) {
        now = time( NULL );
	delay = now - start;

	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: snet_attach() failed after %d seconds",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ),  delay);
	(void)close( sock );
	return( -1 );
    }

    tv = timeout;
    if (( line = snet_getline( cl->conn_sn, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s with %s: snet_getline() failed",
		_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
	goto done;
    }

    if ( *line != '2' ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: protocol error '%s'",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), line );
	goto done;
    }

    if (( ac = argcargv( line, &av )) < 4 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: protocol error argcargv(): '%s'",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), line );
	goto done;
    }

    errno = 0;
    cl->conn_proto = strtol( av[ 1 ], (char **)NULL, 10 );
    if ( errno ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: unrecognized protocol "
		    "version %s, falling back to protocol v0",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), av[1]);
	cl->conn_proto = COSIGN_PROTO_V0;
    }
    if ( cfg->reqfc > 0 && !COSIGN_PROTO_SUPPORTS_FACTORS( cl->conn_proto )) {
	cosign_log( APLOG_ERR, s, "mod_cosign: required v2 or greater "
		    "protocol unsupported by server %s "
		    "(server protocol version: %s)", 
		    cosign_conn_ntop( pconn, sizeof(pconn), cl ), av[ 1 ] );
	goto done;
    }
	   
    cl->conn_capa = COSIGN_CAPA_DEFAULTS;
    if ( ac > 6 ) {
	/* "220 2 Collaborative Web Single Sign-On [COSIGNv3 REKEY ...]" */
	ac -= 6;
	av += 6;
	
	if ( capa_parse( ac, av, cl, s ) < 0 ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: failed to parse server "
			"capabilities", _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
	    goto done;
	}
    } else {
	/* pre-3.1: "220 2 Collaborative Web Single Sign-On" */
	if ( COSIGN_PROTO_SUPPORTS_FACTORS( cl->conn_proto )) {
	    cl->conn_capa |= COSIGN_CAPA_FACTORS;
	}
    }

    if ( cl->conn_proto >= COSIGN_PROTO_V2 ) {
      if ( (rc = snet_writef( cl->conn_sn, "STARTTLS %d\r\n",
			      cl->conn_proto )) < 0 ) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s: snet_write(.., 'STARTTLS %d') failed code %d",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), cl->conn_proto, rc );
	    goto done;
	}
    } else {
        if ( (rc = snet_writef( cl->conn_sn, "STARTTLS\r\n" )) < 0 ) {
	    cosign_log( APLOG_ERR, s,
			"mod_cosign: %s with %s: snet_write(..., 'STARTTLS') failed code %d",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), rc );
	    goto done;
	}
    }

    tv = timeout;
    if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s with %s: snet_getline_multi() failed",
		_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
	goto done;
    }
    if ( *line != '2' ) {
       cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: '%s'",
		   _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), line );
       goto done;
    }

    if ( (rc = snet_starttls( cl->conn_sn, cfg->ctx, 0 )) != 1 ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: snet_starttls() error %d: %s",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ),
		    rc, ERR_error_string( ERR_get_error(), NULL ));
	goto done;
    }

    if (( peer = SSL_get_peer_certificate( cl->conn_sn->sn_ssl )) == NULL ) {
        cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: no certificate",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
	goto done;
    }

    X509_NAME_get_text_by_NID( X509_get_subject_name( peer ), NID_commonName,
	    buf, sizeof( buf ));
    X509_free( peer );

    /* cn and host must match */
    if ( strcasecmp( buf, cfg->host ) != 0 ) {
	cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: 'cn=%s' & 'host=%s': don't match!", 
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), buf, cfg->host );
	goto done;
    }

    if ( cl->conn_proto >= COSIGN_PROTO_V2 ) {
	tv = timeout;
	if (( line = snet_getline_multi( cl->conn_sn, logger, &tv )) == NULL ) {
	    cosign_log( APLOG_ERR, s,
		    "mod_cosign: %s with %s: snet_getline_multi() failed",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
	    goto done;
	}
	if ( *line != '2' ) {
	    cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: Protocol 2+ errorr: '%s'",
			_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), line );
	    goto done;
	}
    }

    return( 0 );


done:
    if ( snet_close( cl->conn_sn ) != 0 ) {
        cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: snet_close() failed",
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
    }
    cl->conn_sn = NULL;
    cl->conn_proto = COSIGN_PROTO_V0;

    return( -1 );
}


    static void
close_sn( struct connlist *cl, void *s )
{
    int                 rc;
    char		*line;
    struct timeval      tv;
    char                pconn[ COSIGN_CONN_NTOP_SIZE ];
    static const char   _func_[] = "close_sn";


    /* Close network connection */
    if ( (rc = snet_writef( cl->conn_sn, "QUIT\r\n" )) <  0 ) {
	cosign_log( APLOG_ERR, s, 
		"mod_cosign: %s with %s: snet_writef('QUIT') failed, code %d",
		_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), rc);
	goto finish;
    }
    tv = timeout;
    if ( ( line = snet_getline_multi( cl->conn_sn, logger, &tv ) ) == NULL ) {
	cosign_log( APLOG_ERR, s,
		"mod_cosign: %s with %s: snet_getline_multi() failed",
		_func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ));
	goto finish;
    }

    if ( *line != '2' ) {
	cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: QUIT protocol misbehavior: '%s'", 
		    _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), line );
    }

finish:
    if ( (rc = snet_close( cl->conn_sn )) != 0 ) {
      cosign_log( APLOG_ERR, s, "mod_cosign: %s with %s: snet_close() failed, code %d",
		  _func_, cosign_conn_ntop( pconn, sizeof(pconn), cl ), rc);
    }
    cl->conn_sn = NULL;

    return;
}
