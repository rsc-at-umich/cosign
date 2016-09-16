/*
 * filters/common/log.h
 *
 * Copyright (c) 2016 by the Regents of the University of Michigan
 * All Rights Reserved.
 *
 * See LICENSE
 */


#ifndef _COSIGN_FILTERS_COMMON_LOG_H_
#  define _COSIGN_FILTERS_COMMON_LOG_H 1

#  ifndef LIGHTTPD
#    ifdef APACHE2
#      define cosign_log( level, server, ... )	ap_log_error( APLOG_MARK, (level)|APLOG_NOERRNO, 0, (server), __VA_ARGS__)
#      define cosign_log_req( level, request, ... )	ap_log_rerror( APLOG_MARK, (level)|APLOG_NOERRNO, 0, (request), __VA_ARGS__)

#    else /* APACHE1 */
#      define cosign_log( level, server, ... )	ap_log_error( APLOG_MARK, (level)|APLOG_NOERRNO, (server),  __VA_ARGS__)
#      define cosign_log_req( level, request, ... )	ap_log_rerror( APLOG_MARK, (level)|APLOG_NOERRNO, (request),  __VA_ARGS__)

#    endif /* APACHE2 */
#  endif /* !LIGHTTPD */

#endif /* _COSIGN_COMMON_FILTERS_LOG_H */
