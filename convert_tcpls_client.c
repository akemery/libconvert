#include <libsyscall_intercept_hook_point.h>
#include <log.h>

#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>

#include <picotls.h>
#include <picotcpls.h>
#include "picotls/openssl.h"

#include "convert_util.h"
#include "convert_tcpls.h"

static FILE *		_log;
static pthread_mutex_t	_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static int _handle_socket(long arg0, long arg1, long arg2, long *result){
  /* Only consider TCP-based sockets. */
  if (((arg0 == AF_INET) || (arg0 == AF_INET6)) && (arg1 == SOCK_STREAM)) {
    log_debug("handle socket(%ld, %ld, %ld)", arg0, arg1, arg2);
    *result = syscall_no_intercept(SYS_socket, arg0, arg1, arg2);
    log_debug("-> fd: %d", (int)*result);
    
    if (*result >= 0){
      /* TCPLS context initializing */
      _tcpls_init(0);
      /* TCPLS allocating con_info */
      _tcpls_alloc_con_info(*result);
    }
    
    /* skip as we executed the syscall ourself. */
    return SYSCALL_SKIP;
  }
  return SYSCALL_RUN;
}

static int _handle_connect(long arg0, long arg1,  UNUSED long arg2, long *result){
  struct tcpls_con *con;
  struct sockaddr *	dest	= (struct sockaddr *)arg1;
  int sd = (int)arg0;

  con = _tcpls_lookup(sd);
  if (!con)
    return SYSCALL_RUN;
    
  log_debug("Opening TCPLS connexion on sd:%d", sd);

  switch (dest->sa_family) {
    case AF_INET:
    case AF_INET6:
      //*result = syscall_no_intercept(SYS_connect, arg0, arg1, arg2);
      *result = _handle_tcpls_connect(sd, dest);
        break;
    default:
      log_warn("sd %d specified an invalid address family %d", sd,
		   dest->sa_family);
      goto error;
  }

  if (*result >= 0) {
    log_debug("TCPLS connexion opened on %d:%d", sd, *result);
    return SYSCALL_SKIP;
  }

  log_warn("TCPLS connexion %d failed with error: %d", sd, *result);
error:
  return SYSCALL_RUN;
}

static int _handle_read(long arg0, long arg1, long arg2, long *result){
  struct tcpls_con *con;
  int sd = (int)arg0;
  log_debug("TCPLS read on %d\n", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_read, arg0, arg1, arg2);
  if(*result >= 0){
    log_debug("TCPLS read on %d:%d\n", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS read %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_recvfrom(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result){
  struct tcpls_con *con;
  int sd = (int)arg0;
  log_debug("TCPLS recvfrom on %d\n", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
#if 1
  *result = _tcpls_handshake(sd);
  if(*result < 0){
    log_debug("handshake failed %d:%d", sd, *result);
  }
#endif
  *result = syscall_no_intercept(SYS_recvfrom, arg0, arg1, arg2, arg3, arg4, arg5);
  if(*result >= 0){
    log_debug("TCPLS recvfrom on %d:%d\n", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS recvfrom %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_recvmsg(long arg0, long arg1, long arg2, long *result){
  struct tcpls_con *con;
  int sd = (int)arg0;
  log_debug("TCPLS recvmsg on %d\n", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_recvmsg, arg0, arg1, arg2);
  if(*result >= 0){
    log_debug("TCPLS recvmsg on %d:%d\n", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS recvmsg %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_sendto(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result){
  struct tcpls_con *con;
  int sd = (int)arg0;
  log_debug("TCPLS sendto on %d\n", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_sendto, arg0, arg1, arg2, arg3, arg4, arg5);
  if(*result >= 0){
    log_debug("TCPLS sendto on %d:%d\n", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS sendto %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_sendmsg(long arg0, long arg1, long arg2, long *result){
  struct tcpls_con *con;
  int sd = (int)arg0;
  log_debug("TCPLS sendmsg on %d\n", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_sendmsg, arg0, arg1, arg2);
  if(*result >= 0){
    log_debug("TCPLS sendmsg on %d:%d\n", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS sendmsg %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_close(long arg0, long *result){
  int sd = (int)arg0;
  if(_tcpls_free_con(sd)){
      //log_debug("not handled socket %d:%d failed\n", sd, *result);
      return SYSCALL_RUN;
  }
  *result = syscall_no_intercept(SYS_close, arg0);
  if(*result >= 0){
    log_debug("connexion closed %d:%d\n", sd, *result);
    return SYSCALL_SKIP;
  }
  log_debug("connexion closed %d:%d failed\n", sd, *result);
  return SYSCALL_RUN;
}

UNUSED static void _log_lock(UNUSED void *udata, int lock){
  if (lock)
    pthread_mutex_lock(&_log_mutex);
  else
    pthread_mutex_unlock(&_log_mutex);
}

static int
_hook(long syscall_number, long arg0, long arg1, long arg2, long UNUSED arg3,
       long arg4,  long arg5, long *result){
  switch(syscall_number){
    case SYS_socket:
      return _handle_socket(arg0, arg1, arg2, result);
    case SYS_connect:
      return _handle_connect(arg0, arg1,  arg2, result);
    case SYS_read:
      return _handle_read(arg0, arg1,arg2, result);
    case SYS_recvfrom:
      return _handle_recvfrom(arg0, arg1, arg2, arg3, arg4, arg5, result);
    case SYS_recvmsg:
      return _handle_recvmsg(arg0, arg1, arg2, result);
    case SYS_close:
      return _handle_close(arg0, result);
    case SYS_sendto:
      return _handle_sendto(arg0, arg1, arg2, arg3, arg4, arg5, result);
    case SYS_sendmsg:
      return _handle_sendmsg(arg0, arg1, arg2, result);
    default:
      /* The default behavior is to run the default syscall. */
      return SYSCALL_RUN;
  } 
}
static __attribute__((constructor)) void init(void) {
  UNUSED char err_buf[1024];
  const char *	log_path = getenv("CONVERT_LOG");
  log_set_quiet(1);
  //log_set_lock(_log_lock);
  /* open the log iff specified */
  if (log_path) {
    _log = fopen(log_path, "w");
    if (!_log)
      fprintf(stderr, "convert: unable to open log %s: %s",
			        log_path, strerror(errno));
    log_set_fp(_log);
  }
  log_info("Starting interception");
#if 0  
  if (_validate_config(err_buf, sizeof(err_buf)) < 0)
    log_error("Unable to setup connection interception: %s.",
		          err_buf);
  else
#endif
  /* Set up the callback function */
    intercept_hook_point = _hook;
}

static __attribute__((destructor)) void fini(void){
  log_info("Terminating interception");
  if (_log)
    fclose(_log);
}
