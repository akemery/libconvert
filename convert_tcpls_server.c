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
  log_debug("handle start socket(%ld, %ld, %ld):%d:%d:%d:%d", arg0, arg1, arg2, SOCK_STREAM, AF_INET, AF_INET6, SOCK_STREAM&arg1);
  /* Only consider TCP-based sockets. */
  if (((arg0 == AF_INET) || (arg0 == AF_INET6)) && (arg1 & SOCK_STREAM)) {
    log_debug("handle socket(%ld, %ld, %ld)", arg0, arg1, arg2);
    *result = syscall_no_intercept(SYS_socket, arg0, arg1, arg2);
    log_debug("-> fd: %d", (int)*result);
    if (*result >= 0){
      /* TCPLS context initializing*/
      _tcpls_init(1);
      /* TCPLS allocating con_info */
      _tcpls_alloc_con_info(*result);
    }
    /* skip as we executed the syscall ourself. */
    return SYSCALL_SKIP;
  }
  return SYSCALL_RUN;
}

static int _handle_bind(long arg0, long arg1, long arg2, long *result){
  struct sockaddr *addr = (struct sockaddr *)arg1;
  int sd = (int)arg0;
  struct tcpls_con *con;
  log_debug("TCPLS binding addr on :%d", sd);

  con = _tcpls_lookup(sd);
  if (!con)
    return SYSCALL_RUN;
  switch (addr->sa_family) {
    case AF_INET:
    case AF_INET6:
      *result = syscall_no_intercept(SYS_bind, arg0, arg1, arg2);
      _tcpls_set_ours_addr(addr);
      break;
    default:
      log_warn("sd %d specified an invalid address family %d", sd,
		   addr->sa_family);
      goto error;
  }
  if (*result >= 0) {
    log_debug("TCPLS binding on %d:%d", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS binding on %d failed with error: %d", sd, *result);
error:
  return SYSCALL_RUN;
}

static int _handle_listen(long arg0, long arg1, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  log_debug("TCPLS listen on :%d", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_listen, arg0, arg1);
  if (*result >= 0) {
    log_debug("TCPLS listen on %d:%d:%d", sd, *result, (int)arg1);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS listen on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_accept4(long arg0, long arg1, long arg2, long arg3, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  log_debug("TCPLS accept4 on %d:", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_accept4, arg0, arg1, arg2, arg3);
  if(*result >= 0){
    log_debug("TCPLS accept4 on %d:%d", sd, *result);
    *result = _tcpls_do_tcpls_accept(*result, (struct sockaddr *)arg1);
    if(*result < 0){
      log_debug("TCPLS tcpls_accept failed %d", *result);
      return SYSCALL_RUN;
    }
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS accept4 on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

UNUSED static int _handle_accept(long arg0, long arg1, long arg2, long arg3, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  log_debug("TCPLS accept on %d:", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_accept, arg0, arg1, arg2, arg3);
  if(*result >= 0){
    log_debug("TCPLS accept on %d:%d", sd, *result);
    _tcpls_alloc_con_info(*result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS accept on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_read(long arg0, long arg1, long arg2, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  log_debug("TCPLS read on %d", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
#if 1
  *result = _tcpls_handshake(sd);
  if(*result < 0){
    log_debug("handshake failed %d:%d", sd, *result);
  }
#endif

  *result = syscall_no_intercept(SYS_read, arg0, arg1, arg2);
  if(*result >= 0){
    log_debug("TCPLS read on %d:%d", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS read on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_writev(long arg0, long arg1, long arg2, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  log_debug("TCPLS writev on %d", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_writev, arg0, arg1, arg2);
  if(*result >= 0){
    log_debug("TCPLS writev on %d:%d", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS writev on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}


UNUSED static int _handle_write(long arg0, long arg1, long arg2, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  log_debug("TCPLS write on %d", sd);
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_write, arg0, arg1, arg2);
  if(*result >= 0){
    log_debug("TCPLS write on %d:%d", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS write on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_close(long arg0, long *result){
  int sd = (int)arg0;
  if(_tcpls_free_con(sd))
      return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_close, arg0);
  if(*result >= 0){
    log_debug("connexion closed %d:%d\n", sd, *result);
    return SYSCALL_SKIP;
  }
  log_debug("connexion closed %d:%d failed\n", sd, *result);
  return SYSCALL_RUN;
}

static void _log_lock(UNUSED void *udata, int lock){
  if (lock)
    pthread_mutex_lock(&_log_mutex);
  else
    pthread_mutex_unlock(&_log_mutex);
}

static int
_hook(long syscall_number, long arg0, long arg1,  long arg2, long  arg3,
      UNUSED long arg4, UNUSED long arg5, long *result){
  switch(syscall_number){
    case SYS_socket:
      return _handle_socket(arg0, arg1, arg2, result);
    case SYS_bind:
      return _handle_bind(arg0, arg1, arg2, result);
    case SYS_listen:
      return _handle_listen(arg0, arg1, result);
    case SYS_accept4:
      return _handle_accept4(arg0, arg1, arg2, arg3, result);
#if 0
    case SYS_accept:
      return _handle_accept(arg0, arg1, arg2, arg3, result);
#endif
    case SYS_read:
      return _handle_read(arg0, arg1, arg2, result);

    case SYS_writev:
      return _handle_writev(arg0, arg1, arg2, result);
#if 0
    case SYS_write:
      return _handle_write(arg0, arg1, arg2, result);
#endif
    case SYS_close:
      return _handle_close(arg0, result);
    default:
      /* The default behavior is to run the default syscall. */
      return SYSCALL_RUN;
  }  
}

static __attribute__((constructor)) void init(void) {
  UNUSED char err_buf[1024];
  const char *	log_path = getenv("CONVERT_LOG");
  log_set_quiet(1);
  log_set_lock(_log_lock);
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
  /* Set up the callback function */
#endif
    intercept_hook_point = _hook;
}

static __attribute__((destructor)) void fini(void){
  log_info("Terminating interception");
  if (_log)
    fclose(_log);
}
