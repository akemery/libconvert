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
#if 0
    if (*result >= 0)
      _alloc((int)*result);
#endif

    /* TCPLS initialization */
    _tcpls_init(0);
    /* skip as we executed the syscall ourself. */
    return SYSCALL_SKIP;
  }
  return SYSCALL_RUN;
}

UNUSED static int _handle_connect(void){
  return 0;
}

UNUSED static int _handle_send(void){
  return 0;
}

UNUSED static int _handle_recv(void){
  return 0;
}

UNUSED static int _handle_close(void){
  return 0;
}

UNUSED static void _log_lock(UNUSED void *udata, int lock){
  if (lock)
    pthread_mutex_lock(&_log_mutex);
  else
    pthread_mutex_unlock(&_log_mutex);
}

static int
_hook(long syscall_number, long arg0, long arg1, long arg2, long UNUSED arg3,
      UNUSED long arg4, UNUSED long arg5, long *result){
  switch(syscall_number){
    case SYS_socket:
      return _handle_socket(arg0, arg1, arg2, result);
#if 0
    case SYS_connect:
      return _handle_connect();
    case SYS_send:
      return _handle_send();
    case SYS_recv:
      return _handle_recv();
    case SYS_close:
      return _handle_close();
#endif
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
