#include <libsyscall_intercept_hook_point.h>
#include <log.h>

#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <arpa/inet.h>

#include <picotls.h>
#include <picotcpls.h>
#include "picotls/openssl.h"

#include "convert_util.h"
#include "convert_tcpls.h"

static FILE *		_log;
static int client_initialized = 0;


static int _handle_connect(long arg0, long arg1,  UNUSED long arg2, long *result){
  struct sockaddr *dest	= (struct sockaddr *)arg1;
  int sd = (int)arg0, ret;
  if (!client_initialized) {
    _tcpls_init(0);
    client_initialized = 1;
  }
  _tcpls_alloc_con_info(sd, 0, dest->sa_family);
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  assert(con);
  switch (dest->sa_family) {
    case AF_INET:
    case AF_INET6: 
      {
        /*int switchback;*/
        /*switchback = set_blocking_mode(sd, 0);*/
        *result = _handle_tcpls_connect(sd, dest, con->tcpls);
        /*if (switchback)*/
          /*set_blocking_mode(sd, 1);*/
        break;
      }
    default:
      log_debug("sd %d specified an invalid address family %d", sd,
		   dest->sa_family);
  }
  if (*result >= 0) {
    ret = _tcpls_handshake(sd, con->tcpls);
    if(ret != 0){
      log_debug("handshake failed %d:%d:%d", sd, *result, ret);
      return SYSCALL_SKIP;
    }
    log_debug("TCPLS: Open connexion on %d handshake OK", sd);
    return SYSCALL_SKIP;
  }
  log_debug("TCPLS connexion %d failed with error: %d", sd, *result);
  return SYSCALL_SKIP;
}

static int _handle_recv(long arg0, long arg1, long arg2, long arg3, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  uint8_t *buf = (uint8_t*)arg1;
  size_t size = (size_t)arg2;
  int flags = (int) arg3;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  /*int switchback;*/
  /*switchback = set_blocking_mode(sd, 1);*/
  *result = _tcpls_do_recv(sd, buf, size, flags, con->tcpls);
  /*if (switchback)*/
    /*set_blocking_mode(sd, 0);*/
  if(*result >= 0){
    log_debug("TCPLS read on socket descriptor :%d received :%d bytes", sd, *result);
    return SYSCALL_SKIP;
  }
  log_debug("TCPLS read on %d failed with error: %d", sd, *result);
  return SYSCALL_SKIP;
}

static int _handle_write(long arg0, long arg1, long arg2, long *result){
  int sd = (int)arg0;
  size_t size = (size_t)arg2; 
  uint8_t *buff = (uint8_t *) arg1;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  //*result = syscall_no_intercept(SYS_write, arg0, arg1, arg2);
  int switchback;
  switchback = set_blocking_mode(sd, 1);
  *result = _tcpls_do_send(buff, size, con->tcpls);
  if (switchback)
    set_blocking_mode(sd, 0);
  if(*result >= 0){
    log_debug("TCPLS write on socket descriptor %d, %d bytes written", sd, *result);
    return SYSCALL_SKIP;
  }
  log_debug("TCPLS write on %d failed with error: %d", sd, *result);
  return SYSCALL_SKIP;
}

static int _handle_sendto(long arg0, long arg1, long arg2, UNUSED long arg3,
    UNUSED long arg4, UNUSED long arg5, long *result){
  return _handle_write(arg0, arg1, arg2, result);
}


static int _handle_close(long arg0, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  log_debug("App wants to close %d sending tcpls_close message", sd);
  /** Close the stream if this is a graceful shutdown*/
  //TODO
  *result = 0;
  return SYSCALL_RUN;
}


static int
_hook(long syscall_number, long arg0, long arg1, long arg2, long UNUSED arg3,
       long arg4,  long arg5, long *result){
  switch(syscall_number){
    case SYS_connect:
      return _handle_connect(arg0, arg1,  arg2, result);
    case SYS_read:
    case SYS_recvfrom:
      return _handle_recv(arg0, arg1,arg2, arg3, result);
    case SYS_close:
      return _handle_close(arg0, result);
    case SYS_sendto:
      return _handle_sendto(arg0, arg1, arg2, arg3, arg4, arg5, result);
    case SYS_write:
      return _handle_write(arg0, arg1, arg2, result);
    default:
      /* The default behavior is to run the default syscall. */
      return SYSCALL_RUN;
  } 
}
static __attribute__((constructor)) void init(void) {
  UNUSED char err_buf[1024];
  const char *	log_path = getenv("CONVERT_LOG");
  log_set_quiet(1);
  /* open the log iff specified */
  if (log_path) {
    _log = fopen(log_path, "w");
    if (!_log)
      fprintf(stderr, "convert: unable to open log %s: %s",
			        log_path, strerror(errno));
    log_add_fp(_log, LOG_DEBUG);
    /*log_set_fp(_log);*/
  }
  log_debug("Starting interception");
  /* Set up the callback function */
    intercept_hook_point = _hook;
}

static __attribute__((destructor)) void fini(void){
  log_debug("Terminating interception");
  if (_log)
    fclose(_log);
}
