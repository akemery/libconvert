#include <libsyscall_intercept_hook_point.h>
#include <log.h>

#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <picotls.h>
#include <picotcpls.h>
#include "picotls/openssl.h"

#include "convert_util.h"
#include "convert_tcpls.h"

static FILE *		_log;

static int _handle_socket(long arg0, long arg1, long arg2, long *result){
  if (((arg0 == AF_INET) || (arg0 == AF_INET6)) && (arg1 & SOCK_STREAM)) {
    *result = syscall_no_intercept(SYS_socket, arg0, arg1, arg2);
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
    char buf[INET_ADDRSTRLEN +1];
    inet_ntop(addr->sa_family, addr, buf, sizeof(buf));          
    log_debug("TCPLS bind on socket descriptor :%d on addr :%s", sd, buf);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS binding on %d failed with error: %d", sd, *result);
error:
  return SYSCALL_RUN;
}

static int _handle_listen(long arg0, long arg1, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_listen, arg0, arg1);
  if (*result >= 0) {
    log_debug("TCPLS listen on socket descriptor :%d backlog :%d", sd, (int)arg1);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS listen on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_accept4(long arg0, long arg1, long arg2, long arg3, long *result){
  int sd = (int)arg0, ret;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  *result = syscall_no_intercept(SYS_accept4, arg0, arg1, arg2, arg3);
  if(*result >= 0){
    ret = _tcpls_do_tcpls_accept(*result, (struct sockaddr *)arg1);
    if(ret != 0){
      return SYSCALL_RUN;
    }
    ret = _tcpls_handshake(*result);
    if(ret != 0){
      return SYSCALL_RUN;
    }
    log_debug("TCPLS: accepting new connection %d on %d handshake OK", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS accept on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

UNUSED static int _handle_accept(long arg0, long arg1, long arg2, long arg3, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  log_debug("TCPLS accept on %d:", sd);
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
  uint8_t *buf = (uint8_t*)arg1;
  size_t size = (size_t)arg2;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  //*result = syscall_no_intercept(SYS_read, arg0, arg1, arg2);
  *result = _tcpls_do_read(sd, buf, size, 0);
  if(*result >= 0){
    log_debug("TCPLS read on socket descriptor :%d received :%d bytes", sd, *result);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS read on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}

static int _handle_writev(long arg0, long arg1, long arg2, long *result){
  int sd = (int)arg0;
  int n = (int)arg2, i;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  log_debug("TCPLS start writev on socket descriptor:%d", sd);
  //*result = syscall_no_intercept(SYS_writev, arg0, arg1, arg2);
  struct iovec* iov = (struct iovec*)arg1;
  *result = 0;
  for(i = 0; i < n; i++){
    size_t iov_len = (size_t)iov[i].iov_len;
    uint8_t *iov_base = (uint8_t*)iov[i].iov_base;
    if(iov_len > 0){
      *result += _tcpls_do_send(iov_base, iov_len);
      log_debug("called tcpls_send on buffer:%x data_sent:%d bytes data_already_sent:%d bytes iovec_count:%d iter_counter:%d",iov_base, iov_len, *result, n, i);
    }
  }
  
  if(*result >= 0){
    log_debug("TCPLS end writev on socket descriptor:%d", sd);
    return SYSCALL_SKIP;
  }
  log_warn("TCPLS writev on %d failed with error: %d", sd, *result);
  return SYSCALL_RUN;
}


static int _handle_write(long arg0, long arg1, long arg2, long *result){
  int sd = (int)arg0;
  uint8_t * buf = (uint8_t*)arg1;
  size_t size = (size_t) arg2;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  log_debug("TCPLS write on %d", sd);
  //*result = syscall_no_intercept(SYS_write, arg0, arg1, arg2);
  *result = _tcpls_do_send(buf, size);
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
    log_debug("connexion closed removed socket descriptor :%d", sd);
    return SYSCALL_SKIP;
  }
  log_debug("connexion closed %d:%d failed\n", sd, *result);
  return SYSCALL_RUN;
}


static int _handle_shutdown(long arg0, long arg1, long *result){
  int sd = (int)arg0;
  struct tcpls_con *con;
  con = _tcpls_lookup(sd);
  if(!con)
    return SYSCALL_RUN;
  log_debug("shuting down %d", sd);
  *result = syscall_no_intercept(SYS_shutdown, arg0, arg1);
  if(*result > 0)
    return SYSCALL_SKIP;
  return SYSCALL_RUN;
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
#if 1
    case SYS_write:
      return _handle_write(arg0, arg1, arg2, result);
#endif
    case SYS_close:
      return _handle_close(arg0, result);
    case SYS_shutdown:
      return _handle_shutdown(arg0, arg1, result);
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
    //log_set_fp(_log);
  }
  log_info("Starting interception");
  intercept_hook_point = _hook;
}

static __attribute__((destructor)) void fini(void){
  log_info("Terminating interception");
  if (_log)
    fclose(_log);
}
