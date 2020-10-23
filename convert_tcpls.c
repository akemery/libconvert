#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#include <log.h>

#include "picotls.h"
#include "picotcpls.h"
#include "picotls/openssl.h"

#include "convert_util.h"
#include "convert_tcpls.h"

const char * cert = "../assets/server.crt";
const char * cert_key = "../assets/server.key";

static int read_offset = 0;
static int recvfrom_offset = 0;
static size_t header_buff_offset = 0;
static size_t recv_buff_offset = 0;
static size_t tmp_buff_size = 0;

char tcpls_header_buff[RECV_BUFF_SIZE];
char tcpls_recv_buff[RECV_BUFF_SIZE];

static ptls_context_t *ctx;
//static tcpls_t *tcpls;
static struct cli_data cli_data;
static list_t *tcpls_con_l = NULL;
static list_t *ours_addr_list = NULL;

static int handle_mpjoin(int socket, uint8_t *connid, uint8_t *cookie, uint32_t transportid, void *cbdata) ;
static int handle_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) ;
static int handle_stream_event(tcpls_t *tcpls, tcpls_event_t event,
    streamid_t streamid, int transportid, void *cbdata);
static int handle_client_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) ;
static int handle_client_stream_event(tcpls_t *tcpls, tcpls_event_t event, streamid_t streamid,
    int transportid, void *cbdata);
    
static int handle_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) {
  list_t *conntcpls = (list_t*) cbdata;
  struct tcpls_con *con;
  if(!conntcpls){
    return 0;
  }
  switch(event){
    case CONN_OPENED:
      log_debug("connection_event_call_back: CONNECTION OPENED %d", socket);
      for (int i = 0; i < conntcpls->size; i++) {
        con = list_get(conntcpls, i);
        if (con->sd == socket) {
          con->transportid = transportid;
          con->state = CONNECTED;
          break;
        }
      }     
      break;
    case CONN_CLOSED:
      log_debug("connection_event_call_back: CONNECTION CLOSED %d",socket);
      for (int i = 0; i < conntcpls->size; i++) {
        con = list_get(conntcpls, i);
        if (con->sd == socket) {
          list_remove(conntcpls, con);
          break;
        }
      }
      break;
    default:
      break;
  }
  return 0;
}

static int handle_client_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) {
  struct cli_data *data = (struct cli_data*) cbdata;
  switch (event) {
    case CONN_CLOSED:
      log_debug("connection_event_call_back: Received a CONN_CLOSED; removing the socket %d transportid %d", socket, transportid);
      list_remove(data->socklist, &socket); 
      break;
    case CONN_OPENED:
      log_debug("connection_event_call_back: Received a CONN_OPENED; adding the socket descriptor %d transport id %d", socket, transportid);
      list_add(data->socklist, &socket);
      break;
    default: break;
  }
  return 0;
}
    
static int handle_client_stream_event(tcpls_t *tcpls, tcpls_event_t event, streamid_t streamid,
    int transportid, void *cbdata) {
  struct cli_data *data = (struct cli_data*) cbdata;
  switch (event) {
    case STREAM_OPENED:
      log_debug("stream_event_call_back: Handling stream_opened callback transportid :%d:%p", transportid, tcpls);
      list_add(data->streamlist, &streamid);
      break;
    case STREAM_CLOSED:
      log_debug("stream_event_call_back: Handling stream_closed callback %d:%p", transportid, tcpls);
      list_remove(data->streamlist, &streamid);
      break;
    default: break;
  }
  return 0;
}

static int handle_stream_event(tcpls_t *tcpls, tcpls_event_t event,
  streamid_t streamid, int transportid, void *cbdata) {
  list_t *conntcpls = (list_t*) cbdata;
  struct tcpls_con *con;
  assert(conntcpls);
  switch(event){
    case STREAM_OPENED:
      log_debug("stream_event_call_back: STREAM OPENED streamid :%d transportid :%d", streamid, transportid);
      for (int i = 0; i < conntcpls->size; i++) {
        con = list_get(conntcpls, i);
        if (con->tcpls == tcpls && con->transportid == transportid) {
          con->streamid = streamid;
          con->is_primary = 1;
          con->wants_to_write = 1;
        }
      }
      break;
    case STREAM_CLOSED:
      log_debug("stream_event_call_back: STREAM CLOSED streamid :%d transportid :%d", streamid, transportid);
      for (int i = 0; i < conntcpls->size; i++) {
        con = list_get(conntcpls, i);
        if ( con->tcpls == tcpls && con->transportid == transportid) {
          log_debug("We're stopping to write on the connection linked to transportid %d %d\n", transportid, con->sd);
          con->is_primary = 0;
          con->wants_to_write = 0;
        }
      }
      break;
    default:
      break;
  }
  return 0;
}

static int load_private_key(ptls_context_t *ctx, const char *fn){
  static ptls_openssl_sign_certificate_t sc;
  FILE *fp;
  EVP_PKEY *pkey;
  if ((fp = fopen(fn, "rb")) == NULL) {
    log_debug("failed to open file:%s:%s\n", fn, strerror(errno));
    return(-1);
  }
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  if (pkey == NULL) {
    log_debug("failed to read private key from file:%s\n", fn);
    return(-1);
  }
  ptls_openssl_init_sign_certificate(&sc, pkey);
  EVP_PKEY_free(pkey);
  ctx->sign_certificate = &sc.super;
  return(0);
}

static ptls_context_t *set_tcpls_ctx_options(int is_server){
  if(ctx)
    goto done;
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  ctx = (ptls_context_t *)malloc(sizeof(*ctx));
  memset(ctx, 0, sizeof(ptls_context_t));  
  ctx->support_tcpls_options = 1;
  ctx->random_bytes = ptls_openssl_random_bytes;
  ctx->key_exchanges = ptls_openssl_key_exchanges;
  ctx->cipher_suites = ptls_openssl_cipher_suites;
  ctx->get_time = &ptls_get_time;
  if(!tcpls_con_l)
    tcpls_con_l = new_list(sizeof(struct tcpls_con),2);
  if(!ours_addr_list)
    ours_addr_list = new_list(sizeof(struct sockaddr), 2);
  if(!is_server){
    ctx->send_change_cipher_spec = 1;
    list_t *socklist = new_list(sizeof(int), 2);
    list_t *streamlist = new_list(sizeof(tcpls_stream_t), 2);
    cli_data.socklist = socklist;
    cli_data.streamlist = streamlist;
    ctx->cb_data = &cli_data;
    ctx->stream_event_cb = &handle_client_stream_event;
    ctx->connection_event_cb = &handle_client_connection_event;
  }else{
    ctx->stream_event_cb = &handle_stream_event;  
    ctx->connection_event_cb = &handle_connection_event;
    ctx->cb_data = tcpls_con_l;
    if (ptls_load_certificates(ctx, (char *)cert) != 0)
      log_debug("failed to load certificate:%s:%s\n", cert, strerror(errno));
    if(load_private_key(ctx, (char*)cert_key)!=0)
      log_debug("failed apply ket :%s:%s\n", cert_key, strerror(errno));  
  }
done:
  return ctx;
}


static int handle_mpjoin(int socket, uint8_t *connid, uint8_t *cookie, uint32_t transportid, void *cbdata) {
  int i, j;
  log_debug("\n\n\nstart mpjoin haha %d %d %d %d %p\n", socket, *connid, *cookie, transportid, cbdata);
  list_t *conntcpls = (list_t*) cbdata;
  struct tcpls_con *con, *con2;
  assert(conntcpls);
  for(i = 0; i<conntcpls->size; i++){
    con = list_get(conntcpls, i);
    if(!memcmp(con->tcpls->connid, connid, CONNID)){
      log_debug("start mpjoin found %d:%p:%d\n", *con->tcpls->connid, con->tcpls, con->sd);
      for(j = 0; j < conntcpls->size; j++){
        con2 = list_get(conntcpls, j);
        log_debug("start mpjoin 1 found %d:%p:%d\n", *con->tcpls->connid, con2->tcpls, con2->sd);
        if(con2->sd == socket){
          con2->tcpls = con->tcpls;
          if(memcmp(con2->tcpls, con->tcpls, sizeof(tcpls_t)))
            log_debug("ils sont bien diff2rents\n");
        }
        log_debug("start mpjoin 2 found %d:%p:%d\n", *con->tcpls->connid, con2->tcpls, con2->sd); 
      }
      return tcpls_accept(con->tcpls, socket, cookie, transportid);
    }
  }
  return -1;
}

static int tcpls_do_handshake(int sd, tcpls_t * tcpls){
  int resultat = -1;
  ptls_handshake_properties_t prop = {NULL};
  memset(&prop, 0, sizeof(prop));
  prop.socket = sd;
  prop.received_mpjoin_to_process = &handle_mpjoin;
  if ((resultat = tcpls_handshake(tcpls->tls, &prop)) != 0) {
    if (resultat == PTLS_ERROR_HANDSHAKE_IS_MPJOIN) 
      return resultat;
    log_warn("tcpls_handshake failed with ret (%d)\n", resultat);
  }
  return resultat;
}

int _tcpls_init(int is_server){
  const char *host = is_server ? "SERVER" : "CLIENT";
  log_debug("Init new tcpls context for %s", host);
  set_tcpls_ctx_options(is_server);
  /*if(!is_server){
    tcpls = tcpls_new(ctx, is_server);
    if(!tcpls)
      return -1;
  }*/
  if(!tcpls_con_l)
    return -1;
  return 0;
}

struct tcpls_con * _tcpls_alloc_con_info(int sd, int is_server, int af_family){
  struct tcpls_con *con = (struct tcpls_con *)malloc(sizeof(struct tcpls_con));
  log_debug("1 adding new socket descriptor :%d",sd);
  if(!con)
    return con;
  con->sd = sd;
  con->state = CLOSED;
  con->af_family = af_family;
  con->tcpls = tcpls_new(ctx, is_server);
  list_add(tcpls_con_l, con); 
  log_debug("adding new socket descriptor :%d",sd);
  return con;
}

struct tcpls_con *_tcpls_lookup(int sd){
  int i;
  struct tcpls_con * con;
  if(!tcpls_con_l || !tcpls_con_l->size)
    return NULL;
  for(i = 0; i < tcpls_con_l->size; i++){
    con = list_get(tcpls_con_l, i);
    if(con->sd == sd){
      return con;
    }
  }
  return NULL;
}

int _tcpls_free_con(int sd){
  int i;
  struct tcpls_con * con;
  if(!tcpls_con_l || !tcpls_con_l->size)
    return -1;
  for(i=0; i < tcpls_con_l->size; i++){
    con = list_get(tcpls_con_l, i);
    if(con->sd == sd){
      //tcpls_free(con->tcpls);
      list_remove(tcpls_con_l, con);
      //free(con);
      return 0;
    }
  }
  return -1;
}

int _handle_tcpls_connect(int sd, struct sockaddr * dest, tcpls_t * tcpls){
  int result = -1;
  struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
  if(dest->sa_family == AF_INET){
    result = tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)dest, 1, 0, 0);
    if(result && result!=TCPLS_ADDR_EXIST){
      return result;
    }
  }
  if(dest->sa_family == AF_INET6){
    result = tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)dest, 1, 0, 0);
    if(result && result!=TCPLS_ADDR_EXIST){
      return result;
    }
  }
  result = tcpls_connect(tcpls->tls, NULL, dest, &timeout, sd);
  return result;
}

int _tcpls_do_tcpls_accept(int sd, struct sockaddr *addr){
  int result = -1;
  struct tcpls_con * con;
  struct sockaddr our_addr;
  socklen_t salen = sizeof(struct sockaddr);
  con = _tcpls_alloc_con_info(sd, 1, addr->sa_family);
  if(!con){
    log_warn("failed to alloc con %d", sd);
    return result;
  }
  /*con->tcpls = tcpls_new(ctx, 1);
  if(!con->tcpls)
    return -1;*/
  if(addr->sa_family == AF_INET){
    result = tcpls_add_v4(con->tcpls->tls, (struct sockaddr_in*)addr, 1, 0, 0);
    if(result)
      return result;
  }
  if(addr->sa_family == AF_INET6){
    result = tcpls_add_v6(con->tcpls->tls, (struct sockaddr_in6*)addr, 1, 0, 0);
    if(result)
      return result;
  }
  if (syscall_no_intercept(SYS_getsockname, sd, (struct sockaddr *) &our_addr, &salen) < 0) {
    log_debug("getsockname(2) failed %d:%d", errno, sd);
  }
  if(our_addr.sa_family == AF_INET){
    result = tcpls_add_v4(con->tcpls->tls, (struct sockaddr_in*)&our_addr, 0, 1, 1);
    if(result)
      return result;
  }
  if(our_addr.sa_family == AF_INET6){
    result = tcpls_add_v6(con->tcpls->tls, (struct sockaddr_in6*)&our_addr, 0, 1, 1);
    if(result)
      return result;
  }
  result = tcpls_accept(con->tcpls, sd, NULL, 0);
  if(result < 0)
    log_debug("TCPLS tcpls_accept failed %d\n", result);
  return result;
}

int _tcpls_set_ours_addr(struct sockaddr *addr){
  if(!ours_addr_list)
    return -1;
  list_add(ours_addr_list, addr);
  return ours_addr_list->size;
}

int _tcpls_handshake(int sd, tcpls_t *tcpls){
  if(ptls_handshake_is_complete(tcpls->tls)){
    return 0;
  }
  return  tcpls_do_handshake(sd, tcpls); 
}

static size_t _tcpls_do_recv(int sd, uint8_t *buf, size_t size, tcpls_t *tcpls){
  size_t n = 0;
  int ret = 0;
  struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
  ptls_buffer_t tcpls_buf;
  ptls_buffer_init(&tcpls_buf, "", 0);
  if(tmp_buff_size){
    if(tmp_buff_size <= size){
      memcpy(buf, tcpls_recv_buff + recv_buff_offset, tmp_buff_size);
      n = tmp_buff_size;
      tmp_buff_size = 0;
      recv_buff_offset = 0;
      log_debug("received mores data (%d bytes) than expected (%d bytes) we sent %d bytes, it remains %d bytes", tmp_buff_size + n, size, n,  tmp_buff_size);
    }
    else{
      memcpy(buf, tcpls_recv_buff + recv_buff_offset, size);
      n = size;
      tmp_buff_size -= size;
      recv_buff_offset += size;
      log_debug("received mores data (%d bytes) than expected (%d bytes) we sent %d bytes, it remains %d bytes", tmp_buff_size + n, size, n,  tmp_buff_size);
    }
  }
  else{
    do{
      //while((ret = tcpls_receive(tcpls->tls, &tcpls_buf, 26276, &timeout))==TCPLS_HOLD_DATA_TO_READ)
        // ;
      ret = tcpls_receive(tcpls->tls, &tcpls_buf, size, &timeout);
      memset(buf,0,size);
      n = tcpls_buf.off;
    } while(!n && !ret);
    if(n>0){
      if(n <= size){
        memcpy(buf, tcpls_buf.base+4, n-4);
        n = n - 8;
        tmp_buff_size = 0;
      }else{
        log_debug("4: do_recv high than expected %d:%d:%d::", n, sd, size);
        recv_buff_offset = 0;
        memcpy(tcpls_recv_buff, tcpls_buf.base+4, n-4);
        tmp_buff_size = n - 8;
        memcpy(buf, tcpls_recv_buff + recv_buff_offset, size);
        recv_buff_offset +=size;
        tmp_buff_size -= size;
        n = size;
      }
    }
    else{
      log_debug("TCPLS tcpls_receive return error %d code on socket descriptor %d", ret, sd);
      n = ret;
    }
  }
  ptls_buffer_dispose(&tcpls_buf);
  return n;
}

size_t _tcpls_do_recvfrom(int sd, uint8_t *buf, size_t size, int is_client, tcpls_t *tcpls){
  int n;
  if(header_buff_offset && is_client && (size == header_buff_offset)){
    log_debug("tcpls_do_rcvfrom : copy %d bytes from recv buffer to application that expect %d bytes", header_buff_offset, size);
    memcpy(buf, tcpls_header_buff, header_buff_offset);
    n = header_buff_offset;
    header_buff_offset = 0;
  } else{
    n = _tcpls_do_recv(sd, buf, size, tcpls);
    if(n > 0){
      recvfrom_offset += n;
      //for(int i = 0; i < n; i++)
        //log_debug(" %x",*(buf+i));
      memcpy(tcpls_header_buff+header_buff_offset, buf, n);
      header_buff_offset+=n;
    }
    else{
      log_debug("Recvfrom --> recv_offset:read_offset:recvfrom_offset %d:%d:%d", header_buff_offset, read_offset, recvfrom_offset);
    }
  }
  return n;
}

size_t _tcpls_do_read(int sd, uint8_t *buf, size_t size, int is_client, tcpls_t *tcpls){
  int n;
  if(header_buff_offset && is_client && (size == header_buff_offset)){
    log_debug("tcpls_do_read : copy %d bytes from recv buffer to application that expect %d bytes", header_buff_offset, size);
    memcpy(buf, tcpls_header_buff, header_buff_offset);
    n = header_buff_offset;
    header_buff_offset = 0;
  }
  else{
    n = _tcpls_do_recv(sd, buf, size, tcpls);
    if(header_buff_offset)
      header_buff_offset = 0;
    if(n > 0){
      read_offset += n;
      //for(int i = 0; i < n; i++)
        //log_debug("read %x",*(buf+i));
    }
    else{
      log_debug("TCPLS tcpls_do_read return error code %d on socket descriptor %d", n, sd);
    }
  }
  return n;
}


size_t _tcpls_do_send(uint8_t *buf, size_t size, tcpls_t *tcpls){
  size_t n;
  int streamid;
  if(!size)
    return size;
  if(tcpls->streams->size == 0)
    streamid = 0;
  else if((tcpls->streams->size == 1) && (tcpls->next_stream_id == 2147483649))
    streamid = tcpls->streams->size;
    else
       streamid = 2147483649;
  n = tcpls_send(tcpls->tls, streamid, buf, size);
  //for(int i = 0; i < (int) n; i++)
    //log_debug("%x",*(buf+i));
  return n;
}
