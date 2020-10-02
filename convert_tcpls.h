int _tcpls_init(int is_server);
int _tcpls_alloc_con_info(int sd);
struct tcpls_con *_tcpls_lookup(int sd);
int _tcpls_free_con(int sd);
int _tcpls_set_ours_addr(struct sockaddr *addr);
int _handle_tcpls_connect(int sd, struct sockaddr * dest);
int _tcpls_do_tcpls_accept(int sd, struct sockaddr *addr);
int _tcpls_handshake(int sd);
size_t _tcpls_do_recv(uint8_t *buf, size_t size);
size_t _tcpls_do_send(char *buf, size_t size);

struct cli_data {
  list_t *socklist;
  list_t *streamlist;
};

struct tcpls_con {
  int sd;
  int transportid;
  int state;
  unsigned int is_primary : 1;
  streamid_t streamid;
  unsigned int wants_to_write : 1;
  tcpls_t *tcpls;
};

enum {
  SYSCALL_SKIP	= 0,
  SYSCALL_RUN	= 1,
};
