
int _tcpls_init(int is_server);

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
