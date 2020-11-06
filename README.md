# TCPLS libconvert 

Libraries to transform TCP client and TCP server to TCPLS client and TCPLS server. ((https://github.com/pluginized-protocols/picotcpls.git)).
* `libconvert_tcpls`: A library to call TCPLS API functions.
* `libconvert_tcpls_client`: An `LD_PRELOAD` library that turns an existing client, using TCP sockets, into a TCPLS client.
* `libconvert_tcpls_server`: An `LD_PRELOAD` library that turns an existing server, using TCP sockets, into a TCPLS server.

This is work in progress. The `libconvert_tcpls_client` library currently only supports `wget` and The `libconvert_tcpls_server` library currently only supports `apache2`. 

### Requirements

* Requires Linux >= 4.5.


### Build

Fetch the Git submodules:
```
$ cd tcplslibconvert
$ git submodule update --init --recursive --remote
```

The easiest way to build both libraries and run the tests is with the provided Dockerfile (which contains all deps):
```
$ cd tcplslibconvert
$ docker build -t tcplslibconvert .
$ docker run -v $PWD:/lc -it tcplslibconvert
$ cd lc
$ mkdir build && cd build && cmake .. && make
```

Note, to use gdb without trouble on the preload library, you can do :
```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v $PWD:/lc -it tcplslibconvert
```

You need a client and a server so you have to run two docker instances. 

### Usage & dependencies of `libconvert_tcpls_server` and `libconvert_tcpls_client`

#### Runtime dependencies

 * libcapstone -- the disassembly engine used by used under the hood by `lib_syscall_intercept`.

#### Usage

To use the `libconvert_server`  and `libconvert_client` libs:
Run the following command in two different terminal to have two docker instances.
```
$ cd tcplslibconvert 
$ docker run  -v $PWD:/lc -it tcplslibconvert
```
Assuming the server has the address 172.17.0.2 and the client has the address 172.17.0.3

Client side:
```
# cd lc/build
# CONVERT_LOG=./client_converter.log LD_PRELOAD=./libconvert_tcpls_client.so wget http://172.17.0.2
# CONVERT_LOG=./client_converter.log LD_PRELOAD=./libconvert_tcpls_client.so /usr/local/apache2/bin/ab -n 100 -c 10 http://172.17.0.2/
```
Server side: 
```
# cd lc/build
# CONVERT_LOG=./server_converter.log LD_PRELOAD=./libconvert_tcpls_server.so /usr/local/apache2/bin/httpd -X
```

The library supports IPv6 as well.

Currently tested with `curl`, `wget` and `apache2` Ubuntu {19}.

### Contact

* [Emery Kouassi Assogba](mailto:assogba.emery@gmail.com)
* [Florentin Rochet](mailto:florentin.rochet@gmail.com)
* [Olivier Bonaventure](mailto:olivier.bonaventure@uclouvain.be)

### License

This project is licensed under the 3-Clause BSD License - see the
[LICENSE](LICENSE) file for details.
