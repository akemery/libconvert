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
$ git submodule init && git submodule update
$ cd lib/picotcpls
$ git pull https://github.com/frochet/picotcpls.git tcpls/ldpreload
$ git submodule init && git submodule update
```

###  Softwares

* Download the following softwares needed to install wget, apache2 and libssl-dev on the provided Dockerfile
  you can download them directly to the tcplslibconvert directory from the following repositories:
* `libssl1.1_1.1.1g-1_amd64.deb` from https://packages.debian.org/sid/amd64/libssl1.1/download
* `libssl-dev_1.1.1g-1_amd64.deb` from https://packages.debian.org/sid/amd64/libssl-dev/download
* `pcre-8.44.tar.bz2` from https://www.pcre.org/
* `expat-2.2.9.tar.bz2` from https://libexpat.github.io/
* `apr-util-1.6.1.tar.gz` from https://apr.apache.org/download.cgi
* `apr-1.7.0.tar.gz` from https://apr.apache.org/download.cgi
* `httpd-2.4.46.tar` from https://httpd.apache.org/download.cgi



The easiest way to build both libraries and run the tests is with the provided Dockerfile (which contains all deps):
```
$ cd tcplslibconvert
$ sudo docker build -t uac.bj/libconvert .
$ sudo docker run  -v $PWD:/lc -it uac.bj/libconvert
$ cd lc
$ bash install_lib.sh
$ mkdir build && cd build && cmake .. && make
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
$ sudo docker run  -v $PWD:/lc -it uac.bj/libconvert
```
Assuming the server has the address 172.17.0.2 and the client has the address 172.17.0.3

Client side:
```
# cd lc/build
# CONVERT_LOG=./client_converter.log   LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_client.so wget http://172.17.0.2
```
Server side: 
```
# cd lc/build
# CONVERT_LOG=./converter.log   LD_LIBRARY_PATH=. LD_PRELOAD=libconvert_tcpls_server.so /usr/local/apache2/bin/apachectl -k start 
```

The library supports IPv6 as well.

Currently tested with `wget` and `apache2` Ubuntu {19}.

The library is known to *not* work on Ubuntu 20 due to incompatibilities between `lib_syscall_intercept` and `libc 20.30-1`. This issue is tracked [here](https://github.com/pmem/syscall_intercept/issues/97).



### Contact

* [Emery Kouassi Assogba](mailto:assogba.emery@gmail.com)
* [Florentin Rochet](mailto:florentin.rochet@gmail.com)
* [Olivier Bonaventure](mailto:olivier.bonaventure@uclouvain.be)

### License

This project is licensed under the 3-Clause BSD License - see the
[LICENSE](LICENSE) file for details.
