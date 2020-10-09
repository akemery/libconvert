# TCPLS libconvert 

Libraries to transform TCP client and TCP server to TCPLS client and TCPLS server. ((https://github.com/pluginized-protocols/picotcpls.git)).
* `libconvert_tcpls`: A library to call TCPLS API functions.
* `libconvert_tcpls_client`: An `LD_PRELOAD` library that turns an existing client, using TCP sockets, into a TCPLS client.
* `libconvert_tcpls_server`: An `LD_PRELOAD` library that turns an existing server, using TCP sockets, into a TCPLS server.

This is work in progress. The `libconvert_tcpls_client` library currently only supports `wget` and The `libconvert_tcpls_server` library currently only supports `apache2`. 

### Requirements

* Requires Linux >= 4.5 (leverages the TCP Fast Open infrastructure).
* Configure `$ sysctl -w net.ipv4.tcp_fastopen=5` to enable sending data in the opening SYN, regardless of cookie availability.

### Build

Fetch the Git submodules:
```
$ git submodule init && git submodule update
```

The easiest way to build both libraries and run the tests is with the provided Dockerfile (which contains all deps):
```
$ docker build -t tessares.net/libconvert .
$ docker run --cap-add=NET_ADMIN --sysctl net.ipv4.tcp_fastopen=5 -v $PWD:/lc -t tessares.net/libconvert /bin/bash -c "mkdir -p /lc/build && cd /lc/build && cmake .. && make && make test"
```

Otherwise, assuming all deps are installed, build and run the tests with CMake as follows:
```
$ mkdir -p build && cd build && cmake .. && make && make test
```

### Usage & dependencies of `libconvert_client`

#### Runtime dependencies

 * libcapstone -- the disassembly engine used by used under the hood by `lib_syscall_intercept`.

#### Usage

To use the `libconvert_client` lib (assuming a Transport Converter listening at 192.0.2.1:1234):
```
$ CONVERT_LOG=/tmp/converter.log CONVERT_ADDR=192.0.2.1 CONVERT_PORT=1234 LD_LIBRARY_PATH=$PWD/build LD_PRELOAD=libconvert_client.so curl https://www.tessares.net
```

The library supports IPv6 as well.

Currently tested with `curl` & `wget` on both Centos 7 and Ubuntu {16,18,19}.

The library is known to *not* work on Ubuntu 20 due to incompatibilities between `lib_syscall_intercept` and `libc 20.30-1`. This issue is tracked [here](https://github.com/pmem/syscall_intercept/issues/97).

### Contributing

Code contributions are more than welcome.

Upon change, please run `uncrustify` (0.68) and validate that `cppcheck` is still happy:
```
$ uncrustify -c uncrustify.cfg -l C --replace --no-backup convert*.{h,c}
$ cppcheck -I/usr/include -q --language=c --std=c99 --enable=warning,style,performance,portability -j "$(nproc)" --suppress=unusedStructMember ./convert*.{h,c}
```

To ease troubleshooting, download the 0-RTT TCP Convert [Wireshark dissector plugin](https://github.com/Tessares/convert-wireshark-dissector).

### Contact

* [Gregory Vander Schueren](mailto:gregory.vanderschueren@tessares.net)
* [Gregory Detal](mailto:gregory.detal@tessares.net)
* [Olivier Bonaventure](mailto:olivier.bonaventure@tessares.net)

### License

This project is licensed under the 3-Clause BSD License - see the
[LICENSE](LICENSE) file for details.
