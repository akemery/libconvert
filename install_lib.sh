#!/bin/bash
dpkg -i libssl1.1_1.1.1h-1_amd64.deb
dpkg -i libssl-dev_1.1.1h-1_amd64.deb
#dpkg -i net-tools_1.60+git20161116.90da8a0-1_amd64.deb
#dpkg -i libnettle4_2.7.1-5+deb8u2_amd64.deb
#dpkg -i libhogweed2_2.7.1-5+deb8u2_amd64.deb
#dpkg -i libgnutls-deb0-28_3.3.30-0+deb8u1_amd64.deb
#dpkg -i libgnutls-openssl27_3.3.30-0+deb8u1_amd64.deb
#dpkg -i iputils-ping_20121221-5+b2_amd64.deb
tar  -xf pcre-8.44.tar.bz2
cd pcre-8.44
./configure
make
make install
cd /lc

tar  -xf expat-2.2.9.tar.bz2
cd expat-2.2.9
./configure --prefix=/usr/local/bin/
make
make install
cd /lc
tar xvf  apr-util-1.6.1.tar.gz
tar xvf  apr-1.7.0.tar.gz
tar xvf httpd-2.4.46.tar.gz
mkdir -p httpd-2.4.46/srclib/apr-util/
mkdir -p httpd-2.4.46/srclib/apr/
cp -r apr-util-1.6.1/* httpd-2.4.46/srclib/apr-util/
cp -r apr-1.7.0/* httpd-2.4.46/srclib/apr/

cd httpd-2.4.46
./configure --with-pcre=/usr/local/bin/pcre-config --with-expat=/usr/local/bin/
make
make install
ldconfig
