#!/bin/bash
FILES="libssl1.1_1.1.1h-1_amd64.deb libssl-dev_1.1.1h-1_amd64.deb pcre-8.44.tar.bz2 expat-2.2.9.tar.bz2 apr-1.7.0.tar.gz apr-util-1.6.1.tar.gz httpd-2.4.46.tar.gz libcbor0_0.5.0+dfsg-2_amd64.deb libfido2-1_1.5.0-2_amd64.deb openssh-client_8.3p1-1_amd64.deb openssh-sftp-server_8.3p1-1_amd64.deb ucf_3.0043_all.deb runit-helper_2.9.0_all.deb openssh-server_8.3p1-1_amd64.deb"
declare -a URL
URL=('http://ftp.de.debian.org/debian/pool/main/o/openssl/' 'http://ftp.de.debian.org/debian/pool/main/o/openssl/' 'https://ftp.pcre.org/pub/pcre/' 'https://github.com/libexpat/libexpat/releases/download/R_2_2_9/' 'https://downloads.apache.org//apr/' 'https://downloads.apache.org//apr/' 'https://downloads.apache.org//httpd/' 'http://ftp.de.debian.org/debian/pool/main/libc/libcbor/' 'http://ftp.de.debian.org/debian/pool/main/libf/libfido2/' 'http://ftp.de.debian.org/debian/pool/main/o/openssh/' 'http://ftp.de.debian.org/debian/pool/main/o/openssh/' 'http://ftp.de.debian.org/debian/pool/main/u/ucf/' 'http://ftp.de.debian.org/debian/pool/main/d/dh-runit/' 'http://ftp.de.debian.org/debian/pool/main/o/openssh/')
url_counter=0
for file in $FILES; do
if [ -f $file ];
  then 
    echo "$file exists";
  else 
    wget ${URL[$url_counter]}$file;
    if [ $? -eq 0 ];
      then 
        echo "$file is downloaded";
      else
        rm $file;
        echo "download of $file failed";
        exit;
    fi
fi
url_counter=$((url_counter + 1))
done

dpkg -i libssl1.1_1.1.1h-1_amd64.deb
dpkg -i libssl-dev_1.1.1h-1_amd64.deb

dpkg -i libcbor0_0.5.0+dfsg-2_amd64.deb 
dpkg -i libfido2-1_1.5.0-2_amd64.deb
dpkg -i openssh-client_8.3p1-1_amd64.deb

dpkg -i openssh-sftp-server_8.3p1-1_amd64.deb
dpkg -i ucf_3.0043_all.deb
dpkg -i runit-helper_2.9.0_all.deb 
dpkg -i openssh-server_8.3p1-1_amd64.deb

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
