#!/bin/bash

#
# Copyright 2013-2018 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.
#

set -e

deb_dir=packaging/deb

#Temporary directories for deb package build.
tmp_dir_lib=$deb_dir/tmp_lib
tmp_dir_devel=$deb_dir/tmp_devel
tmp_dir_src=$deb_dir/tmp_src

#Destination dirs used for installion.
lib_install_dir=usr/local/lib
inc_install_dir=usr/local/include/legacy
doc_install_dir=usr/share/doc/legacy
src_install_dir=usr/local/src

#Source directories for files.
include_dir=src/lib
lib_dir=src/lib/.libs


#File list for liblegacy installion
liblegacy_libs="$lib_dir/liblegacy.so \
		$lib_dir/liblegacy.so.*"

liblegacy_doc="changelog \
		license.txt"


#File list for liblegacy-devel installion
liblegacy_devel_includes="\
		$include_dir/parseasn1.h\
		$include_dir/tsconvert.h\
		$include_dir/version.h"

liblegacy_devel_libs="\
		$lib_dir/liblegacy.a \
		$lib_dir/liblegacy.la \
		liblegacy.pc"



#Rebuild API
./rebuild.sh
make dist



#Create directory structure
mkdir -p $tmp_dir_lib
mkdir -p $tmp_dir_lib/liblegacy/$lib_install_dir/pkgconfig
mkdir -p $tmp_dir_lib/liblegacy/$inc_install_dir
mkdir -p $tmp_dir_lib/liblegacy/$doc_install_dir

mkdir -p $tmp_dir_devel
mkdir -p $tmp_dir_devel/liblegacy-devel/$lib_install_dir/pkgconfig
mkdir -p $tmp_dir_devel/liblegacy-devel/$inc_install_dir
mkdir -p $tmp_dir_devel/liblegacy-devel/$doc_install_dir

mkdir -p $tmp_dir_src

mkdir -p $tmp_dir_lib/liblegacy/DEBIAN
mkdir -p $tmp_dir_devel/liblegacy-devel/DEBIAN
mkdir -p $tmp_dir_src/liblegacy/debian


#Get version number
VER=$(tr -d [:space:] < VERSION)
ARCH=$(dpkg --print-architecture)


#Copy files
cp  $deb_dir/liblegacy/DEBIAN/control $tmp_dir_lib/liblegacy/DEBIAN/control
cp  $deb_dir/liblegacy/DEBIAN/control-devel $tmp_dir_devel/liblegacy-devel/DEBIAN/control
cp  $deb_dir/liblegacy/DEBIAN/control-source $tmp_dir_src/liblegacy/debian/control
cp  $deb_dir/liblegacy/DEBIAN/changelog $tmp_dir_src/liblegacy/debian/


sed -i s/@VER@/$VER/g "$tmp_dir_lib/liblegacy/DEBIAN/control"
sed -i s/@ARCH@/$ARCH/g "$tmp_dir_lib/liblegacy/DEBIAN/control"

sed -i s/@VER@/$VER/g $tmp_dir_devel/liblegacy-devel/DEBIAN/control
sed -i s/@ARCH@/$ARCH/g $tmp_dir_devel/liblegacy-devel/DEBIAN/control

sed -i s/@ARCH@/$ARCH/g "$tmp_dir_src/liblegacy/debian/control"
sed -i s/@VER@/$VER/g "$tmp_dir_src/liblegacy/debian/control"

#copy data

cp -f $liblegacy_libs $tmp_dir_lib/liblegacy/$lib_install_dir/
cp -f $liblegacy_doc $tmp_dir_lib/liblegacy/$doc_install_dir/

cp -f $liblegacy_devel_includes $tmp_dir_devel/liblegacy-devel/$inc_install_dir/
cp -f $liblegacy_devel_libs $tmp_dir_devel/liblegacy-devel/$lib_install_dir/

#cp -f liblegacy-${VER}.tar.gz $tmp_dir_src/liblegacy_${VER}.orig.tar.gz
tar -xvzf liblegacy-${VER}.tar.gz -C $tmp_dir_src/
cp -r $tmp_dir_src/liblegacy/debian $tmp_dir_src/liblegacy-${VER}


#Build packages
dpkg-deb --build $tmp_dir_lib/liblegacy
mv $tmp_dir_lib/liblegacy.deb liblegacy_${VER}_${ARCH}.deb

dpkg-deb --build $tmp_dir_devel/liblegacy-devel
mv $tmp_dir_devel/liblegacy-devel.deb liblegacy-devel_${VER}_${ARCH}.deb

dpkg-source -b -sn $tmp_dir_src/liblegacy-${VER} ""


#Cleanup
rm -rf $deb_dir/liblegacy/usr

rm -rf $tmp_dir_lib
rm -rf $tmp_dir_devel
rm -rf $tmp_dir_src
rm liblegacy-${VER}.tar.gz
