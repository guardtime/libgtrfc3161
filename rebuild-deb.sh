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


# Get version number.
VER=$(tr -d [:space:] < VERSION)
ARCH=$(dpkg --print-architecture)
RELEASE_VERSION="$(lsb_release -is)$(lsb_release -rs | grep -Po "[0-9]{1,3}" | head -1)"
PKG_VERSION=1
DEB_DIR=packaging/deb

autoreconf -if
./configure $conf_args
make clean
make dist


# Rebuild debian changelog.
if command  -v dch > /dev/null; then
  echo "Generating debian changelog..."
  $DEB_DIR/rebuild_changelog.sh changelog $DEB_DIR/control libgtrfc3161 $DEB_DIR/changelog "1.0:unstable"
else
  >&2 echo "Error: Unable to generate Debian changelog file as dch is not installed!"
  >&2 echo "Install devscripts 'apt-get install devscripts'"
  exit 1
fi

tar xvfz libgtrfc3161-$VER.tar.gz
mv libgtrfc3161-$VER.tar.gz libgtrfc3161-$VER.orig.tar.gz
mkdir libgtrfc3161-$VER/debian
cp $DEB_DIR/control $DEB_DIR/changelog $DEB_DIR/rules $DEB_DIR/copyright libgtrfc3161-$VER/debian
chmod +x libgtrfc3161-$VER/debian/rules
cd libgtrfc3161-$VER
debuild -us -uc
cd ..

suffix=${VER}-${PKG_VERSION}.${RELEASE_VERSION}_${ARCH}
mv libgtrfc3161_${VER}_${ARCH}.changes libgtrfc3161_$suffix.changes
mv libgtrfc3161_${VER}_${ARCH}.deb libgtrfc3161_$suffix.deb
mv libgtrfc3161-dev_${VER}_${ARCH}.deb libgtrfc3161-dev_$suffix.deb

rm -rf libgtrfc3161-$VER

