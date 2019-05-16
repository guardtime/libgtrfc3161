#!/bin/sh

#
# Copyright 2013-2019 Guardtime, Inc.
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

set -e

help_txt() {
	echo "Usage:"
	echo "  $0 [-s] [-d|-r] [Options]"
	echo "  $0 --get-dep-online [-d|-r --no-dep-check] [Options]"
	echo "  $0 -l path -i path [-d|-r --no-dep-check] [Options]"
	echo ""

	echo "Description:"
	echo "  This is libgtrfc3161 general build script. It can be used to build"
	echo "  libgtrfc3161 (packages rpm or deb) with libksi dynamically. See"
	echo "  sections 'Examples' and 'Problems that can be resolved with this"
	echo "  script' to see why and how this script is used."
	echo ""
	echo ""

	echo "Options:"
	echo "  --build-rpm | -r"
	echo "       - Build RPM package."
	echo ""
	echo "  --build-deb | -d"
	echo "       - Build Deb package."
	echo ""
	echo "  --lib-dir | -l"
	echo "       - Path to directory containing library objects. Can have multiple"
	echo "         values. Note that full path is required!"
	echo ""
	echo "  --inc-dir | -i"
	echo "       - Path to directory containing include directories. Can have."
	echo "         multiple values. Note that full path is required!"
	echo ""
	echo "  --configure-flags | -c"
	echo "       - Extra flags for configure script. Note that -s will already add"
	echo "         something to configure options."
	echo ""
	echo "  --make-flags | -m"
	echo "       - Extra flags for make file."
	echo ""
	echo "  --linker-flags | -L"
	echo "       - Extra flags that are set to temporary environment variable LDFLAGS."
	echo "         Note that -l and --get-dep-online will affect that."
	echo ""
	echo "  --compiler-flags | -C"
	echo "       - Extra flags that are set to temporary environment variable CPPFLAGS."
	echo "         Note that -i and --get-dep-online will affect that."
	echo ""
	echo "  --get-dep-online"
	echo "       - When this flag is set, libksi is downloaded from github and built."
	echo "         Result is dumped in directory 'dependencies' that will contain"
	echo "         'include' and 'lib' directory. Libraries built should be available"
	echo "          automatically. If not, see -l and -i."
	echo ""
	echo "  --no-dep-check"
	echo "       - No dependency check is performed when building rpm or deb package. Note"
	echo "         that it doesn't remove required dependencies from constructed packages!"
	echo "         It is useful when building packages with dependencies that are not"
	echo "         installed by package manager."
	echo ""
	echo "  --ign-dep-online-err"
	echo "       - This option can be combined with --get-dep-online to ignore failing"
	echo "         tests of the dependencies built. Note that actually it ignores the exit"
	echo "         code of the rebuild script and continues in case of error. Make sure"
	echo "         that You really know what You are doing when using this option!"
	echo ""
	echo "  -v"
	echo "       - Verbose output."
	echo ""
	echo "  --help | -h"
	echo "       - You are reading it right now."
	echo ""
	echo ""

	echo "Problems that can be resolved with this script:"
	echo "  1) When all required dependencies are installed, just run ./rebuild.sh."
	echo "  2) When there are wrong dependencies installed or it is prohibited to install"
	echo "     extra packages, specify include and library paths for libksi with -i and"
	echo "     -l. If there are no library and include files present, consider using"
	echo "     --get-dep-online. See example 1."
	echo "  3) When packaging is performed in 'sterile' environment and it is prohibited"
	echo "     to install any packages, use advice given in point 2 with --no-dep-check."
	echo "     This option skips checking if libksi packages is installed"
	echo "     during the build. Constructed packages are correct and dependency check is"
	echo "     performed during the install. See example 2."
	echo ""
	echo ""

	echo "Examples:"
	echo ""
	echo "  1) Link libgtrfc3161 with libksi (e.g. cloned from github), from not default"
	echo "  location. Useful when libksi is not installed or installed version does not"
	echo "  match."
	echo ""
	echo "    ./rebuild.sh -i /usr/tmp/libksi/src/ -l /usr/tmp/libksi/src/ksi/.libs/"
	echo ""
	echo "  2) Build libgtrfc3161 rpm packages with libksi from github."
	echo ""
	echo "    ./rebuild.sh --get-dep-online --no-dep-check --build-rpm"
	echo ""
	echo ""

}

conf_args=""
make_args=""
include_dir=""
lib_dir=""
lib_path=""
extra_linker_flags=""
extra_compiler_flags=""
rpmbuild_flags=""
debuild_flags=""

is_inc_dir_set=false
is_lib_dir_set=false
is_extra_l_or_c_flags=false
is_verbose=false
do_build_rpm=false
do_build_deb=false
do_build_dependecies=false
show_help=false
rebuild_lib_dependencies_flags=""

# Simple command-line parameter parser.
while [ "$1" != "" ]; do
	case $1 in
		--build-rpm | -r )		 echo "Building rpm."
								 do_build_rpm=true
								 ;;
		--build-deb | -d )		 echo "Building deb."
								 do_build_deb=true
								 ;;
		--lib-dir | -l )	 	 shift
								 echo "Library search path added: '$1'."
								 lib_dir="$lib_dir -L$1"
								 lib_path="$lib_path $1:"
								 is_lib_dir_set=true
								 ;;
		--inc-dir | -i )	 	 shift
								 echo "Include file path added: '$1'."
								 include_dir="$include_dir -I$1"
								 is_inc_dir_set=true
								 ;;
		--configure-flags | -c ) shift
								 echo "Using extra configure flags '$1'."
								 conf_args="$conf_args $1"
								 ;;
		--make-flags | -m )		 shift
								 echo "Using extra make flags '$1'."
								 make_args="$make_args $1"
								 ;;
		--linker-flags | -L )	 shift
								 extra_linker_flags="$extra_linker_flags $1"
								 is_extra_l_or_c_flags=true
								 ;;
		--compiler-flags | -C )	 shift
								 extra_compiler_flags="$extra_compiler_flags $1"
								 is_extra_l_or_c_flags=true
								 ;;
		--get-dep-online )		 echo "Download and build libksi."
								 do_build_dependecies=true
								 ;;
		--no-dep-check )		 echo "Ignoring 'build depends on' when building a package."
								 rpmbuild_flags="--nodeps"
								 debuild_flags="-d"
								 ;;
		--ign-dep-online-err )	 echo "Ignoring errors while building online dependencies."
								 rebuild_lib_dependencies_flags="--ignore-build-error"
								 ;;
		-v )					 is_verbose=true
								 ;;
		--help | -h )			 show_help=true
								 ;;
		* )						 echo "Unknown token '$1' from command-line."
								 show_help=true
								 exit 1
	esac
	shift
done

if $show_help ; then
	help_txt
	exit 0
fi

if $do_build_dependecies ; then
	is_inc_dir_set=true
	is_lib_dir_set=true
	./rebuild-lib-dependencies.sh $rebuild_lib_dependencies_flags
	include_dir="$include_dir -I$(pwd)/dependencies/include"
	lib_dir="$lib_dir -L$(pwd)/dependencies/lib"
	lib_path="$lib_path $(pwd)/dependencies/lib:"
fi

if $is_extra_l_or_c_flags ; then
	export CPPFLAGS="$CPPFLAGS $extra_compiler_flags"
	export LDFLAGS="$LDFLAGS $extra_linker_flags"
fi

if $is_inc_dir_set ; then
	export CPPFLAGS="$CPPFLAGS $include_dir"
fi

if $is_lib_dir_set ; then
	export LDFLAGS="$LDFLAGS $lib_dir"
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH $lib_path"
fi


# Error handling.
if $do_build_rpm && $do_build_deb; then
	>&2 echo  "Error: It is not possible to build both deb and rpm packages!"
	exit 1
fi


# Simple configure and make with extra options.
if $is_verbose ; then
	conf_args="$conf_args --disable-silent-rules"
	echo "Using extra configure flags: '$conf_args'"
	echo "Using extra make flags: '$make_args'"
	echo "CPPFLAGS = $CPPFLAGS"
	echo "LDFLAGS  = $LDFLAGS"
fi

echo ""

autoreconf -if
./configure $conf_args
make $make_args clean

# Package the software.
if $do_build_rpm || $do_build_deb; then
	echo "Making dist."
	make dist
	version=$(tr -d [:space:] < VERSION)

	if $do_build_rpm ; then
		echo "Making rpm."
		BUILD_DIR=~/rpmbuild
		mkdir -p $BUILD_DIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tmp} && \
		cp packaging/rpm/libgtrfc3161.spec $BUILD_DIR/SPECS/ && \
		cp libgtrfc3161-*.tar.gz $BUILD_DIR/SOURCES/ && \
		rpmbuild -ba $rpmbuild_flags $BUILD_DIR/SPECS/libgtrfc3161.spec && \
		cp $BUILD_DIR/RPMS/*/libgtrfc3161-*$version*.rpm . && \
		cp $BUILD_DIR/SRPMS/libgtrfc3161-*$version*.rpm . && \
		chmod -v 644 *.rpm
	elif $do_build_deb ; then
		ARCH=$(dpkg --print-architecture)
		RELEASE_VERSION="$(lsb_release -is)$(lsb_release -rs | grep -Po "[0-9]{1,3}" | head -1)"
		PKG_VERSION=1
		DEB_DIR=packaging/deb


		# Rebuild debian changelog.
		if command  -v dch > /dev/null; then
		  echo "Generating debian changelog..."
		  $DEB_DIR/rebuild_changelog.sh changelog $DEB_DIR/control libgtrfc3161 $DEB_DIR/changelog "1.0.0:unstable "
		else
		  >&2 echo "Error: Unable to generate Debian changelog file as dch is not installed!"
		  >&2 echo "Install devscripts 'apt-get install devscripts'"
		  exit 1
		fi

		tar xvfz libgtrfc3161-$version.tar.gz
		mv libgtrfc3161-$version.tar.gz libgtrfc3161-$version.orig.tar.gz
		mkdir libgtrfc3161-$version/debian
		cp $DEB_DIR/control $DEB_DIR/changelog $DEB_DIR/rules $DEB_DIR/copyright libgtrfc3161-$version/debian
		chmod +x libgtrfc3161-$version/debian/rules
		cd libgtrfc3161-$version
		# debuild cleans some environment variables, to keep LIBS -e is used.
		debuild -e LIBS -us -uc $debuild_flags
		cd ..

		suffix=${version}-${PKG_VERSION}.${RELEASE_VERSION}_${ARCH}
		mv libgtrfc3161_${version}_${ARCH}.changes libgtrfc3161_$suffix.changes
		mv libgtrfc3161_${version}_${ARCH}.deb libgtrfc3161_$suffix.deb
		mv libgtrfc3161-dev_${version}_${ARCH}.deb libgtrfc3161-dev_$suffix.deb

		rm -rf libgtrfc3161-$version
	else
		>&2 echo  "Error: Undefined behaviour!"
		exit 1
	fi
else
	make $make_args
fi
