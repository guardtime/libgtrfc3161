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

AC_INIT([libgtrfc3161], m4_esyscmd([tr -d [:space:] <VERSION]), [support@guardtime.com])
AC_CONFIG_FILES([libgtrfc3161.pc])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/gtrfc3161/config.h])
AC_CANONICAL_TARGET

LTVER=m4_esyscmd([head -n 1 ABI_VERSION | tr -d [:space:]])
AC_SUBST(LTVER)

AM_INIT_AUTOMAKE([subdir-objects foreign -Wall -Werror tar-ustar])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL
AC_CHECK_PROG(git_installed,git,"yes", "no")

# Define the git hash of the current version.
AC_MSG_CHECKING([for commit id])
commit_id=""
if test "$git_installed" = "yes" -a -x ".git"; then
	commit_id=$(git log -n 1 --format="%H")
	AC_MSG_RESULT([$commit_id])
	AC_DEFINE_UNQUOTED(COMMIT_ID, "$commit_id", [Commit id])
else
	AC_MSG_RESULT([no])
fi


# Define min libksi version dependency.
libksi_ver="3.10"

# Specify dependencies for DEB packaging.
KSI_DEB_BUILD_DEPENDENCY="libksi-dev(>=$libksi_ver)"
KSI_DEB_RUN_DEPENDENCY="libksi(>=$libksi_ver)"

# Checks for libraries.
# Perform the dynamic build.
AC_CHECK_LIB([ksi],
		[KSI_CTX_new],
		[],
		[AC_MSG_FAILURE([Could not find libksi (KSI C SDK). Install libksi or specify the library path manually.])])
AC_CHECK_LIB([ksi],
		[KSI_SignatureBuilder_open],
		[],
		[AC_MSG_FAILURE([Current libksi version (< 3.10.1839) does not support KSI_SignatureBuilder interface.])])

LIBKSI_BUILD_DEPENDENCY="BuildRequires: libksi-devel >= $libksi_ver"


AC_SUBST(LIBKSI_BUILD_DEPENDENCY)
AC_SUBST(KSI_DEB_BUILD_DEPENDENCY)
AC_SUBST(KSI_DEB_RUN_DEPENDENCY)
#AC_SUBST(RPM_BUILD_FLAGS)

# Checks for libraries.
AC_CHECK_HEADER([ksi/ksi.h], [], [AC_MSG_FAILURE([Could not find include files (libksi-devel) of libksi (KSI C SDK). Install libksi-devel or specify the headers manually.])])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stddef.h stdint.h stdlib.h string.h unistd.h])


# To ensure compatibility with Microsoft compiler.
CFLAGS+= " -Wdeclaration-after-statement"
# Add more warnings
CFLAGS+=" -Wall"
# Optimize for debugging
#CFLAGS+=" -Og"

AC_ARG_WITH(unit-test-xml,
		[  --with-unit-test-xml=file		Specifies the target xml of unit tests.],
		:,
		with_unit_test_xml=testsuite-xunit.xml)

AC_DEFINE_UNQUOTED(UNIT_TEST_OUTPUT_XML, "$with_unit_test_xml", [Location of the unit test xml results.])

AC_ARG_ENABLE([custom-malloc],
		[  --enable-custom-malloc		Use custom malloc (used for test purpose).],
		[ AC_MSG_NOTICE([!!!!!!!! U S I N G    C U S T O M    M A L L O C !!!!!!!!]) ]
			[ AC_DEFINE(USE_CUSTOM_MALLOC, 1, [Custom malloc is used.]) ],
		:)

AC_ARG_ENABLE([full-test-coverage],
		[  --enable-full-test-coverage		Build all necessary libraries to enable full test coverage.],
		enable_full_test_coverage=true,
		:)

AM_CONDITIONAL([FULL_TEST_COVERAGE], [test x$enable_full_test_coverage = xtrue])

AC_MSG_NOTICE([Update version.h])
rm -f src/gtrfc3161/version.h
VER=($(echo $PACKAGE_VERSION | tr "." " "))
VER_MAJOR=${VER[[0]]}
VER_MINOR=${VER[[1]]}
VER_BUILD=${VER[[2]]}
AC_SUBST(VER_MAJOR)
AC_SUBST(VER_MINOR)
AC_SUBST(VER_BUILD)
AC_CONFIG_FILES([src/gtrfc3161/version.h])


AC_CONFIG_FILES([GNUmakefile src/gtrfc3161/GNUmakefile test/GNUmakefile doc/GNUmakefile src/example/GNUmakefile])
AC_CONFIG_FILES([packaging/rpm/libgtrfc3161.spec packaging/deb/control packaging/deb/rules])
AC_OUTPUT
