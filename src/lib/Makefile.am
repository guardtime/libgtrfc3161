noinst_LIBRARIES = libtsconvert.a
noinst_HEADERS = tsconvert.h

if DEBUG
  AM_CFLAGS =-I$(top_srcdir)/src/lib -Wall -g -O0
else
  AM_CFLAGS =-I$(top_srcdir)/src/lib -Wall
endif

# The files to add to the library and to the source distribution
libtsconvert_a_SOURCES = \
                         $(libtsconvert_base_a_HEADERS) \
                         parseasn1.c \
                         tsconvert.c
