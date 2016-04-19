	
if DEBUG
  AM_CFLAGS =-I$(top_srcdir)/src/bin -I$(top_srcdir)/src/lib -Wall -g -O0
else
  AM_CFLAGS =-I$(top_srcdir)/src/bin -I$(top_srcdir)/src/lib -Wall -O3
endif

AM_CFLAGS += $(KSI_CFLAGS)

bin_PROGRAMS = tsconvert
tsconvert_SOURCES = main.c

tsconvert_LDADD = $(top_builddir)/src/lib/libtsconvert.a $(AM_LDFLAGS)
tsconvert_LDADD += -lksi
##tsconvert_LDADD += $(KSI_LIBS)
