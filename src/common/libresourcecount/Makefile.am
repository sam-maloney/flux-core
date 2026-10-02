AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS)

AM_CPPFLAGS = \
	$(CODE_COVERAGE_CPPFLAGS) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/common/libccan \
	-I$(top_builddir)/src/common/libflux \
	$(JANSSON_CFLAGS)

noinst_LTLIBRARIES = libresourcecount.la

fluxinclude_HEADERS = count.h

libresourcecount_la_SOURCES = \
	count.c \
	count.h

TESTS = test_count.t

check_PROGRAMS = \
	$(TESTS)

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_count_t_SOURCES = test/count.c
test_count_t_CPPFLAGS = $(AM_CPPFLAGS)
test_count_t_LDADD = \
	$(top_builddir)/src/common/libresourcecount/libresourcecount.la \
	$(top_builddir)/src/common/libidset/libidset.la \
	$(top_builddir)/src/common/libtap/libtap.la \
	$(JANSSON_LIBS)
