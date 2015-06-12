/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int verbosity = 0;

#define _verbose(lvl, args)			\
	do {					\
		if (verbosity >= lvl) {		\
			printf(args);		\
			fflush(stdout);		\
		}				\
	} while(0);

#define verbose(...)  _verbose(1, __VA_ARGS__)
#define vverbose(...) _verbose(2, __VA_ARGS__)

static void usage(const char *progname)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s -h\n", progname);
	fprintf(stderr, "  %s [-v]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h    Print this help and exit\n");
	fprintf(stderr, "  -v    Be verbose (use twice for greater effect)\n");
}

static void *alloc_inbuf(size_t sz)
{
	return malloc(sz);
}

int main(int argc, char *argv[])
{
	int i;
	int rnd;
	void *in;
	size_t rsize = 1024;		/* Process rsize bytes at a time */
	size_t tsize = 1024 * 1024;	/* Total size to process */
	ssize_t done = 0;		/* Size processed */
	ssize_t s;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v"))
			verbosity++;
		else if (!strcmp(argv[i], "-h")) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "%s: invalid argument\n", argv[0]);
			usage(argv[0]);
			return 1;
		}

	}
	rnd = open("/dev/urandom", O_RDONLY);
	if (rnd < 0) {
		perror("open");
		return 1;
	}
	in = alloc_inbuf(rsize);
	if (!in) {
		fprintf(stderr, "allocation failed\n");
		return 1;
	}
	while (done < tsize) {
		s = read(rnd, in, rsize);
		if (s < 0) {
			perror("read");
			return 1;
		}
		if (s != rsize) {
			printf("read: requested %zu bytes, got %zd\n",
			       rsize, s);
		}
		done += s;
		verbose("#");
	}
	verbose("\n");
	close(rnd);
	return 0;
}
