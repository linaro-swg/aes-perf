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
#include <stdint.h>
#include <time.h>
#include <math.h>

/* Default buffer size (-s) */
#define DEF_S 1024

#define DEF_N 20000

static int verbosity = 0;

#define _verbose(lvl, ...)			\
	do {					\
		if (verbosity >= lvl) {		\
			printf(__VA_ARGS__);	\
			fflush(stdout);		\
		}				\
	} while (0)

#define verbose(...)  _verbose(1, __VA_ARGS__)
#define vverbose(...) _verbose(2, __VA_ARGS__)

/*
 * Statistics
 *
 * We want to compute min, max, mean and standard deviation of processing time
 */

struct statistics {
	int n;
	double m;
	double M2;
	double min;
	double max;
	int initialized;
};

/* Take new sample into account (Knuth/Welford algorithm) */
static void update_stats(struct statistics *s, long t)
{
	double x = (double)t;
	double delta = x - s->m;

	s->n++;
	s->m += delta/s->n;
	s->M2 += delta*(x - s->m);
	if (!s->initialized) {
		s->min = s->max = x;
		s->initialized = 1;
	} else {
		if (s->min > x)
			s->min = x;
		if (s->max < x)
			s->max = x;
	}
}

static double stddev(struct statistics *s)
{
	if (s->n < 2)
		return NAN;
	return sqrt(s->M2/s->n);
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s -h\n", progname);
	fprintf(stderr, "  %s [-v] [-n loops] [-s size]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h    Print this help and exit\n");
	fprintf(stderr, "  -n    Number of loops [%u]\n", DEF_N);
	fprintf(stderr, "  -s    Buffer size (process size bytes at a time) ");
	fprintf(stderr, "[%u]\n", DEF_S);
	fprintf(stderr, "  -v    Be verbose (use twice for greater effect)\n");
}

static void *alloc_inbuf(size_t sz)
{
	return malloc(sz);
}

static void free_inbuf(void *buf)
{
	free(buf);
}

static ssize_t read_random(void *in, size_t rsize)
{
	static int rnd;
	ssize_t s;

	if (!rnd) {
		rnd = open("/dev/urandom", O_RDONLY);
		if (rnd < 0) {
			perror("open");
			return 1;
		}
	}
	s = read(rnd, in, rsize);
	if (s < 0) {
		perror("read");
		return 1;
	}
	if (s != rsize) {
		printf("read: requested %zu bytes, got %zd\n",
		       rsize, s);
	}
}

static long get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
}

static long timspec_diff(struct timespec *start, struct timespec *end)
{
	long ns = 0;

	if (end->tv_nsec < start->tv_nsec) {
		ns += 1000000000 * (end->tv_sec - start->tv_sec - 1);
		ns += 1000000000 - start->tv_nsec + end->tv_nsec;
	} else {
		ns += 1000000000 * (end->tv_sec - start->tv_sec);
		ns += end->tv_nsec - start->tv_nsec;
	}
	return ns;
}

static long run_test_once(void *in, size_t size)
{
	int i;
	struct timespec t0, t1;
	long ns;

	get_current_time(&t0); /* TODO: move after read */
	read_random(in, size);
	/* TODO: Encrypt or decrypt buffer */
	get_current_time(&t1);

	return timspec_diff(&t0, &t1);
}

/* Encryption test: buffer of tsize byte. Run test n times. */
static void run_test(size_t size, unsigned int n)
{
	void *in;
	long t;
	struct statistics stats = {0, };

	in = alloc_inbuf(size);
	if (!in) {
		fprintf(stderr, "allocation failed\n");
		exit(1);
	}

	printf("Starting test: size = %zu bytes, # loops = %u\n", size, n);
	while (n-- > 0) {
		t = run_test_once(in, size);
		update_stats(&stats, t);
		if (n % 1000 == 0)
			verbose("#");
	}
	verbose("\n");

	free_inbuf(in);
	printf("Done. n=%d: min=%g max=%g mean=%g stddev=%g\n",
	       stats.n, stats.min, stats.max, stats.m, stddev(&stats));
}

int main(int argc, char *argv[])
{
	int i;
	struct timespec ts;
	size_t size = DEF_S;	/* Process rsize bytes at a time */
	unsigned int n = DEF_N;	/* Run test n times */

	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v")) {
			verbosity++;
		} else if (!strcmp(argv[i], "-h")) {
			usage(argv[0]);
			return 0;
		} else if (!strcmp(argv[i], "-s")) {
			i++;
			size = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-n")) {
			i++;
			n = atoi(argv[i]);
		} else {
			fprintf(stderr, "%s: invalid argument\n", argv[0]);
			usage(argv[0]);
			return 1;
		}
	}

	if (clock_getres(CLOCK_MONOTONIC, &ts) < 0) {
		perror("clock_getres");
		return 1;
	}
	printf("Note: clock resolution is %lu ns.\n", ts.tv_sec*1000000000 +
	       ts.tv_nsec);

	run_test(size, n);

	return 0;
}
