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
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <tee_client_api.h>
#include "ta_aes_perf.h"

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
 * Command line parameters
 */

static size_t size = 1024;	/* Buffer size (-s) */
static unsigned int n = 100000;	/* Number of measurements (-n) */
static unsigned int l = 1;	/* Inner loops (-l) */
static int verbosity = 0;	/* Verbosity (-v) */
static int decrypt = 0;		/* Encrypt by default, -d to decrypt */
static int keysize = 128;	/* AES key size (-k) */
static int mode = TA_AES_ECB;	/* AES mode (-m) */
static int random_in = 0;	/* Get input data from /dev/urandom (-r) */
static int in_place = 0;	/* 1: use same buffer for in and out (-i) */

/*
 * TEE client stuff
 */

static TEEC_Context ctx;
static TEEC_Session sess;
/*
 * in_shm and out_shm are both IN/OUT to support dynamically choosing
 * in_place == 1 or in_place == 0.
 */
static TEEC_SharedMemory in_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};
static TEEC_SharedMemory out_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};

static void errx(const char *msg, TEEC_Result res)
{
	fprintf(stderr, "%s: 0x%08x", msg, res);
	exit (1);
}

static void check_res(TEEC_Result res, const char *errmsg)
{
	if (res != TEEC_SUCCESS)
		errx(errmsg, res);
}

static void open_ta()
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_AES_PERF_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	check_res(res,"TEEC_InitializeContext");

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	check_res(res,"TEEC_OpenSession");
}

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
static void update_stats(struct statistics *s, uint64_t t)
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

static const char *mode_str(uint32_t mode)
{
	switch (mode) {
	case TA_AES_ECB:
		return "ECB";
	case TA_AES_CBC:
		return "CBC";
	case TA_AES_CTR:
		return "CTR";
	case TA_AES_XTS:
		return "XTS";
	default:
		return "???";
	}
}

#define _TO_STR(x) #x
#define TO_STR(x) _TO_STR(x)

static void usage(const char *progname)
{
	fprintf(stderr, "AES performance testing tool for OP-TEE (%s)\n\n",
		TO_STR(VERSION));
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s -h\n", progname);
	fprintf(stderr, "  %s [-v] [-m mode] [-k keysize] ", progname);
	fprintf(stderr, "[-s bufsize] [-r] [-i] [-n loops] [-l iloops] \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h    Print this help and exit\n");
	fprintf(stderr, "  -i    Use same buffer for input and output (in ");
	fprintf(stderr, "place)\n");
	fprintf(stderr, "  -k    Key size in bits: 128, 192 or 256 [%u]\n",
			keysize);
	fprintf(stderr, "  -l    Inner loop iterations (TA calls ");
	fprintf(stderr, "TEE_CipherUpdate() <x> times) [%u]\n", l);
	fprintf(stderr, "  -m    AES mode: ECB, CBC, CTR, XTS [%s]\n",
			mode_str(mode));
	fprintf(stderr, "  -n    Outer loop iterations [%u]\n", n);
	fprintf(stderr, "  -r    Get input data from /dev/urandom ");
	fprintf(stderr, "(otherwise use zero-filled buffer)\n");
	fprintf(stderr, "  -s    Buffer size (process <x> bytes at a time) ");
	fprintf(stderr, "[%zu]\n", size);
	fprintf(stderr, "  -v    Be verbose (use twice for greater effect)\n");
}

static void alloc_shm(size_t sz)
{
	TEEC_Result res;

	in_shm.buffer = NULL;
	in_shm.size = sz;
	res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
	check_res(res, "TEEC_AllocateSharedMemory");

	if (!in_place) {
		out_shm.buffer = NULL;
		out_shm.size = sz;
		res = TEEC_AllocateSharedMemory(&ctx, &out_shm);
		check_res(res, "TEEC_AllocateSharedMemory");
	}
}

static void free_shm()
{
	TEEC_ReleaseSharedMemory(&in_shm);
	TEEC_ReleaseSharedMemory(&out_shm);
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

static uint64_t timespec_diff_ns(struct timespec *start, struct timespec *end)
{
	uint64_t ns = 0;

	if (end->tv_nsec < start->tv_nsec) {
		ns += 1000000000 * (end->tv_sec - start->tv_sec - 1);
		ns += 1000000000 - start->tv_nsec + end->tv_nsec;
	} else {
		ns += 1000000000 * (end->tv_sec - start->tv_sec);
		ns += end->tv_nsec - start->tv_nsec;
	}
	return ns;
}

static uint64_t run_test_once(void *in, size_t size, TEEC_Operation *op,
			  unsigned int l)
{
	struct timespec t0, t1;
	TEEC_Result res;
	uint32_t ret_origin;

	if (random_in)
		read_random(in, size);
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_AES_PERF_CMD_PROCESS, op,
				 &ret_origin);
	check_res(res, "TEEC_InvokeCommand");
	get_current_time(&t1);

	return timespec_diff_ns(&t0, &t1);
}

static void prepare_key()
{
	TEEC_Result res;
	uint32_t ret_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = decrypt;
	op.params[0].value.b = keysize;
	op.params[1].value.a = mode;
	res = TEEC_InvokeCommand(&sess, TA_AES_PERF_CMD_PREPARE_KEY, &op,
				 &ret_origin);
	check_res(res, "TEEC_InvokeCommand");
}

static const char *yesno(int v)
{
	return (v ? "yes" : "no");
}

/* Encryption test: buffer of tsize byte. Run test n times. */
static void run_test(size_t size, unsigned int n, unsigned int l)
{
	uint64_t t;
	struct statistics stats = {0, };
	TEEC_Operation op;
	int n0 = n;

	alloc_shm(size);

	if (!random_in)
		memset(in_shm.buffer, 0, size);

	memset(&op, 0, sizeof(op));
	/* Using INOUT to handle the case in_place == 1 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = size;
	op.params[1].memref.parent = in_place ? &in_shm : &out_shm;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = size;
	op.params[2].value.a = l;

	verbose("Starting test: %s, %scrypt, keysize=%u bits, size=%zu bytes, ",
		mode_str(mode), (decrypt ? "de" : "en"), keysize, size);
	verbose("random=%s, ", yesno(random_in));
	verbose("in place=%s, ", yesno(in_place));
	verbose("inner loops=%u, loops=%u\n", l, n);

	while (n-- > 0) {
		t = run_test_once(in_shm.buffer, size, &op, l);
		update_stats(&stats, t);
		if (n % (n0/10) == 0)
			vverbose("#");
	}
	vverbose("\n");
	printf("min=%gμs max=%gμs mean=%gμs stddev=%gμs\n", stats.min/1000,
		stats.max/1000, stats.m/1000, stddev(&stats)/1000);
	free_shm();
}

int main(int argc, char *argv[])
{
	int i;
	struct timespec ts;
	struct timespec t0, t1;
	double elapsed;

	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h")) {
			usage(argv[0]);
			return 0;
		}
	}
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d")) {
			decrypt = 1;
		} else if (!strcmp(argv[i], "-i")) {
			in_place = 1;
		} else if (!strcmp(argv[i], "-k")) {
			i++;
			keysize = atoi(argv[i]);
			if (keysize != 128 && keysize != 192 &&
				keysize != 256) {
				fprintf(stderr, "%s: invalid key size\n",
					argv[0]);
				usage(argv[0]);
				return 1;
			}
		} else if (!strcmp(argv[i], "-l")) {
			i++;
			l = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-m")) {
			i++;
			if (!strcasecmp(argv[i], "ECB"))
				mode = TA_AES_ECB;
			else if (!strcasecmp(argv[i], "CBC"))
				mode = TA_AES_CBC;
			else if (!strcasecmp(argv[i], "CTR"))
				mode = TA_AES_CTR;
			else if (!strcasecmp(argv[i], "XTS"))
				mode = TA_AES_XTS;
			else {
				fprintf(stderr, "%s, invalid mode\n",
					argv[0]);
				usage(argv[0]);
				return 1;
			}
		} else if (!strcmp(argv[i], "-n")) {
			i++;
			n = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-r")) {
			random_in = 1;
		} else if (!strcmp(argv[i], "-s")) {
			i++;
			size = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-v")) {
			verbosity++;
		} else {
			fprintf(stderr, "%s: invalid argument\n", argv[0]);
			usage(argv[0]);
			return 1;
		}
	}

	vverbose("aes-perf version %s\n", TO_STR(VERSION));
	if (clock_getres(CLOCK_MONOTONIC, &ts) < 0) {
		perror("clock_getres");
		return 1;
	}
	vverbose("Clock resolution is %lu ns\n", ts.tv_sec*1000000000 +
		ts.tv_nsec);

	get_current_time(&t0);
	open_ta();
	prepare_key();
	run_test(size, n, l);
	get_current_time(&t1);

	elapsed = timespec_diff_ns(&t0, &t1);
	elapsed /= 1000000000;
	printf("Processed %lu bytes in %g seconds ", size * n, elapsed);
	printf("(%g MiB/s)\n", ((double)(size * n))/(1024 * 1024 * elapsed));

	return 0;
}
