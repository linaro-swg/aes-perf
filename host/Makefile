# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.
ifeq ($O,)
$(error output path should be specified when calling this makefile)
endif

CC = $(CROSS_COMPILE_HOST)gcc

srcs := aes-perf.c

objs := $(patsubst %.c,$(O)/%.o, $(srcs))

CFLAGS += -I.
CFLAGS += -I$(OPTEE_CLIENT_PATH)/out/export/include

LDFLAGS += -L$(OPTEE_CLIENT_PATH)/out/export/lib -lteec

.PHONY: all
all: aes-perf

aes-perf: $(objs)
	@$(cmd-echo-silent) '  CC      $(O)/$@'
	$(q)$(CC) -o $(O)/$@ $+ $(LDFLAGS)

$(O)/%.o: $(CURDIR)/%.c
	$(q)mkdir -p $(O)/host
	@$(cmd-echo-silent) '  CC      $@'
	$(q)$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@echo '  CLEAN  $(O)'
	$(q)rm -f $(O)/aes-perf
	$(q)rm -f $(objs)

