CROSS_COMPILE := $(CROSS_COMPILE_TA)
BINARY = e626662e-c0e2-485c-b8c809fbce6edf3d
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

.PHONY: all
all: $(O)/$(BINARY).ta

$(O)/$(BINARY).ta: $(O)/$(BINARY).bin
	@$(cmd-echo-silent) '  GEN    $@'
	@rm -f $@
	@cat faked_armv7_uta_signed_header.bin $< > $@
