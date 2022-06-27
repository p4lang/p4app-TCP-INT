# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

USER_TARGETS = tcp_int_exporter

PREFIX ?= /usr/local
INSTALLPATH = $(PREFIX)/lib/bpf/tcp-int/

all: clean build

clean:
	go clean
	rm -f $(USER_TARGETS)

build:
	go build -o tcp_int_exporter

install: $(USER_TARGETS)
	install -d $(INSTALLPATH)
	install $^ $(INSTALLPATH)

uninstall: $(USER_TARGETS)
	rm -f $(INSTALLPATH)$(USER_TARGETS)
