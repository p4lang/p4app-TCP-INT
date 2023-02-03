# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

GIT_VERSION := $(shell git describe --abbrev=12 --tags)
GIT_COMPILE_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

GOLDFLAGS += -X main.version=$(GIT_VERSION)
GOLDFLAGS += -X main.compileTime=$(GIT_COMPILE_TIME)
GOLDFLAGS += -X main.gitBranch=$(GIT_BRANCH)
GOFLAGS = -ldflags "$(GOLDFLAGS)"

USER_TARGETS = tcp_int_exporter

PREFIX ?= /usr/local
INSTALLPATH = $(PREFIX)/lib/bpf/tcp-int/

all: clean build

clean:
	go clean
	rm -f $(USER_TARGETS)

build:
	go build -o tcp_int_exporter $(GOFLAGS)

install: $(USER_TARGETS)
	install -d $(INSTALLPATH)
	install $^ $(INSTALLPATH)

uninstall: $(USER_TARGETS)
	rm -f $(INSTALLPATH)$(USER_TARGETS)
