#!/bin/sh

# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

mkdir -p ./exporter/go

# generate Go code
protoc --experimental_allow_proto3_optional --go_out=exporter/go --go_opt=paths=source_relative \
    --go-grpc_out=exporter/go --go-grpc_opt=paths=source_relative \
    exporter.proto

