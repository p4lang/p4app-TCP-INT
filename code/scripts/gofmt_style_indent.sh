#!/bin/bash

# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Automatically reindent all go files in this project.

if [ -d .git ]
then
    PROJ_ROOT=$PWD
    1>&2 echo "Found .git directory.  Assuming this directory is project root directory:"
    echo $PROJ_ROOT
else
    1>&2 echo "No .git directory.  This command must be run from project root directory"
    exit 1
fi

gofmt -s -w .
