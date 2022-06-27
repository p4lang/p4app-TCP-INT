#!/bin/bash

# Copyright 2021-2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Automatically reindent all .c and .h source files in this project.
# Need to install clag-format before running this script "apt install clang-format"

if [ -d .git ]
then
    PROJ_ROOT=$PWD
    1>&2 echo "Found .git directory.  Assuming this directory is project root directory:"
    echo $PROJ_ROOT
else
    1>&2 echo "No .git directory.  This command must be run from project root directory"
    exit 1
fi

for f in `find . -name '*.[ch]' | grep -v '/include/vmlinux*' | grep -v 'bpf/.*.skel.h'`
do
    clang-format -i -style="{BasedOnStyle: llvm, IndentWidth: 4, SortIncludes: false, BreakBeforeBraces: Linux}" "$f" $*
done
