#!/bin/bash

# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

show_usage() {
    1>&2 echo "usage: `basename $0` < dest_ip >"
}

if [ $# -ne 1 ]
then
    show_usage
    exit 1
fi

DEST_IP=$1

while true
do
    ss -ietnOH dst $DEST_IP
done
