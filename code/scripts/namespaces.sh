#!/bin/bash

# Copyright 2021-2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

echo "Creating namespaces ..."
sudo ip link add vbr1 type bridge

# Create namespaces
sudo ip netns add ns1
sudo ip netns add ns2

# Create virtual links
sudo ip link add v1 type veth peer name v3
sudo ip link add v2 type veth peer name v4

# Connect bridges & namespaces using these links
sudo ip link set v1 netns ns1
sudo ip link set v2 netns ns2
sudo ip link set v3 master vbr1
sudo ip link set v4 master vbr1

# Add ip addresses to bridge & bring it up
sudo ip link set dev vbr1 up
sudo ip addr add 10.0.0.5/24 dev vbr1

sudo ip link set v3 up
sudo ip link set v4 up

# Setup IP and set the links up
sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev v1
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev v2
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up
sudo ip netns exec ns1 ip link set v1 up
sudo ip netns exec ns2 ip link set v2 up

echo ""
echo "Created these Linux network namespaces:"

echo ""
echo "+-------------------+ +-----------------------------------------+"
echo "| namespace ns1     | |                default namespace        |"
echo "|                   | |                                         |"
echo "|       10.0.0.1/24 | |   (interface)                           |"
echo "|            v1 --------- v3 -------------                      |"
echo "|       (interface) | |                   |                     |"
echo "+-------------------+ |                   |                     |"
echo "                      |                   |                     |"
echo "                      |                 vbr1  10.0.0.5/24       |"
echo "|-------------------+ |                   |                     |"
echo "| namespace ns2     | |                   |                     |"
echo "|                   | |                   |                     |"
echo "|       10.0.0.2/24 | |                   |                     |"
echo "|            v2 --------- v4 -------------                      |"
echo "|       (interface) | |   (interface)                           |"
echo "+-------------------+ +-----------------------------------------+"
echo ""
echo "To start a shell in ns1 / ns2:"
echo "    sudo ip netns exec ns1 bash"
echo "    sudo ip netns exec ns2 bash"
echo ""
echo "Useful tcpdump options to see packets on v1 (v2) run from inside ns1 (ns2):"
echo "    tcpdump -l -X -vv -i v1"
echo "    tcpdump -l -X -vv -i v2"

# Check whether br_netfilter is loaded
if lsmod | grep br_netfilter &> /dev/null ; then
    1>&2 echo "Warning: the br_netfilter module is loaded, which may drop IP packets between the namespaces. For more information, see: https://unix.stackexchange.com/a/671703"
    1>&2 echo "If there are routing problems, try unloading the module (may interfere with docker): rmmod br_netfilter"
fi
