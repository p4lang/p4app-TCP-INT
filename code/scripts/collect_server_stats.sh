#!/bin/bash

# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

show_usage() {
    1>&2 echo "usage: `basename $0` <interface> <client_ip> <directory> <window_size> <tcpdump_yes | tcpdump_no> [ extra args added to iperf command ]"
}

if [ $# -lt 5 ]
then
    show_usage
    exit 1
fi

DEV=$1
shift
DEST_IP=$1
shift
DIR=$1
shift
WIN_SIZE=$1
shift
TCPDUMP=$1
shift

ss_pid=0
hist_pid=0

mkdir -p $DIR

cp /dev/null $DIR/ifconfig_server.log

date >> $DIR/ifconfig_server.log
echo "Running ifconfig"
ifconfig $DEV >> $DIR/ifconfig_server.log
bpftool prog show > $DIR/start_stats_server.txt

echo "Start top command to run every 2 second"
top -b -d 2 > $DIR/top_server.log &

if [[ $TCPDUMP == tcpdump_yes ]]; then
    tcpdump -i $DEV -s 128 -w $DIR/results_server.pcap &
fi

echo "Collect ss stats"
/opt/tcp-int/scripts/run_ss.sh $DEST_IP > $DIR/ss_results_server.txt &
ss_pid=$!

echo "Start collecting rx packetlen histograms"
/usr/local/lib/bpf/tcp-int/tcp_int hist-rxpktlen > $DIR/rx_hist_server.log &
hist_pid=$!

/opt/tcp-int/scripts/tcp-int-run numactl -N netdev:$DEV -m netdev:$DEV iperf -s -w $WIN_SIZE -p 5001 -Z dctcp $* > $DIR/iperf_server.log &

echo "iperf server running."
echo "Press return to complete the collection of statistics."

read

pkill iperf
date >> $DIR/ifconfig_server.log
ifconfig $DEV >> $DIR/ifconfig_server.log
bpftool prog show > $DIR/end_stats_server.txt
pkill top

if [[ $TCPDUMP == tcpdump_yes ]]; then
    pkill tcpdump
fi

if [[ ${hist_pid} -ne 0 ]]; then
    kill -s SIGINT ${hist_pid}
    hist_pid=0
fi

if [[ ${ss_pid} -ne 0 ]]; then
    kill -9 ${ss_pid}
    ss_pid=0
fi

echo "Finished perf test"
exit 0
