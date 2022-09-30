#!/bin/bash

# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

show_usage() {
    1>&2 echo "usage: `basename $0` <interface> <time_in_seconds> <server_ip> <directory> <tcpdump_yes | tcpdump_no> [ extra args added to iperf command ]"
}

if [ $# -lt 5 ]
then
    show_usage
    exit 1
fi

DEV=$1
shift
TIME=$1
shift
DEST_IP=$1
shift
DIR=$1
shift
TCPDUMP=$1
shift

ss_pid=0
hist_pid=0

mkdir -p $DIR

cp /dev/null $DIR/ifconfig_client.log

date >> $DIR/ifconfig_client.log

echo "Running ifconfig"
ifconfig $DEV >> $DIR/ifconfig_client.log
bpftool prog show > $DIR/start_stats_client.txt

echo "Start top command to run every 2 second"
top -b -d 2 > $DIR/top_client.log &

if [[ $TCPDUMP == tcpdump_yes ]]; then
    tcpdump -i $DEV -s 128 -w $DIR/results_client.pcap &
fi

echo "Collect ss stats"
/opt/tcp-int/scripts/run_ss.sh $DEST_IP > $DIR/ss_results_client.txt &
ss_pid=$!

echo "Start collecting tx histograms"
/usr/local/lib/bpf/tcp-int/tcp_int hist-txpktlen > $DIR/tx_hist_client.log &
hist_pid=$!

/opt/tcp-int/scripts/tcp-int-run numactl -N netdev:$DEV -m netdev:$DEV iperf -c $DEST_IP -p 5001 -N -i 5 -e -t $TIME -P 1 -Z dctcp $* > $DIR/iperf_client.log

bpftool prog show > $DIR/end_stats_client.txt
date >> $DIR/ifconfig_client.log
ifconfig $DEV >> $DIR/ifconfig_client.log

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

echo "Perf test finished"

exit 0
