# TCP-INT: Lightweight In-band Network Telemetry for TCP

In-band Network Telemetry (INT) provides visibility into the state of the network and can be used
for monitoring and debugging. However, existing INT implementations do not make telemetry available
to end-hosts. TCP-INT addresses this shortcoming by delivering network telemetry directly to the
end-host TCP stack, enabling end-hosts to correlate local TCP state with the state of the network
fabric.

TCP-INT is implemented in the TCP header as a new TCP option with three fields:

 - INTval: the link utilization (or queue depth if utilization is 100%).
 - HopID: the ID of most congested switch (the packet’s TTL at the switch).
 - SWLat: the sum of latencies experienced at each hop.

Each field has a corresponding echo-reply field (ecr) for the receiver to echo the telemetry back to
the sender.

### TCP-INT option format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|  Kind = 0x72  |  Length = 6   |    INTval     |     INTecr    |
+---------------+---------------+---------------+----------------
|  HopID=IP.TTL |    HopIDecr   |            SWLat (3B)       ...
----------------+---------------+--------------------------------
 ...            |                  SWLatEcr (3B)                |
----------------+-----------------------------------------------+
```

### Workflow
- A process joins the `tcp-int` cgroup to indicate that its flows should be monitored by TCP-INT.
- When a packet is sent, the TCP-INT eBPF adds a TCP-INT header option to the TCP header.
- Upon receiving a packet with a TCP-INT header option, the switch updates the fields:
    - pkt.INTval = switch.INTval if switch.INTval > pkt.INTval
    - pkt.HopID = IP.TTL if switch.INTval > pkt.INTval
    - pkt.SWLat += latency through this switch
- The eBPF receives the telemetry and (possibly) sends it to user-space for consumption.
- When the ACK is sent, the eBPF sets the ecr fields to the latest INT received on the send path.


## Repo Organization

The TCP-INT repository is organized as follows:
```
code:
  ┣ src/bpf: eBPF module
  ┣ src/tools: tool for loading, managing and monitoring the module
  ┣ tcp-int-exporter: user-space agent to export INT to gRPC server
  ┗ scripts: helper scripts
```

### Switch Code

The switch-side P4 and control plane implementations are provided in a special release of Intel P4 Studio (aka Tofino SDE). To obtain access to the SDE, contact your Intel Sales Representative. Academic researchers can apply for access through the [Intel Connectivity Research Program (ICRP)](https://www.intel.com/content/www/us/en/products/network-io/programmable-ethernet-switch/connectivity-education-hub/research-program.html).


## Getting Started

### Prerequisites

* Linux Kernel 5.10.x or later

### Tested on

* Linux 5.11.0-17-generic and Linux 5.13.0-28-generic
* Ubuntu 21.04 and Ubuntu 21.10

### Setup steps for all end-hosts (clients and servers)

Examples in this README assume that you are running as the 'root' user. If not, then most commands will likely need privilege escalation using `sudo`.

#### 1. Install TCP-INT Dependencies

TCP-INT requires the following packages to be installed:
* build-essential
* clang
* llvm
* gcc-multilib
* libelf-dev
* linux-tools
* pkg-config
* libbpf 0.7 (See LibBPF setup below)
```
# For Debian based distributions
apt install -y build-essential clang llvm gcc-multilib libelf-dev linux-tools-$(uname -r) pkg-config
```

#### 2. Download and install Libbpf

More detailed installation instructions and dependencies can be found on the Libbpf Github page:<br>
https://github.com/libbpf/libbpf/tree/v0.7.0
```
wget https://github.com/libbpf/libbpf/archive/refs/tags/v0.7.0.tar.gz
tar xzf v0.7.0.tar.gz -C /opt
cd /opt/libbpf-0.7.0/src
make
LIBDIR=/lib/x86_64-linux-gnu make install
```
Note: User might need pkg-config to build libbpf.

#### 3. Copy TCP-INT source to end-hosts

Copy this source code repository to each end-host where you intend to use TCP-INT. For the purpose of these instructions we will assume it is extracted to `/opt/tcp-int`.

#### 4. Optional: update vmlinux.h file for the current kernel version

BPF programs need to hook into data structures in memory of the current running kernel, to do this they need an up-to-date header file containing information about the running kernel.

* Additional packages may be required to install the bpftool application

```
cd /opt/tcp-int/include/
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux-$(uname -r).h
rm vmlinux.h
ln -s vmlinux-$(uname -r).h vmlinux.h
```

#### 5. Compile and deploy TCP-INT on the end-hosts

```
# Compile and install TCP-INT
cd /opt/tcp-int/src
make clean && make install
```
#### 6. Verify / set-up cgroups v2

TCP-INT requires cgroups v2 in order to work.
* The default 'load' command will attempt to create the following cgroup directory: `/sys/fs/cgroup/cgroup.tcp-int`
  * The default expects /sys/fs/cgroup to already exist as a cgroup2 mount.
* An alternative path can be specified when loading with the `-c` option.
  * For example: `tcp_int load -c /sys/fs/cgroup/unified/my-tcp-int.cgroup`

```
# Check if cgroups v2 are already mounted correctly
mount -l | grep cgroup2

# Example output 1: Ubuntu 21.04: Indicates that cgroups v2 is already mounted in a subdirectory of cgroup.
cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)

# Example output 2: Debian 11 (and ubuntu 21.10): Indicates that cgroups v2 is mounted at the top level cgroup directory.
# In this case you can simply create the 'unified' subdirectory or define a custom tcp-int cgroup path using the -c option.
cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
```

### Loading TCP-INT and running test applications

#### 1. Load TCP-INT on the end-hosts

This step should be run on all end-hosts each time that node is rebooted. This loads the TCP-INT BPF program.

```
# First, attempt to unload TCP-INT in case it was not left in a clean state
/usr/local/lib/bpf/tcp-int/tcp_int unload

# Now load the TCP-INT BPF program
/usr/local/lib/bpf/tcp-int/tcp_int load
```

#### 2. Disable TCP Timestamps (optional)

TCP timestamps may need to be disabled on BOTH the client and server end-hosts, depending on the current version of TCP-INT support on the switches. If this is necessary, run the following command on ALL end-host nodes:
```
# Disable TCP timestamps
sysctl -w net.ipv4.tcp_timestamps=0
```

#### 3. Server-side setup

The role of the server in TCP-INT test applications is to echo back the altered TCP-INT values to the client in acknowledgement (ACK) messages.

```
# Start bash session in tcp-int cgroup
bash
echo $$ >> /sys/fs/cgroup/cgroup.tcp-int/cgroup.procs

# Start server
pkill iperf3
iperf3 -s -p 5001
```

#### 4. Client-side setup

The role of the client is to initialise the TCP-INT TCP option and also to receive and process the echoed TCP-INT replies coming back from the server.

* Setting up a test stream with TCP-INT TCP Option initialised
```
# Open a shell terminal on the client node in the tcp-int cgroup
bash
echo $$ >> /sys/fs/cgroup/cgroup.tcp-int/cgroup.procs

# Generate a tcp stream using TCP-INT-eBPF
iperf3 -c <iPerf SERVER-IP> -p 5001 -w 20M -t 120
```

* Open a second console to control and observer TCP-INT
```
# Optionally disable TCP-INT echo on the client to reduce overheads
/usr/local/lib/bpf/tcp-int/tcp_int ecr-disable

# Start full tracing
/usr/local/lib/bpf/tcp-int/tcp_int trace
```
* Alternatively, display TCP-INT histograms showing in-network link utilisation and queue depth
```
# Optionally disable TCP-INT echo on the client to reduce overheads
/usr/local/lib/bpf/tcp-int/tcp_int ecr-disable

# Show TCP-INT histograms
watch -t -p -n 1 timeout -s SIGINT 1 "/usr/local/lib/bpf/tcp-int/tcp_int hist-int-perid | column"

# The tcp_int help text lists other modes of operation
/usr/local/lib/bpf/tcp-int/tcp_int help
```

## Running applications locally with network namespaces

This was tested an Ubuntu 21.10 VM with kernel `5.13.0-28-generic`.

#### 1. Load TCP-INT on the host
```
sudo /usr/local/lib/bpf/tcp-int/tcp_int load
```

#### 2. Setup the network namespaces
```
./code/scripts/namespaces.sh
```

#### 3. Start the application in the namespaces
* Open a shell for the server, add it to the tcp-int cgroup, and launch iperf3 in ns1:
```
bash
echo $$ | sudo tee -a /sys/fs/cgroup/cgroup.tcp-int/cgroup.procs
sudo ip netns exec ns1 iperf3 -s -p 5001
```

* Open another shell for the client and start the iperf3 client in ns2:
```
bash
echo $$ | sudo tee -a /sys/fs/cgroup/cgroup.tcp-int/cgroup.procs
sudo ip netns exec ns2 iperf3 -c 10.0.0.1 -p 5001 -t 120
```

#### 4. Add a `tc` pedit filter to mimic the switch
Modify TCP packets (except for SYN/FIN) sent from ns2 to port 5001: set the tcp-int option fields (intval=5, id=6).
This `tc` filter uses hard-coded offsets that **assume TCP timestamps are enabled**.
```
sudo ip netns exec ns2 tc qdisc replace dev v2 root handle 1: htb
sudo ip netns exec ns2 tc filter add dev v2 parent 1: protocol ip flower ip_proto tcp tcp_flags 0x0/0x7 dst_port 5001 action pedit munge offset 54 u8 set 5 continue
sudo ip netns exec ns2 tc filter add dev v2 parent 1: protocol ip flower ip_proto tcp tcp_flags 0x0/0x7 dst_port 5001 action pedit munge offset 56 u8 set 6 continue
```

#### 5. Monitor with tcp-int trace
```
sudo /usr/local/lib/bpf/tcp-int/tcp_int trace
```

#### 6. Remove the `tc` pedit filter
```
sudo ip netns exec ns2 tc filter del dev v2 parent 1:
```
