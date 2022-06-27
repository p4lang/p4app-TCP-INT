# tcpint exporter

### Tcp_int_exporter dependencies
* go language (version tested go1.17.7)
* protobuf(version 3.19.4)

NOTE: Check number of CPU's running on the server/vm where client code
will be running & change value of TCP_INT_MAX_CPUS in file tcp_int.bpf.c.

//To build and run the tcp_int_client:
```
make clean
make build
make install
/usr/local/lib/bpf/tcp-int/tcp_int_exporter --collector="10.232.15.198:30900"
```

### Runtime configuration
By default tcp_int_exporter tries to connect to the gRPC server using TLS. To
change this for testing/development use the -use-tls flag. This is not recommended
for production systems.
```
/usr/local/lib/bpf/tcp-int/tcp_int_exporter --collector="10.232.15.198:30900" -use-tls=false
```
