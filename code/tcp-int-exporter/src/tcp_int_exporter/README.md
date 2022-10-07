# tcpint exporter

### Tcp_int_exporter dependencies
* go language (version tested go1.17.7)
* protobuf(version 3.19.4)
* Install Go pluggins. Installation instructions can be found at
https://grpc.io/docs/languages/go/quickstart/

### Compile and run the tcp_int_exporter
```
make clean
make build
make install
/usr/local/lib/bpf/tcp-int/tcp_int_exporter --collector="0.0.0.0:30900"
```

### Runtime configuration
By default tcp_int_exporter tries to connect to the gRPC server using TLS. To
change this for testing/development use the -use-tls flag. This is not recommended
for production systems.
```
/usr/local/lib/bpf/tcp-int/tcp_int_exporter --collector="0.0.0.0:30900" -use-tls=false
```
