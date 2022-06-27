
# Protobuf code generation
Use below command to generate Go code after changing the `.proto` files.
```
protoc --experimental_allow_proto3_optional \
    --go_out=exporter/go --go_opt=paths=source_relative \
    --go-grpc_out=exporter/go --go-grpc_opt=paths=source_relative \
    exporter.proto
```
