module tcp_int

go 1.17

require (
	github.com/cilium/ebpf v0.9.0
	google.golang.org/grpc v1.46.2
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.0.0-20201021035429-f5854403a974 // indirect
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34 // indirect
	golang.org/x/text v0.3.3 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	models v0.0.0-00010101000000-000000000000 // indirect
)

replace models => ../models
