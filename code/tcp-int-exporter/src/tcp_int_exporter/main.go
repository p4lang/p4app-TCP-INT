// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	pb "models/proto/exporter/go"
	"tcp_int/pkg/exporter"
	"tcp_int/pkg/secure"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"google.golang.org/grpc"
)

var (
	collector   string
	ebpfMapFile string
	bufferSize  int
	numWorkers  int
	queueSize   int
	timeout     time.Duration
	useTls      bool
	caCert      string
	version     string
	compileTime string
	gitBranch   string
)

func main() {
	flag.StringVar(&collector, "collector", "10.232.15.198:30900", "collector")
	flag.StringVar(&ebpfMapFile, "ebpf_map_file", "/sys/fs/bpf/tcp-int/map_tcp_int_events", "tcp int event map file path")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "gRPC timeout")
	flag.IntVar(&numWorkers, "num_workers", 10, "number of workers")
	flag.IntVar(&bufferSize, "buffer_size", 100, "ring buffer size")
	flag.IntVar(&queueSize, "queue_size", 1000, "message queue size")
	flag.BoolVar(&useTls, "use-tls", true, "Connect to server using TLS")
	flag.StringVar(&caCert, "ca-cert", "/ets/ssl/certs/tcp_int_ca_cert.pem", "Certificate of the CA that signed the collector's cert")
	flag.Parse()

	log.Printf("Compile Time: %s\n", compileTime)
	log.Printf("Version: %s\n", version)
	log.Printf("Git Branch: %s\n", gitBranch)

	if useTls && !secure.IsValidCert(caCert) {
		log.Fatalf("CA certificate '%s' does not appear to be a valid PEM certificate file", caCert)
	}

	ctx := context.Background()
	errChan := make(chan error, 0)

	var err error
	var conn *grpc.ClientConn

	proxyEnv := os.Getenv("https_proxy")

	if useTls {
		tlsCredentials, err := secure.LoadTLSCredentialsForClient(caCert)
		if err != nil {
			log.Fatal("cannot load TLS credentials: ", err)
		}
		conn, err = grpc.Dial(collector,
			grpc.WithTransportCredentials(tlsCredentials),
			grpc.WithNoProxy())

	} else {

		if strings.Contains(proxyEnv, "http://localhost") {
			conn, err = grpc.Dial(collector,
				grpc.WithInsecure())
		} else {
			conn, err = grpc.Dial(collector,
				grpc.WithInsecure(),
				grpc.WithNoProxy())
		}
	}

	if err != nil {
		log.Fatalf("did not connect: %s", err)
		os.Exit(1)
	}
	defer conn.Close()
	// create gRPC client
	c := pb.NewTcpIntServiceClient(conn)

	// load ebpf map
	eventsMap, err := ebpf.LoadPinnedMap(ebpfMapFile, nil)
	if err != nil {
		log.Fatalf("failed to load map %s, err: %v \n", ebpfMapFile, err)
		os.Exit(1)
	}

	events, err := perf.NewReader(eventsMap, bufferSize)
	if err != nil {
		log.Fatalf("NewReader err: %v \n", err)
		os.Exit(1)
	}
	defer events.Close()

	// start tcp int exporter
	tcpintClient := exporter.NewTcpIntClient(events, c, numWorkers, queueSize)
	log.Printf("starting TCP-INT gRPC client...")
	go tcpintClient.Start(ctx, errChan)

	select {
	case <-ctx.Done():
		log.Fatalf("context done: %v\n", ctx.Err())
		os.Exit(1)
	case err := <-errChan:
		log.Fatalf("error running telemetry collector: %v\n", err)
		os.Exit(1)
	}
}
