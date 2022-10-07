// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package exporter

import (
	"context"
	"fmt"
	"log"

	pb "models/proto/exporter/go"
	"tcp_int/pkg/parser"

	"github.com/cilium/ebpf/perf"
)

type TcpIntClient struct {
	reader *perf.Reader
	client pb.TcpIntServiceClient

	workChan   chan *pb.TcpIntMsg
	numWorkers int
}

func NewTcpIntClient(reader *perf.Reader, client pb.TcpIntServiceClient, numWorker int, queueSize int) *TcpIntClient {
	return &TcpIntClient{
		reader:     reader,
		client:     client,
		numWorkers: numWorker,

		workChan: make(chan *pb.TcpIntMsg, queueSize),
	}
}

func (c *TcpIntClient) Start(ctx context.Context, errChan chan error) {

	// start the workers
	for i := 0; i < c.numWorkers; i++ {
		go c.work(ctx, c.workChan)
	}

	for {
		select {
		case <-ctx.Done():
			errChan <- ctx.Err()
		default:
			//log.Printf("listening for events \n")
			record, err := c.reader.Read()
			if err != nil {
				fmt.Printf("failed to read record from eBPF map: %v \n", err)
				continue
			}
			//log.Printf("eBPF map record: %+v \n", record)

			if record.LostSamples != 0 {
				continue
			}

			msg, err := parser.Parse(record.RawSample)
			if err != nil {
				log.Printf("error parsing record, err: %v\n", err)
				continue
			}

			// send the msg
			c.workChan <- msg
		}
	}
}

func (c *TcpIntClient) work(ctx context.Context, workChan chan *pb.TcpIntMsg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-workChan:
			// log.Printf("sending gRPC message: %+v \n", msg)
			_, err := c.client.CreateTcpIntMsgs(ctx, &pb.TcpIntMsgs{Msgs: []*pb.TcpIntMsg{msg}})
			if err != nil {
				log.Printf("error sending gRPC message, err: %v\n", err)
				continue
			}
		}
	}
}
