// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"bufio"
	"log"
	"os"
	"strconv"
)

var InitialTtl uint32

func init() {
	InitialTtl = ttlInitial()
}

func ttlInitial() uint32 {
	var init_ttl int
	//Reading default ttl from the server where exporter will be run
	f, err := os.Open("/proc/sys/net/ipv4/ip_default_ttl")
	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineStr := scanner.Text()
		num, _ := strconv.Atoi(lineStr)
		init_ttl = num
	}
	return uint32(init_ttl)
}
