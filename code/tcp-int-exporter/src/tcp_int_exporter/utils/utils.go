// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"net"
	"time"
)

const Layout = "2006-01-02T15:04:05.999999Z"

func ConvertDateTimeToMilliSec(t time.Time) int64 {
	return t.UnixNano() / int64(time.Millisecond)
}

func ConvertMilliSecToDateTime(milli int64) time.Time {
	return time.Unix(0, milli*int64(time.Millisecond))
}

func ConvertMicroSecToDateTime(milli int64) time.Time {
	return time.Unix(0, milli*int64(time.Microsecond))
}

func ConvertDateTimeToNanoSec(t time.Time) int64 {
	return t.UnixNano() / int64(time.Nanosecond)
}

func ConvertNanoSecToDateTime(milli int64) time.Time {
	return time.Unix(0, milli*int64(time.Nanosecond))
}

func NewInt64(x int64) *int64 {
	return &x
}

func NewUInt64(x uint64) *uint64 {
	return &x
}

func NewInt32(x int32) *int32 {
	return &x
}

func NewUInt32(x uint32) *uint32 {
	return &x
}

// GetIP returns either IPv4 or IPv6 base on the given input.
func GetIP(arr []byte, family uint32) net.IP {
	var ip net.IP
	if family == 2 {
		ip = net.IPv4(arr[0], arr[1], arr[2], arr[3])
	} else if family == 10 {
		ip = net.IP(arr)
	}
	return ip
}
