// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/binary"
	"fmt"
	//"log"
	pb "models/proto/exporter/go"
	"tcp_int/pkg/global"
	"tcp_int/utils"
)

const uint8Size = 1
const uint16size = 2
const uint32Size = 4
const uint64Size = 8

func Parse(data []byte) (*pb.TcpIntMsg, error) {
	timestampSize := uint64Size
	familySize := uint32Size
	sportSize := uint16size
	dportSize := uint16size
	saddrSize := 4 * uint32Size
	daddrSize := 4 * uint32Size
	cwndSize := uint32Size
	srttSize := uint32Size
	rateDeliveredSize := uint32Size
	rateIntervalSize := uint32Size
	mssSize := uint32Size
	hopLatSize := uint32Size
	returnHopLatSize := uint32Size
	intvalSize := uint8Size
	hopIdSize := uint8Size
	lostOutSize := uint32Size
	segsOutSize := uint32Size
	bytesAckedSize := uint64Size
	totalRetransSize := uint32Size

	perfEventSize := timestampSize + familySize + sportSize +
		dportSize + saddrSize + daddrSize + cwndSize +
		srttSize + rateDeliveredSize + rateIntervalSize +
		mssSize + hopLatSize + returnHopLatSize + intvalSize +
		hopIdSize + lostOutSize + segsOutSize + bytesAckedSize +
		totalRetransSize

	if len(data) < perfEventSize {
		return nil, fmt.Errorf("invalid data format: %v", data)
	}

	tsUs := data[0:timestampSize]
	offset := timestampSize
	family := utils.NewUInt32(binary.LittleEndian.Uint32(data[offset:(offset + familySize)]))
	offset = offset + familySize
	sport := binary.LittleEndian.Uint16(data[offset:(offset + sportSize)])
	offset = offset + sportSize
	dport := binary.LittleEndian.Uint16(data[offset:(offset + dportSize)])
	offset = offset + dportSize
	saddr := data[offset:(offset + saddrSize)]
	offset = offset + saddrSize
	daddr := data[offset:(offset + daddrSize)]
	offset = offset + daddrSize
	cwnd := binary.LittleEndian.Uint32(data[offset:(offset + cwndSize)])
	offset = offset + cwndSize
	srtt := binary.LittleEndian.Uint32(data[offset:(offset + srttSize)])
	offset = offset + srttSize
	rate := binary.LittleEndian.Uint32(data[offset:(offset + rateDeliveredSize)])
	offset = offset + rateDeliveredSize
	rateInterval := binary.LittleEndian.Uint32(data[offset:(offset + rateIntervalSize)])
	offset = offset + rateIntervalSize
	maxSegmentSize := binary.LittleEndian.Uint32(data[offset:(offset + mssSize)])
	offset = offset + mssSize
	lostOut := binary.LittleEndian.Uint32(data[offset:(offset + lostOutSize)])
	offset = offset + lostOutSize
	intVal := uint32(data[offset])
	offset = offset + intvalSize
	hopId := uint32(data[offset])
	offset = offset + hopIdSize
	hopLat := binary.LittleEndian.Uint32(data[offset:(offset + hopLatSize)])
	offset = offset + hopLatSize
	returnHopLat := binary.LittleEndian.Uint32(data[offset:(offset + returnHopLatSize)])
	offset = offset + returnHopLatSize
	segsOut := binary.LittleEndian.Uint32(data[offset:(offset + segsOutSize)])
	offset = offset + segsOutSize
	bytesAcked := binary.LittleEndian.Uint64(data[offset:(offset + bytesAckedSize)])
	offset = offset + bytesAckedSize
	totalRetrans := binary.LittleEndian.Uint32(data[offset:(offset + totalRetransSize)])
	msg := &pb.TcpIntMsg{
		TsUs:                 tsUs,
		Family:               family,
		SourcePort:           utils.NewUInt32(uint32(sport)),
		DestinationPort:      utils.NewUInt32(uint32(dport)),
		SourceIp:             utils.GetIP(saddr, *family).String(),
		DestinationIp:        utils.GetIP(daddr, *family).String(),
		CongestionWindow:     cwnd * maxSegmentSize,
		RoundTripTime:        srtt >> 3 * 1000,
		Rate:                 rate,
		RateInterval:         rateInterval,
		MaxSegmentSize:       maxSegmentSize,
		IntValue:             intVal,
		FinalTtl:             utils.NewUInt32(hopId),
		LatenciesOutgoingSum: hopLat * (1 << 8),
		LatenciesReturnSum:   returnHopLat * (1 << 8),
		QueueDepth:           parseQueueDepth(intVal),
		Bandwidth:            parseBandwidthMBPS(rate, rateInterval, maxSegmentSize),
		Utilization:          parseUtilizationPercentage(intVal),
		InitialTtl:           utils.NewUInt32(global.InitialTtl),
		LostOut:              lostOut,
		SegsOut:              segsOut,
		BytesAcked:           bytesAcked,
		TotalRetrans:         totalRetrans,
		HopId:                utils.NewUInt32(hopId),
	}

	//log.Printf("msg: %+v \n", msg)
	return msg, nil
}

func parseQueueDepth(intValue uint32) uint32 {
	var qd uint32
	if intValue >= 0x80 {
		qd = ((intValue & 0x7f) << 13)
	} else {
		qd = 0
	}
	return qd
}

func parseBandwidthMBPS(rate, rateInterval, maxSegmentSize uint32) uint32 {
	var bw uint32
	if rateInterval != 0 {
		bw = rate * maxSegmentSize / rateInterval
	}
	return bw
}

func parseUtilizationPercentage(intValue uint32) float64 {
	var ut float64
	if intValue >= 0x80 {
		ut = float64(100)
	} else {
		ut = float64(intValue << 3)
	}
	return ut
}
