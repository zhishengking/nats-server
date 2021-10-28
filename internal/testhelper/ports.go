// Copyright 2021 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testhelper

// We want to safely run tests without conflicts, and possibly even have
// concurrent test runs in the same network namespace.
// This logic provides for a GetNextPort() to assist in that.

import (
	"net"
	"sync/atomic"
	"testing"
)

var (
	// These are uint32 for ease of atomic checks, even though the real value is constrained to be uint16
	latestIssuedPort uint32
	basePort         uint32

	baseReservation *net.TCPListener
)

var disallowedPorts map[uint32]struct{}

func init() {
	disallowedPorts = map[uint32]struct{}{
		4222: struct{}{},
		6222: struct{}{},
		8000: struct{}{},
		8080: struct{}{},
		8222: struct{}{},
	}
}

// HoldBasePort should be called by TestMain, to select a base port for tests.
// TODO: should we have OS-specific dumps of currently listening ports in this
// namespace, to augment disallowedPorts?
func HoldBasePort(m *testing.M) {
	for base := uint32(2000); base <= 16_000; base += 1000 {
		l, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: int(base)})
		if err != nil {
			continue
		}
		basePort = base
		latestIssuedPort = base
		// keep it from being GC'd
		baseReservation = l
		return
	}
	panic("unable to get a base port locked")
}

// GetNextPortUint16 returns a port number which we haven't previously allocated.
// TODO: should we taste the port to confirm?
func GetNextPortUint16() uint16 {
	p := atomic.AddUint32(&latestIssuedPort, 1)
	if p <= 1 {
		panic("HoldBasePort not called")
	}
	if p > 0xFFFF {
		panic("port overflow")
	}
	if _, ok := disallowedPorts[p]; ok {
		return GetNextPortUint16()
	}
	return uint16(p)
}

// GetNextPortInt is a convenience for callers who need ints, not uint16
func GetNextPortInt() int {
	return int(GetNextPortUint16())
}

// GetBasePortInt is perhaps useful for diagnostics
func GetBasePortInt() int {
	return int(basePort)
}

// GetBaseReservation exists purely to silence staticcheck about the listener we keep around as a process-level lock on our range.
func GetBaseReservation() *net.TCPListener {
	return baseReservation
}
