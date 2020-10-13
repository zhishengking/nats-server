// Copyright 2020 The NATS Authors
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

// +build !linux

package server

import (
	"errors"
	"net"
)

// These are empty but should exist so that they can be embedded in state
// structs so that we don't have heavy(ier) GC churn.
type TCPInfo struct{}
type TCPDiagnostics struct{}
type TCPInfoExpMetrics struct{}
type TCPInfoExpMaps struct{}

var ErrNotSupported = errors.New("error: operation not supported on this platform")

const PlatformCanGetSocketTCPInfo = false

// GetSocketTCPDiagnostics populates a TCPDiagnostics structure.
// The core of this relies upon a non-portable Linux-ism for returning a lot of
// data about a connected socket.
func GetSocketTCPDiagnostics(conn *net.TCPConn, diag *TCPDiagnostics) error {
	return ErrNotImplemented
}

func (m *TCPInfoExpMetrics) PopulateFromTCPDiagnostics(d *TCPDiagnostics, maps *TCPInfoExpMaps, fullLabel string) {
}

func NewTCPInfoExpMaps() *TCPInfoExpMaps {
	return &TCPInfoExpMaps{}
}

// There will be other functions here, as we populate maps.
