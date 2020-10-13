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

package server

import (
	"expvar"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type TCPInfo = syscall.TCPInfo

type TCPDiagnostics struct {
	Info       TCPInfo
	UnreadData uint32
	UnsentData uint32
}

const PlatformCanGetSocketTCPInfo = true

// GetSocketTCPDiagnostics relies upon a non-portable Linux-ism for returning a
// lot of data about a connected socket.
// We expect this to be called routinely, so we expect the caller to provide
// the existing memory object to be written to.
func GetSocketTCPDiagnostics(conn *net.TCPConn, diag *TCPDiagnostics) error {
	if conn == nil {
		return fmt.Errorf("GetSocketTCPDiagnostics: %w", ErrConnectionClosed)
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("GetSocketTCPDiagnostics: %w", err)
	}

	*diag = TCPDiagnostics{}
	infoSize := syscall.SizeofTCPInfo

	err = nil
	rawConn.Control(func(fd uintptr) {
		sysErr := syscall.Errno(0)
		ret := uintptr(0)
		for sysErr == 0 || sysErr == syscall.EINTR {
			_, _, sysErr = syscall.Syscall6(
				syscall.SYS_GETSOCKOPT, fd,
				syscall.SOL_TCP, syscall.TCP_INFO,
				uintptr(unsafe.Pointer(&diag.Info)), uintptr(unsafe.Pointer(&infoSize)),
				0)
		}
		if sysErr != 0 {
			err = fmt.Errorf("GetSocketTCPDiagnostics: getsockopt(TCP_INFO) failed: %w", sysErr)
			return
		}
		for sysErr == 0 || sysErr == syscall.EINTR {
			ret, _, sysErr = syscall.Syscall(syscall.SYS_IOCTL, fd, unix.SIOCINQ, 0)
		}
		if sysErr != 0 {
			err = fmt.Errorf("GetSocketTCPDiagnostics: getsockopt(SIOCINQ) failed: %w", sysErr)
			return
		}
		diag.UnreadData = uint32(ret)

		for sysErr == 0 || sysErr == syscall.EINTR {
			ret, _, sysErr = syscall.Syscall(syscall.SYS_IOCTL, fd, unix.SIOCOUTQ, 0)
		}
		if sysErr != 0 {
			err = fmt.Errorf("GetSocketTCPDiagnostics: getsockopt(SIOCOUTQ) failed: %w", sysErr)
			return
		}
		diag.UnsentData = uint32(ret)
	})

	if err != nil {
		return err
	}

	return nil
}

type TCPInfoExpMetrics struct {
	// nb: the Golang syscall/ztypes_linux_amd64.go stops at Total_retrans
	// So we miss out on things like tcpi_notsent_bytes
	UnreadData          expvar.Int
	UnsentData          expvar.Int
	UnAckedPackets      expvar.Int
	LostPackets         expvar.Int
	RetransOutPackets   expvar.Int
	TotalRetransPackets expvar.Int
	PathMTU             expvar.Int
	LastDataSentMSec    expvar.Int // result of jiffies_to_msecs(), now-timestamp
	LastDataRecvMSec    expvar.Int // result of jiffies_to_msecs(), now-timestamp
	RTT                 expvar.Int
	RTTVariance         expvar.Int
}

func (m *TCPInfoExpMetrics) PopulateFromTCPDiagnostics(d *TCPDiagnostics) {
	m.UnreadData.Set(int64(d.UnreadData))
	m.UnsentData.Set(int64(d.UnsentData))
	m.UnAckedPackets.Set(int64(d.Info.Unacked))
	m.LostPackets.Set(int64(d.Info.Lost))
	m.RetransOutPackets.Set(int64(d.Info.Retrans))
	m.TotalRetransPackets.Set(int64(d.Info.Total_retrans))
	m.PathMTU.Set(int64(d.Info.Pmtu))
	m.LastDataSentMSec.Set(int64(d.Info.Last_data_sent))
	m.LastDataRecvMSec.Set(int64(d.Info.Last_data_recv))
	m.RTT.Set(int64(d.Info.Rtt))
	m.RTTVariance.Set(int64(d.Info.Rttvar))
}
