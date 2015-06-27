// Copyright 2012 Chris Howey. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"time"

	"golang.org/x/crypto/scrypt"
)

func getParams() (logN uint, r, p int) {
	opsPerSecond := 0
	startTime := time.Now()
	for time.Since(startTime).Seconds() < 2 {
		scrypt.Key([]byte("pass"), []byte("salt"), 128, 1, 1, 64)
		opsPerSecond += 512
	}
	opslimit := opsPerSecond * int(flagMaxTime)

	if opslimit < 32768 {
		opslimit = 32768
	}

	memlimit := int(flagMaxMemFrac * float64(flagMaxMem))

	r = 8

	/*
	 * The memory limit requires that 128Nr <= memlimit, while the CPU
	 * limit requires that 4Nrp <= opslimit.  If opslimit < memlimit/32,
	 * opslimit imposes the stronger limit on N.
	 */
	if opslimit < memlimit/32 {
		p = 1
		maxN := opslimit / (r * 4)
		for logN = uint(1); logN < 63; logN += 1 {
			if 1<<logN > maxN/2 {
				break
			}
		}
	} else {
		/* Set N based on the memory limit. */
		maxN := memlimit / (r * 128)
		for logN = uint(1); logN < 63; logN += 1 {
			if 1<<logN > maxN/2 {
				break
			}
		}

		/* Choose p based on the CPU limit. */
		maxrp := uint(opslimit/4) / (uint(1) << logN)
		if maxrp > 0x3fffffff {
			maxrp = 0x3fffffff
		}
		p = int(maxrp / uint(r))
	}
	return
}
