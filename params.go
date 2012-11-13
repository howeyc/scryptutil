// Copyright 2012 Chris Howey. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"code.google.com/p/go.crypto/scrypt"
	"time"
)

/* Choose N based on the CPU limit. */
func getlogN() uint {
	opsPerSecond := 0
	startTime := time.Now()
	for time.Since(startTime).Seconds() < 2 {
		scrypt.Key([]byte("pass"), []byte("salt"), 128, 1, 1, 64)
		opsPerSecond += 512
	}
	opslimit := opsPerSecond * 3

	if opslimit < 32768 {
		opslimit = 32768
	}

	r := 8
	var logN uint

	maxN := opslimit / (r * 4)
	for logN = uint(1); logN < 63; logN += 1 {
		if 1<<logN > maxN/2 {
			break
		}
	}
	return logN
}
