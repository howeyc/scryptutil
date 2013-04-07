// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"

	"code.google.com/p/go.crypto/scrypt"
	"github.com/howeyc/gopass"
	"github.com/howeyc/memstatus"
)

const (
	headerMagic   = "scrypt"
	headerVersion = 0
)

var (
	flagMaxTime    int64
	flagMaxMemFrac float64
	flagMaxMem     int64
)

type params struct {
	logN byte
	r, p int
	salt []byte
}

func deriveKeys(password []byte, p *params) (keyEnc, keyHmac []byte, err error) {
	N := int(1 << uint64(p.logN))
	k, err := scrypt.Key(password, p.salt, N, p.r, p.p, 64)
	if err != nil {
		return
	}
	keyEnc = k[0:32]
	keyHmac = k[32:64]
	return
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func askForPassword(confirm bool) (password []byte, err error) {
	for {
		fmt.Printf("Enter passphrase: ")
		password = gopass.GetPasswd()
		if err != nil {
			return
		}
		if !confirm {
			break
		}
		var confirmation []byte
		fmt.Printf("Confirm passphrase: ")
		confirmation = gopass.GetPasswd()
		if err != nil {
			return
		}
		if len(password) == 0 {
			fmt.Println("Empty password, please try again.")
			clearBytes(confirmation)
			continue
		}
		if bytes.Equal(password, confirmation) {
			clearBytes(confirmation)
			break
		}
		fmt.Println("Passphrases mismatch, please try again.")
		clearBytes(confirmation)
		clearBytes(password)
	}
	return
}

func usage() {
	fmt.Printf("Usage: %s {enc | dec} infile [outfile]\n", os.Args[0])
	os.Exit(1)
}

func main() {
	physmem, _ := memstatus.MemStatus()
	log.SetFlags(0)
	flag.Int64Var(&flagMaxTime, "t", 5, "maximum time in seconds to spend computing encryption key from password")
	flag.Float64Var(&flagMaxMemFrac, "m", 0.5, "fraction of memory to use for computing encryption key from password")
	flag.Int64Var(&flagMaxMem, "M", int64(physmem.Total), "maximum memory in bytes to use computing encryption key from password")
	flag.Parse()
	// Check arguments.
	if flag.NArg() < 2 || flag.Arg(0) != "enc" && flag.Arg(0) != "dec" && flag.Arg(0) != "info" {
		usage()
	}
	if flag.Arg(0) == "info" {
		in, err := os.Open(flag.Arg(1))
		if err != nil {
			log.Fatalf("%s", err)
		}
		e := displayInfo(in)
		if e != nil {
			log.Fatalf("%s", e)
		}
		in.Close()
		os.Exit(0)
	}
	// Ask for password.
	password, err := askForPassword(flag.Arg(0) == "enc")
	if err != nil {
		log.Fatalf("%s", err)
	}
	// Function fatal will clean password, output message and exit.
	fatal := func(msg string, args ...interface{}) {
		clearBytes(password)
		log.Fatalf(msg, args...)
	}
	// Defer cleaning of password for normal exit.
	defer func() {
		clearBytes(password)
	}()
	// Open input file.
	in, err := os.Open(flag.Arg(1))
	if err != nil {
		fatal("%s", err)
	}
	defer in.Close()
	// Open output file.
	var out *os.File
	if flag.NArg() < 3 {
		out = os.Stdout
	} else {
		out, err = os.Create(flag.Arg(2))
		if err != nil {
			fatal("create: %s", err)
		}
		defer func() {
			if err := out.Sync(); err != nil {
				log.Printf("fsync: %s", err)
			}
			if err := out.Close(); err != nil {
				fatal("close: %s", err)
			}
		}()
	}
	// Encrypt/decrypt.
	switch flag.Arg(0) {
	case "enc":
		if err := encrypt(in, out, password); err != nil {
			fatal("decrypt: %s", err)
		}
	case "dec":
		if err := decrypt(in, out, password); err != nil {
			fatal("decrypt: %s", err)
		}
	}
}
