// info
package main

import (
	"errors"
	"fmt"
	"io"
)

func displayInfo(r io.Reader) (err error) {
	// Read first 7 bytes of header.
	header := make([]byte, 96)
	if _, err := io.ReadFull(r, header[0:7]); err != nil {
		return err
	}
	// Check magic and version.
	if string(header[0:6]) != headerMagic {
		return errors.New("not an scrypt file")
	}
	if header[6] != headerVersion {
		return errors.New("unsupported scrypt version")
	}
	// Read the rest of the header.
	if _, err := io.ReadFull(r, header[7:]); err != nil {
		return err
	}

	p, err := parseHeader(header)
	if err != nil {
		return err
	}
	mac := header[64:96]
	fmt.Printf("Params: {N: %d, r: %d, p: %d}\nSalt: %v\nHMAC: %v\n", uint64(1)<<p.logN, p.r, p.p, p.salt, mac)
	return nil
}
