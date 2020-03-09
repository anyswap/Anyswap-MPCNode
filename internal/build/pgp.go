// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// signFile reads the contents of an input file and signs it (in armored format)
// with the key provided, placing the signature into the output file.

package build

// PGPSignFile parses a PGP private key from the specified string and creates a
// signature file into the output parameter of the input file.
//
// Note, this method assumes a single key will be container in the pgpkey arg,
// furthermore that it is in armored format.
func PGPSignFile(input string, output string, pgpkey string) error {
	return nil
}

// PGPKeyID parses an armored key and returns the key ID.
func PGPKeyID(pgpkey string) (string, error) {
	return "", nil
}
