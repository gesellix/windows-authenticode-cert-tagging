// Copyright 2015 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ========================================================================
//
// Program certificate_tag manipulates "tags" in Authenticode-signed
// Windows binaries.
//
// Traditionally we have inserted tag data after the PKCS#7 blob in the file
// (called an "appended tag" here). This area is not hashed in when checking
// the signature so we can alter it at serving time without invalidating the
// Authenticode signature.
//
// However, Microsoft are changing the verification function to forbid that so
// this tool also handles "superfluous certificate" tags. These are dummy
// certificates, inserted into the PKCS#7 certificate chain, that can contain
// arbitrary data in extensions. Since they are also not hashed when verifying
// signatures, that data can also be changed without invalidating it.
//
// The tool supports PE32 exe files and MSI files.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/gesellix/windows-authenticode-cert-tagging/pkg"
	"io/ioutil"
	"os"
	"strings"
)

var (
	dumpAppendedTag       *bool   = flag.Bool("dump-appended-tag", false, "If set, any appended tag is dumped to stdout.")
	removeAppendedTag     *bool   = flag.Bool("remove-appended-tag", false, "If set, any appended tag is removed and the binary rewritten.")
	loadAppendedTag       *string = flag.String("load-appended-tag", "", "If set, this flag contains a filename from which the contents of the appended tag will be saved")
	setSuperfluousCertTag *string = flag.String("set-superfluous-cert-tag", "", "If set, this flag contains a string and a superfluous certificate tag with that value will be set and the binary rewritten. If the string begins with '0x' then it will be interpreted as hex")
	paddedLength          *int    = flag.Int("padded-length", 0, "A superfluous cert tag will be padded with zeros to at least this number of bytes")
	savePKCS7             *string = flag.String("save-pkcs7", "", "If set to a filename, the PKCS7 data from the original binary will be written to that file.")
	outFilename           *string = flag.String("out", "", "If set, the updated binary is written to this file. Otherwise the binary is updated in place.")
	printTagDetails       *bool   = flag.Bool("print-tag-details", false, "IF set, print to stdout the location and size of the superfluous cert's Gact2.0 marker plus buffer.")
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] binary.exe\n", os.Args[0])
		os.Exit(255)
	}
	inFilename := args[0]
	if len(*outFilename) == 0 {
		outFilename = &inFilename
	}

	contents, err := ioutil.ReadFile(inFilename)
	if err != nil {
		panic(err)
	}

	bin, err := pkg.NewBinary(contents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	var finalContents []byte
	didSomething := false

	if len(*savePKCS7) > 0 {
		if err := ioutil.WriteFile(*savePKCS7, bin.Asn1Data(), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error while writing file: %s\n", err)
			os.Exit(1)
		}
		didSomething = true
	}

	if *dumpAppendedTag {
		appendedTag, ok := bin.AppendedTag()
		if !ok {
			fmt.Fprintf(os.Stderr, "No appended tag found\n")
		} else {
			os.Stdout.WriteString(hex.Dump(appendedTag))
		}
		didSomething = true
	}

	if *removeAppendedTag {
		contents, err := bin.RemoveAppendedTag()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while removing appended tag: %s\n", err)
			os.Exit(1)
		}
		if err := ioutil.WriteFile(*outFilename, contents, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error while writing updated file: %s\n", err)
			os.Exit(1)
		}
		finalContents = contents
		didSomething = true
	}

	if len(*loadAppendedTag) > 0 {
		tagContents, err := ioutil.ReadFile(*loadAppendedTag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while reading file: %s\n", err)
			os.Exit(1)
		}
		contents, err := bin.SetAppendedTag(tagContents)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while setting appended tag: %s\n", err)
			os.Exit(1)
		}
		if err := ioutil.WriteFile(*outFilename, contents, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error while writing updated file: %s\n", err)
			os.Exit(1)
		}
		finalContents = contents
		didSomething = true
	}

	if len(*setSuperfluousCertTag) > 0 {
		var tagContents []byte

		if strings.HasPrefix(*setSuperfluousCertTag, "0x") {
			tagContents, err = hex.DecodeString((*setSuperfluousCertTag)[2:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse tag contents from command line: %s\n", err)
				os.Exit(1)
			}
		} else {
			tagContents = []byte(*setSuperfluousCertTag)
		}

		for len(tagContents) < *paddedLength {
			tagContents = append(tagContents, 0)
		}
		// print-tag-details only works if the length requires 2 bytes to specify. (The length bytes
		// length is part of the search string.)
		// Lorry only tags properly (aside from tag-in-zip) if the length is 8206 or more. b/173139534
		// Omaha may or may not have a practical buffer size limit; 8206 is known to work.
		if len(tagContents) < 0x100 || len(tagContents) > 0xffff {
			fmt.Fprintf(os.Stderr, "Want final tag length in range [256, 65535], got %d\n", len(tagContents))
			os.Exit(1)
		}

		contents, err := bin.SetSuperfluousCertTag(tagContents)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while setting superfluous certificate tag: %s\n", err)
			os.Exit(1)
		}
		if err := ioutil.WriteFile(*outFilename, contents, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error while writing updated file: %s\n", err)
			os.Exit(1)
		}
		finalContents = contents
		didSomething = true
	}

	if *printTagDetails {
		if finalContents == nil {
			// Re-read the input, as NewBinary() may modify it.
			finalContents, err = ioutil.ReadFile(inFilename)
			if err != nil {
				panic(err)
			}
		}
		offset, length, err := pkg.FindTag(finalContents, bin.CertificateOffset())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while searching for tag in file bytes: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Omaha Tag offset, length: (%d, %d)\n", offset, length)
		didSomething = true
	}

	if !didSomething {
		// By default, print basic information.
		appendedTag, ok := bin.AppendedTag()
		if !ok {
			fmt.Printf("No appended tag\n")
		} else {
			fmt.Printf("Appended tag included, %d bytes\n", len(appendedTag))
		}
	}
}
