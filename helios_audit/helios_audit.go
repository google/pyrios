// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/pyrios"
)

func main() {
	var electionUuid = flag.String("uuid", "", "The uuid of the election to download")
	var heliosServer = flag.String("server", "https://vote.heliosvoting.org/helios/elections/", "The server to download the election from")
	var electionFile = flag.String("election", "", "The file to write the election into or to read it from")
	var ballotFile = flag.String("ballot", "", "The file containing the JSON for a ballot audit")
	var fingerprint = flag.String("fingerprint", "", "The ballot tracking number for this ballot")
	var download = flag.Bool("download", false, "Whether or not to download the election")
	var write = flag.Bool("write", true, "Whether or not to write the downloaded election to disk")
	flag.Parse()

	if *download && len(*electionUuid) == 0 {
		fmt.Fprintln(os.Stderr, "Must provide a UUID for downloading election information")
		return
	}

	if (!*download || *write) && len(*electionFile) == 0 {
		fmt.Fprintln(os.Stderr, "Must provide a election file name")
		return
	}

	if len(*ballotFile) == 0 {
		fmt.Fprintln(os.Stderr, "Must provide a ballot file name")
		return
	}

	var e pyrios.Election
	if *download {
		elecAddr := *heliosServer + *electionUuid
		electionJSON, err := pyrios.GetJSON(elecAddr, &e)
		if err != nil {
			panic(err)
		}

		e.Init(electionJSON)

		if *write {
			err = ioutil.WriteFile(*electionFile, electionJSON, 0644)
			if err != nil {
				panic(err)
			}
		}
	} else {
		electionJSON, err := ioutil.ReadFile(*electionFile)
		if err != nil {
			panic(err)
		}

		err = pyrios.UnmarshalJSON(electionJSON, &e)
		if err != nil {
			panic(err)
		}

		e.Init(electionJSON)
	}

	var b pyrios.Ballot
	ballotJSON, err := ioutil.ReadFile(*ballotFile)
	if err != nil {
		panic(err)
	}

	err = pyrios.UnmarshalJSON(ballotJSON, &b)
	if err != nil {
		panic(err)
	}

	if b.Audit(*fingerprint, ballotJSON, &e) {
		fmt.Println("The ballot passes verification")

		fmt.Println("The ballot was cast with the following values:")
		r := b.ExtractResult(&e)
		lr := e.LabelResults(r)
		fmt.Printf("%s", lr)
	} else {
		fmt.Fprintln(os.Stderr, "The election fails verification")
	}
}
