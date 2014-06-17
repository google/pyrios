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
	"io/ioutil"

	"code.google.com/p/pyrios"
	"github.com/golang/glog"
)

func main() {
	var electionUuid = flag.String("uuid", "", "The uuid of the election to download")
	var heliosServer = flag.String("server", "https://vote.heliosvoting.org/helios/elections/", "The server to download the election from")
	var electionFile = flag.String("election", "", "The file to write the election into or to read it from")
	var ballotFile = flag.String("ballot", "", "The file containing the JSON for a ballot audit")
	var fingerprint = flag.String("fingerprint", "", "The ballot tracking number for this ballot")
	var download = flag.Bool("download", false, "Whether or not to download the bundle")
	flag.Parse()

	if *download && len(*electionUuid) == 0 {
		glog.Fatal("Must provide a UUID for downloading election information")
	}

	if len(*electionFile) == 0 {
		glog.Fatal("Must provide a election file name")
	}

	if len(*ballotFile) == 0 {
		glog.Fatal("Must provide a ballot file name")
	}

	var e pyrios.Election
	if *download {
		elecAddr := *heliosServer + *electionUuid
		electionJSON, err := pyrios.GetJSON(elecAddr, &e)
		if err != nil {
			panic(err)
		}

		e.Init(electionJSON)

		err = ioutil.WriteFile(*electionFile, electionJSON, 0644)
		if err != nil {
			panic(err)
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
		glog.Info("The ballot passes verification")

		glog.Infof("The ballot was cast with the following values:\n")
		r := b.ExtractResult(&e)
		lr := e.LabelResults(r)
		glog.Infof("\n%s", lr)
	} else {
		glog.Fatal("The election fails verification")
	}
}
