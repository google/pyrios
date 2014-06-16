package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"

	"code.google.com/p/pyrios"
	"github.com/golang/glog"
)

func main() {
	var electionUuid = flag.String("uuid", "", "The uuid of the election to download")
	var heliosServer = flag.String("server", "https://vote.heliosvoting.org/helios/elections/", "The server to download the election from")
	var bundleFile = flag.String("bundle", "", "The file to write the bundle into")
	var download = flag.Bool("download", true, "Whether or not to download the bundle")
	var verify = flag.Bool("verify", false, "Whether or not to verify the downloaded bundle")
	flag.Parse()

	if len(*electionUuid) == 0 {
		glog.Fatal("Must provide an election uuid")
	}

	if len(*bundleFile) == 0 {
		glog.Fatal("Must provide a bundle file name")
	}

	var b *pyrios.ElectionBundle
	var err error
	if *download {
		b, err = pyrios.Download(*heliosServer, *electionUuid)
		if err != nil {
			panic(err)
		}

		serialized, err := json.Marshal(b)
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(*bundleFile, serialized, 0644)
		if err != nil {
			panic(err)
		}
	} else {
		serialized, err := ioutil.ReadFile(*bundleFile)
		if err != nil {
			panic(err)
		}

		b = new(pyrios.ElectionBundle)
		err = pyrios.UnmarshalJSON(serialized, b)
		if err != nil {
			panic(err)
		}

		if err = b.Instantiate(); err != nil {
			panic(err)
		}
	}

	if *verify {
		if b.Verify() {
			glog.Info("The election passes verification")

			glog.Infof("The results are as follows:\n")
			lr := b.Election.LabelResults(b.Results)
			glog.Infof("\n%s", lr)
		} else {
			glog.Fatal("The election fails verification")
		}
	}
}
