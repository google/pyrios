Pyrios
======

Pyrios is a Go library that implements verification of
[Helios](https://vote.heliosvoting.org) elections, following the [Helios v3
verification spec](http://documentation.heliosvoting.org)

Helios is a cryptographic election system used by the [International
Association of Cryptologic Research](http://www.iacr.org) and the
[ACM](http://www.acm.org) for elections. See the [IACR elections
page](http://www.iacr.org/elections/eVoting/about-helios.html) and the [ACM
elections page](http://www.acm.org/acmelections) for details.  Elections in
Helios use cryptography to protect ballots and enable public verifiability:
anyone can check that the results of an election were computed correctly.

Election Verification
---------------------

Helios elections are identified by a UUID, like
`43a30b30-04d8-11e1-8fc9-12313f028a58`; the URL for this election is then
https://vote.heliosvoting.org/helios/elections/43a30b30-04d8-11e1-8fc9-12313f028a58.
The program `helios_verify` can be used to verify elections; for this election,
you can run the command.

    helios_verify -verify -uuid=43a30b30-04d8-11e1-8fc9-12313f028a58 -write=false -logtostderr

The `helios_verify` program can also download an entire election and all its
associated verification information as a single JSON bundle to be verified
later. This is the default behavior if the `-write=false` argument is not
provided.

Note that pyrios exploits Go concurrency for ballot verification, so the
verification of large elections can be sped up significantly by setting
`GOMAXPROCS` to the number of available CPUs on the machine, e.g.,

    export GOMAXPROCS=32

Ballot Audit
------------

Helios ballots can be spoiled at voting time; these ballots are not cast and are
only used to make sure the Helios voting booth is encrypting ballots correctly.
A spoiled ballot is provided to the user as a JSON file. Given such a JSON file,
called `test_audit.json`, you need the fingerprint of the ballot (provided by
the voting booth) and the UUID of the election. Then you can verify this ballot
as follows.

    helios_audit -ballot=test_audit.json -uuid=b36cbf0c-250a-11e3-89f4-46d2afa631be -download=true -fingerprint=3HknRw5qRLzxs6UQ1XpE8TQznEbN0t8LtISLSPArCj0 -write=false -logtostderr
