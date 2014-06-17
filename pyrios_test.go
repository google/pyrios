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

package pyrios

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"testing/quick"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/golang/glog"
)

// heliosServer is the fixed address of the Helios voting server.
var heliosServer = "https://vote.heliosvoting.org/helios/elections/"

// The following uuid is a simple test election on the helios server.

// electionUuid is the unique identifier for the election
var electionUuid = "43a30b30-04d8-11e1-8fc9-12313f028a58"

// A set of parameters to use when we don't want to generate keys, e.g., for
// short tests. These parameters are taken from exisiting Helios elections,
// and the length of the exponent prime makes this different from the DSA-based
// parameters we otherwise generate.
var quickGenerator = "14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533"
var quickPrime = "16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071"
var quickExponentPrime = "61329566248342901292543872769978950870633559608669337131139375508370458778917"

func TestQuestionCreation(t *testing.T) {
	answers := make([]string, 3)
	answers[0] = "yes"
	answers[1] = "no"
	answers[2] = "maybe so"
	var q Question
	if err := q.Create(answers, 2, 1, "Which is it?", "absolute", "Test Q"); err != nil {
		t.Error("Couldn't create a question")
	}

	return
}

func instantiateQuickParams() (*big.Int, *big.Int, *big.Int, error) {
	var g, p, q big.Int
	if _, success := g.SetString(quickGenerator, 10); !success {
		return nil, nil, nil, errors.New("couldn't create a bignum from the quick generator string")
	}

	if _, success := p.SetString(quickPrime, 10); !success {
		return nil, nil, nil, errors.New("couldn't create a bignum from the quick prime string")
	}

	if _, success := q.SetString(quickExponentPrime, 10); !success {
		return nil, nil, nil, errors.New("couldn't create a bignum from the quick exponent prime string")
	}

	return &g, &p, &q, nil
}

func TestKeyCreation(t *testing.T) {
	var k Key
	var secret *big.Int
	var err error
	if testing.Short() {
		g, p, q, err := instantiateQuickParams()
		if err != nil {
			t.Error(err)
		}

		secret, err = k.CreateFromParams(g, p, q)
	} else {
		secret, err = k.Create()
	}

	if err != nil {
		t.Error("Couldn't create a key from a given parameter set")
	}

	if secret == nil || secret.BitLen() == 0 {
		t.Error("Didn't create a valid secret")
	}
	return
}

// perm64 returns, as a slice of n int64s, a pseudo-random permutation of the
// integers [0,n). This code is derived from the implementation of rand.Perm.
func perm64(r *rand.Rand, n int) []int64 {
	m := make([]int64, n)
	for i := 0; i < n; i++ {
		m[i] = int64(i)
	}
	for i := 0; i < n; i++ {
		j := r.Intn(i + 1)
		m[i], m[j] = m[j], m[i]
	}
	return m
}

func normalMod(val, modulus int) int {
	realVal := val % modulus
	if realVal < 0 {
		realVal = -realVal
	}

	realVal++
	return realVal
}

func TestRandomElection(t *testing.T) {

	var innerErr error
	f := func(voterCount, ballotCount, auditCount, questionCount, answerLimit, maxStrLen, trusteeLimit int) bool {
		realVoterCount := normalMod(voterCount, 50)
		realBallotCount := normalMod(ballotCount, realVoterCount)
		realAuditCount := normalMod(auditCount, realBallotCount)
		realQuestionCount := normalMod(questionCount, 10)
		realAnswerLimit := normalMod(answerLimit, 5)
		realMaxStrLen := normalMod(maxStrLen, 20)
		realTrusteeLimit := normalMod(trusteeLimit, 3)

		_, innerErr = createFakeBundle(realVoterCount, realBallotCount, realAuditCount, realQuestionCount,
			realAnswerLimit, realMaxStrLen, realTrusteeLimit)
		return innerErr == nil
	}

	testCount := 10
	if testing.Short() {
		testCount = 1
	}

	conf := &quick.Config{testCount, 0, rand.New(rand.NewSource(time.Now().UnixNano())), nil}
	if err := quick.Check(f, conf); err != nil {
		t.Error("The election didn't pass verification: ", innerErr)
	}
}

func createRandomQuestions(r *rand.Rand, questionCount, answerLimit, maxStrLen int) ([]Question, error) {
	// Create the questions and answers.
	questions := make([]Question, questionCount)
	for i := range questions {
		// From 1 to answerLimit answers
		answerCount := r.Intn(answerLimit) + 1
		answers := make([]string, answerCount)
		for j := range answers {
			strLen := r.Intn(maxStrLen) + 1
			answers[j] = randomString(strLen, r)
		}

		// min ranges from 0 to answerCount
		min := r.Intn(answerCount + 1)

		// max ranges from min to answerCount
		max := r.Intn(answerCount-min+1) + min

		questionLen := r.Intn(maxStrLen) + 1
		shortLen := r.Intn(maxStrLen) + 1
		if err := questions[i].Create(answers, max, min, randomString(questionLen, r),
			"absolute", randomString(shortLen, r)); err != nil {
			return nil, err
		}
	}

	return questions, nil
}

func createRandomVoters(r *rand.Rand, voterCount, maxStrLen int) ([]Voter, error) {
	// Create the voters.
	voters := make([]Voter, voterCount)
	coin := ((r.Intn(2) % 2) == 0)
	for i := range voters {
		nameLen := r.Intn(maxStrLen) + 1
		emailLen := r.Intn(maxStrLen) + 1
		voterHash := ""
		if !coin {
			hashLen := r.Intn(maxStrLen) + 1
			voterHash = randomString(hashLen, r)
		}
		if err := voters[i].Create(randomString(nameLen, r), randomString(emailLen, r),
			coin, voterHash, "email"); err != nil {
			return nil, err
		}

		glog.Infof("Created voter with uuid %s\n", voters[i].Uuid)
	}

	return voters, nil
}

func createRandomElection(r *rand.Rand, maxStrLen int, voters []Voter, questions []Question) (*Election, *big.Int, error) {
	// Create the election.
	e := new(Election)
	urlLen := r.Intn(maxStrLen) + 1
	url := randomString(urlLen, r)

	electionDescLen := r.Intn(maxStrLen) + 1
	electionDesc := randomString(electionDescLen, r)

	frozenAt := time.Now().String()

	electionNameLen := r.Intn(maxStrLen) + 1
	electionName := randomString(electionNameLen, r)

	openreg := ((r.Intn(2) % 2) == 0)

	shortNameLen := r.Intn(maxStrLen) + 1
	shortName := randomString(shortNameLen, r)

	votersJSON, err := MarshalJSON(&voters)
	if err != nil {
		return nil, nil, err
	}

	h := sha256.Sum256(votersJSON)
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	votersHash := encodedHash[:len(encodedHash)-1]

	votingStarts := time.Now().String()
	votingEnds := time.Now().String()

	var pk *Key
	if testing.Short() {
		var g, p, q *big.Int
		g, p, q, err = instantiateQuickParams()
		if err != nil {
			return nil, nil, err
		}

		pk = new(Key)
		pk.Generator = *g
		pk.Prime = *p
		pk.ExponentPrime = *q
	}

	secret, err := e.Create(url, electionDesc, frozenAt, electionName, openreg,
		questions, shortName, false, votersHash, votingEnds, votingStarts, pk)
	if err != nil {
		return nil, nil, err
	}

	return e, secret, nil
}

func createRandomBallots(r *rand.Rand, voterCount, ballotCount, auditCount int, voters []Voter, questions []Question, e *Election) ([]CastBallot, [][]int64, error) {
	// Create the ballots.
	// Choose a random subset of size ballotCount out of voterCount entries
	ballotIndices := r.Perm(voterCount)[:ballotCount]
	votes := make([]CastBallot, len(ballotIndices))

	// Initialize a tally structure to keep track of the actual votes for later comparison.
	tally := make([][]int64, len(questions))
	for i := range questions {
		q := &questions[i]
		tally[i] = make([]int64, len(q.Answers))
	}

	// Audit a random subset of the ballots.
	auditIndices := r.Perm(ballotCount)[:auditCount]
	ballotAuditRequired := make([]bool, len(ballotIndices))
	for _, i := range auditIndices {
		ballotAuditRequired[i] = true
	}

	resp := make(chan error)
	for k, i := range ballotIndices {
		// Use shadowing to create unique variables for the goroutine.
		k := k
		i := i
		go func(c chan error) {
			v := &voters[i]
			glog.Infof("Voter with uuid %s cast a vote\n", v.Uuid)
			answers := make([][]int64, len(questions))

			// Answer the questions.
			for j := range questions {
				q := &questions[j]
				// If both max and min are 0, then choose a random number of answers
				// with a count in [0, len(q.Answers)]
				// Otherwise, choose a random number of answers with a count in [q.Min, q.Max].
				min := q.Min
				max := q.ComputeMax()

				answersCount := r.Intn(max-min+1) + min
				answers[j] = perm64(r, len(q.Answers))[:answersCount]
				for _, a := range answers[j] {
					tally[j][a]++
				}
			}

			if ballotAuditRequired[k] {
				// Create a spoiled ballot and audit it before
				// creating the real ballot.
				var cb CastBallot
				if err := cb.Create(e, answers, v, true /* save audit info */); err != nil {
					c <- err
					return
				}

				// Recompute the JSON for this Ballot, since it's not saved in the structure.
				serializedVote, err := MarshalJSON(&cb.Vote)
				if err != nil {
					c <- err
					return
				}

				if !cb.Vote.Audit(cb.VoteHash, serializedVote, e) {
					c <- errors.New("a ballot failed its audit")
					return
				}
			}

			c <- votes[k].Create(e, answers, v, false /* don't save audit info */)
			return
		}(resp)
	}

	// Wait for the all the ballots to be cast.
	for _ = range ballotIndices {
		if err := <-resp; err != nil {
			return nil, nil, err
		}
	}

	return votes, tally, nil
}

func marshalBundle(e *Election, voters []Voter, votes []CastBallot, results [][]int64, trustees []Trustee) (*ElectionBundle, error) {
	// Create the bundle.
	b := new(ElectionBundle)
	var err error
	if b.ElectionData, err = MarshalJSON(e); err != nil {
		return nil, err
	}

	// VotersData is a list of json-encoded []Voter structures. So, it is marshalled
	// in slices for the bundle.
	listLen := 100
	cur := 0
	for cur < len(voters) {
		end := cur + listLen
		if end > len(voters) {
			end = len(voters)
		}

		slice := voters[cur:end]
		cur = end
		var temp []byte
		if temp, err = MarshalJSON(&slice); err != nil {
			return nil, err
		}

		b.VotersData = append(b.VotersData, temp)
	}

	b.VotesData = make([][]byte, len(votes))
	for i := range votes {
		if b.VotesData[i], err = MarshalJSON(&votes[i]); err != nil {
			return nil, err
		}
	}

	if b.ResultsData, err = MarshalJSON(&results); err != nil {
		return nil, err
	}

	if b.TrusteesData, err = MarshalJSON(&trustees); err != nil {
		return nil, err
	}

	return b, nil
}

func createSingleBallot(r *rand.Rand) (*Election, []CastBallot, error) {
	maxStrLen := 10
	questions, err := createRandomQuestions(r, 1, 2, maxStrLen)
	if err != nil {
		return nil, nil, err
	}

	voters, err := createRandomVoters(r, 1, maxStrLen)
	if err != nil {
		return nil, nil, err
	}

	e, _, err := createRandomElection(r, maxStrLen, voters, questions)
	if err != nil {
		return nil, nil, err
	}

	votes, _, err := createRandomBallots(r, 1, 1, 0, voters, questions, e)
	if err != nil {
		return nil, nil, err
	}

	return e, votes, nil
}

func corruptInteger(r *rand.Rand, i *big.Int) {
	bitLen := i.BitLen()
	s := r.Intn(bitLen)
	c := r.Intn(bitLen-s) + 1
	for j := s; j < s+c; j++ {
		b := uint(r.Intn(2))
		i.SetBit(i, j, b)
	}
}

func TestCorruptedDecryptionProofA(t *testing.T) {
	// Create a tiny election to check: one voter, one ballot, one
	// question, one trustee.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	corruptInteger(r, &b.Trustees[0].DecryptionProofs[0][0].Commitment.A)
	if b.Verify() {
		t.Error("A corrupted bundle still passes verification")
	}
}

func TestCorruptedDecryptionProofB(t *testing.T) {
	// Create a second tiny election to check: one voter, one ballot, one
	// question, one trustee.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	corruptInteger(r, &b.Trustees[0].DecryptionProofs[0][0].Commitment.B)
	if b.Verify() {
		t.Error("A corrupted bundle still passes verification")
	}
}

func TestCorruptedDecryptionProofBadHash(t *testing.T) {
	// Finally, to test the case where the proofs pass but the hash doesn't match,
	// try the case where A = 1, B = 1, response = 0, and challenge = 0. This leads
	// to 1 == 1, so it passes verification. But the hash then doesn't work.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	d := &b.Trustees[0].DecryptionProofs[0][0]
	d.Challenge.SetInt64(0)
	d.Response.SetInt64(0)
	d.Commitment.A.SetInt64(1)
	d.Commitment.B.SetInt64(1)
	if b.Verify() {
		t.Error("A corrupted bundle still passes verification")
	}
}

func TestCorruptedRetallyResults(t *testing.T) {
	// Try with the wrong number of results.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	// Wrong number of questions.
	fakeResults := [][]int64{{1, 2, 3, 4, 5}, {2, 3, 4, 5, 6}, {3, 4, 5, 6, 7}}
	if b.Election.Retally(b.Votes, fakeResults, b.Trustees) {
		t.Error("The wrong results passed a retally")
	}

	// Wrong number of results.
	fakeResults = [][]int64{{1, 2, 3, 4, 5}}
	if b.Election.Retally(b.Votes, fakeResults, b.Trustees) {
		t.Error("The wrong results passed a retally")
	}

	// Wrong individual result.
	b.Results[0][0] = 200
	if b.Verify() {
		t.Error("A bundle with an incorrect result passed verification")
	}
}

func TestCorruptedProofWrongAlpha(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	e, votes, err := createSingleBallot(r)
	if err != nil {
		t.Error("Couldn't create a single ballot")
	}

	// Make sure the proof originally passes verification.
	cb := votes[0]
	plaintext := big.NewInt(0)
	if !cb.Vote.Answers[0].IndividualProofs[0][0].Verify(&cb.Vote.Answers[0].Choices[0], plaintext, &e.PublicKey) {
		t.Error("The original proof doesn't pass verification")
	}

	// Before corrupting anything, try verifying the wrong bounds for the proof.
	if cb.Vote.Answers[0].IndividualProofs[0].Verify(0, 0, &cb.Vote.Answers[0].Choices[0], &e.PublicKey) {
		t.Error("A DisjunctiveZKProof passed verification for the wrong bounds")
	}

	// Try verifying the corrupted proof as a ZKProof.
	corruptInteger(r, &cb.Vote.Answers[0].Choices[0].Alpha)
	if cb.Vote.Answers[0].IndividualProofs[0][0].Verify(&cb.Vote.Answers[0].Choices[0], plaintext, &e.PublicKey) {
		t.Error("A vote with corrupted Alpha incorrectly passed verification")
	}

	// Try verifying it as a DisjunctiveZKProof, too.
	if cb.Vote.Answers[0].IndividualProofs[0].Verify(0, 1, &cb.Vote.Answers[0].Choices[0], &e.PublicKey) {
		t.Error("A DisjunctiveZKProof with corrupted Alpha incorrectly passed verification")
	}
}

func TestCorruptedProofWrongBeta(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	e, votes, err := createSingleBallot(r)
	if err != nil {
		t.Error("Couldn't create a single ballot")
	}

	cb := votes[0]
	// Try with a corrupted Beta value instead of Alpha.
	plaintext := big.NewInt(0)
	corruptInteger(r, &cb.Vote.Answers[0].Choices[0].Beta)
	if cb.Vote.Answers[0].IndividualProofs[0][0].Verify(&cb.Vote.Answers[0].Choices[0], plaintext, &e.PublicKey) {
		t.Error("A vote with corrupted Beta incorrectly passed verification")
	}
}

func TestCorruptedProofWrongBounds(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Try cheating on a proof by removing one of the elements and changing the bounds.
	// This must cause the hash check to fail.
	e, votes, err := createSingleBallot(r)
	if err != nil {
		t.Error("Couldn't create a single ballot")
	}

	cb := votes[0]

	// Take only the first element of the proof.
	cb.Vote.Answers[0].IndividualProofs[0] = cb.Vote.Answers[0].IndividualProofs[0][:1]
	if cb.Vote.Answers[0].IndividualProofs[0].Verify(0, 0, &cb.Vote.Answers[0].Choices[0], &e.PublicKey) {
		t.Error("A DisjunctiveZKProof with a missing proof incorrectly passed verification")
	}
}

func TestCorruptedBundleWrongBeta(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Try full-bundle verification with a corrupted Beta.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	corruptInteger(r, &b.Votes[0].Vote.Answers[0].Choices[0].Beta)
	if b.Verify() {
		t.Error("A bundle with an invalid vote passed verification")
	}
}

func TestCorruptedAuditWrongBeta(t *testing.T) {
	// Create a fake bundle to create the ballot audit.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	min := b.Election.Questions[0].Min
	if min == 0 {
		min = 1
	}

	answers := make([]int64, min)
	for i := range answers {
		answers[i] = int64(i)
	}

	var cb CastBallot
	if err = cb.Create(&b.Election, [][]int64{answers}, &b.Voters[0], true); err != nil {
		t.Error("Couldn't create a ballot to audit")
	}

	res := cb.Vote.ExtractResult(&b.Election)
	lr := b.Election.LabelResults(res)
	t.Logf("Got labeled audit results %s", lr)

	// Try with a corrupted Beta value.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	corruptInteger(r, &cb.Vote.Answers[0].Choices[0].Beta)

	// Recompute the JSON for this Ballot, since it's not saved in the structure.
	serializedVote, err := MarshalJSON(&cb.Vote)
	if err != nil {
		t.Error("Couldn't marshal the vote")
	}

	if cb.Vote.Audit(cb.VoteHash, serializedVote, &b.Election) {
		t.Error("A corrupted ballot incorrectly passed audit")
	}
}

func TestCorruptedAuditWrongAnswer(t *testing.T) {
	// Create a fake bundle to create the ballot audit.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	min := b.Election.Questions[0].Min
	if min == 0 {
		min = 1
	}

	answers := make([]int64, min)
	for i := range answers {
		answers[i] = int64(i)
	}

	var cb CastBallot
	if err = cb.Create(&b.Election, [][]int64{answers}, &b.Voters[0], true); err != nil {
		t.Error("Couldn't create a ballot to audit")
	}

	// Write the wrong answer.
	cb.Vote.Answers[0].Answer[0] = 1

	// Recompute the JSON for this Ballot, since it's not saved in the structure.
	serializedVote, err := MarshalJSON(&cb.Vote)
	if err != nil {
		t.Error("Couldn't marshal the vote")
	}

	if cb.Vote.Audit(cb.VoteHash, serializedVote, &b.Election) {
		t.Error("A corrupted ballot incorrectly passed audit")
	}
}

func TestCorruptedAuditNoRandomness(t *testing.T) {
	// Create a fake bundle to create the ballot audit.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	min := b.Election.Questions[0].Min
	if min == 0 {
		min = 1
	}

	answers := make([]int64, min)
	for i := range answers {
		answers[i] = int64(i)
	}

	// Try deleting the randomness.
	var cb CastBallot
	if err = cb.Create(&b.Election, [][]int64{answers}, &b.Voters[0], true); err != nil {
		t.Error("Couldn't create a ballot to audit")
	}

	// Write the wrong answer.
	cb.Vote.Answers[0].Randomness = nil

	// Recompute the JSON for this Ballot, since it's not saved in the structure.
	serializedVote, err := MarshalJSON(&cb.Vote)
	if err != nil {
		t.Error("Couldn't marshal the vote")
	}

	if cb.Vote.Audit(cb.VoteHash, serializedVote, &b.Election) {
		t.Error("A corrupted ballot incorrectly passed audit")
	}
}

func TestCorruptedAuditBadHash(t *testing.T) {
	// Create a fake bundle to create the ballot audit.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	min := b.Election.Questions[0].Min
	if min == 0 {
		min = 1
	}

	answers := make([]int64, min)
	for i := range answers {
		answers[i] = int64(i)
	}

	// Corrupt the election hash.
	var cb CastBallot
	if err = cb.Create(&b.Election, [][]int64{answers}, &b.Voters[0], true); err != nil {
		t.Error("Couldn't create a ballot to audit")
	}

	cb.Vote.ElectionHash = ""

	// Recompute the JSON for this Ballot, since it's not saved in the structure.
	serializedVote, err := MarshalJSON(&cb.Vote)
	if err != nil {
		t.Error("Couldn't marshal the vote")
	}

	if cb.Vote.Audit(cb.VoteHash, serializedVote, &b.Election) {
		t.Error("An invalid hash still passes audit")
	}
}

func TestCorruptedAuditOverallProof(t *testing.T) {
	// Create a fake bundle to create the ballot audit.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	min := b.Election.Questions[0].Min
	if min == 0 {
		min = 1
	}

	answers := make([]int64, min)
	for i := range answers {
		answers[i] = int64(i)
	}

	// Corrupt the overall proof and remove the "approval" type.
	var cb CastBallot
	if err = cb.Create(&b.Election, [][]int64{answers}, &b.Voters[0], true); err != nil {
		t.Error("Couldn't create a ballot to audit")
	}

	cb.Vote.Answers[0].OverallProof = nil
	b.Election.Questions[0].ChoiceType = "none"
	serializedVote, err := MarshalJSON(&cb.Vote)
	if err != nil {
		t.Error("Couldn't marshal the vote")
	}

	if cb.Vote.Audit(cb.VoteHash, serializedVote, &b.Election) {
		t.Error("An invalid overall proof still passes audit")
	}
}

func TestCorruptedAuditBadChoice(t *testing.T) {
	// Create a fake bundle to create the ballot audit.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	min := b.Election.Questions[0].Min
	if min == 0 {
		min = 1
	}

	answers := make([]int64, min)
	for i := range answers {
		answers[i] = int64(i)
	}

	var cb CastBallot
	if err = cb.Create(&b.Election, [][]int64{answers}, &b.Voters[0], true); err != nil {
		t.Error("Couldn't create a ballot to audit")
	}

	// Test with the wrong fingerprint
	serializedVote, err := MarshalJSON(&cb.Vote)
	if cb.Vote.Audit("wrong fingerprint", serializedVote, &b.Election) {
		t.Error("An invalid fingerprint still passes audit")
	}

	// Corrupt the choice.
	cb.Vote.Answers[0].Answer[0] = 200
	serializedVote, err = MarshalJSON(&cb.Vote)
	if err != nil {
		t.Error("Couldn't marshal the vote")
	}

	if cb.Vote.Audit(cb.VoteHash, serializedVote, &b.Election) {
		t.Error("An invalid choice value still passes audit")
	}
}

func TestCorruptedAuditWrongRandomness(t *testing.T) {
	// Create a fake bundle to create the ballot audit.
	b, err := createFakeBundle(1, 1, 0, 1, 2, 10, 1)
	if err != nil {
		t.Error("Couldn't create a fake bundle")
	}

	min := b.Election.Questions[0].Min
	if min == 0 {
		min = 1
	}

	answers := make([]int64, min)
	for i := range answers {
		answers[i] = int64(i)
	}

	var cb CastBallot
	if err = cb.Create(&b.Election, [][]int64{answers}, &b.Voters[0], true); err != nil {
		t.Error("Couldn't create a ballot to audit")
	}

	// Corrupt the choice.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	corruptInteger(r, &cb.Vote.Answers[0].Randomness[0])
	serializedVote, err := MarshalJSON(&cb.Vote)
	if err != nil {
		t.Error("Couldn't marshal the vote")
	}

	if cb.Vote.Audit(cb.VoteHash, serializedVote, &b.Election) {
		t.Error("An invalid randomness value still passes audit")
	}
}

func createFakeBundle(voterCount, ballotCount, auditCount, questionCount, answerLimit, maxStrLen, trusteeLimit int) (*ElectionBundle, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	questions, err := createRandomQuestions(r, questionCount, answerLimit, maxStrLen)
	if err != nil {
		return nil, err
	}

	voters, err := createRandomVoters(r, voterCount, maxStrLen)
	if err != nil {
		return nil, err
	}

	e, secret, err := createRandomElection(r, maxStrLen, voters, questions)
	if err != nil {
		return nil, err
	}

	votes, tally, err := createRandomBallots(r, voterCount, ballotCount, auditCount, voters, questions, e)
	if err != nil {
		return nil, err
	}

	// Create the trustees.
	trusteeCount := r.Intn(trusteeLimit) + 1
	glog.Infof("There are %d trustees\n", trusteeCount)
	var trustees []Trustee
	var trusteeSecrets []big.Int
	trustees, trusteeSecrets, err = SplitKey(secret, &e.PublicKey, trusteeCount)
	if err != nil {
		return nil, err
	}

	// Tally the election.
	results := e.Tally(votes, trustees, trusteeSecrets)
	if len(results) != len(tally) {
		return nil, errors.New("couldn't tally the election")
	}

	// Check that the results match the plaintext tally.
	for i, res := range results {
		t := tally[i]
		for j, v := range res {
			if v != t[j] {
				return nil, errors.New("mismatched results")
			}
		}
	}

	b, err := marshalBundle(e, voters, votes, results, trustees)
	if err != nil {
		return nil, err
	}

	// Instantiate and verify the bundle.
	if err = b.Instantiate(); err != nil {
		return nil, err
	}

	if !b.Verify() {
		return nil, errors.New("the bundle didn't pass verification")
	}
	glog.Info("The bundle passed verification")

	return b, nil
}

func TestBrokenJSON(t *testing.T) {
	var b ElectionBundle
	var err error

	// Invalid JSON data
	b.ElectionData = []byte("{")
	if err = b.Instantiate(); err == nil {
		t.Error("The election bundle should not successfully deserialize an invalid Election")
	}

	// Use a valid election with invalid voters.
	b.ElectionData = []byte("{}")
	b.VotersData = [][]byte{[]byte("{")}
	if err = b.Instantiate(); err == nil {
		t.Error("The election bundle should not successfully deserialize invalid Voters")
	}

	// Use an empty single voter.
	b.VotersData = [][]byte{[]byte("[{}]")}
	b.VotesData = [][]byte{[]byte("{")}
	if err = b.Instantiate(); err == nil {
		t.Error("The election bundle should not successfully deserialize invalid CastBallots")
	}

	// Use an empty single CastBallot.
	b.VotesData = [][]byte{[]byte("{}")}
	b.TrusteesData = []byte("{")
	if err = b.Instantiate(); err == nil {
		t.Error("The election bundle should not successfully deserialize invalid Trustees")
	}

	b.TrusteesData = []byte("[{}]")
	b.ResultsData = []byte("{")
	if err = b.Instantiate(); err == nil {
		t.Error("The election bundle should not successfully deserialize invalid Results")
	}
}

func TestElectionCreation(t *testing.T) {
	var k *Key
	if testing.Short() {
		g, p, q, err := instantiateQuickParams()
		if err != nil {
			t.Error(err)
		}

		k = new(Key)
		k.Generator = *g
		k.Prime = *p
		k.ExponentPrime = *q
	}

	answers := make([]string, 3)
	answers[0] = "yes"
	answers[1] = "no"
	answers[2] = "maybe so"
	var q Question
	if err := q.Create(answers, 2, 1, "Which is it?", "absolute", "Test Q"); err != nil {
		t.Error("Couldn't create a question")
	}

	var e Election
	secret, err := e.Create("https://example.com", "Fake Election", time.Now().String(),
		"Fake Election", false, []Question{q}, "Fake",
		false, "Fake hash", time.Now().String(), time.Now().String(), k)
	if err != nil {
		t.Error("Couldn't create an election")
	}

	if secret == nil || secret.BitLen() == 0 {
		t.Error("The election didn't produce a valid secret")
	}
}

func TestCreateVoter(t *testing.T) {
	var v Voter
	err := v.Create("voter 1", "voter1@example.com", true, "", "email")
	if err != nil {
		t.Error("Couldn't create a voter")
	}

	err = v.Create("voter 2", "voter2@example.com", false, "fake hash", "email")
	if err != nil {
		t.Error("Couldn't create a second voter")
	}

	err = v.Create("voter 3", "voter3@example.com", true, "fake hash", "email")
	if err == nil {
		t.Error("Incorrectly created a voter with a computed and a supplied hash")
	}
}

func TestRandomUTF8(t *testing.T) {
	count := 10
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	fmt.Println("Got string:", randomString(count, r))
}

// randomString generates a stirng of random graphical unicode characters
func randomString(n int, r *rand.Rand) string {
	var temp []byte
	for i := 0; i < n; i++ {
		ru := randomRune(r)
		rb := make([]byte, utf8.RuneLen(ru))
		_ = utf8.EncodeRune(rb, ru)
		temp = append(temp, rb...)
	}

	return string(temp)
}

// randomRune generates a random graphical Unicode code point in the Unicode
// Basic Multilingual Plane (16 bits)
func randomRune(r *rand.Rand) rune {
	i := r.Intn(1 << 16)
	for !utf8.ValidRune(rune(i)) || !unicode.IsGraphic(rune(i)) {
		i = r.Intn(1 << 16)
	}

	return rune(i)
}

func TestElectionVerification(t *testing.T) {
	if !checkCerts() {
		t.Skip("Couldn't run the election verification test due to lack of certs")
	}

	b, err := Download(heliosServer, electionUuid)
	if err != nil {
		t.Error("Couldn't download the election with uuid", electionUuid)
	}

	if !b.Verify() {
		t.Error("The election with uuid", electionUuid, "didn't pass verification")
	}

	return
}

func TestElectionBundleSerialization(t *testing.T) {
	if !checkCerts() {
		t.Skip("Couldn't run the election bundle serialization test due to lack of certs")
	}

	b, err := Download(heliosServer, electionUuid)
	if err != nil {
		t.Error("Couldn't download the election with uuid", electionUuid)
	}

	serialized, err := json.Marshal(&b)
	if err != nil {
		t.Error("Couldn't marshal the election bundle as JSON: ", err)
	}

	var deserialized ElectionBundle
	err = UnmarshalJSON(serialized, &deserialized)
	if err != nil {
		t.Error("Couldn't unmarshal the election JSON: ", err)
	}

	return
}

// Check to see if there are certificates available. If not, then https won't
// work.
func checkCerts() bool {
	if _, err := os.Stat("/etc/ssl/certs/ca-certificates.crt"); err != nil {
		return false
	}

	return true
}

func TestGetJSONBadAddress(t *testing.T) {
	var e Election
	_, err := GetJSON("garbage address", &e)
	if err == nil {
		t.Error("Incorrectly got JSON from an invalid address")
	}
}

func TestGetJSONBadType(t *testing.T) {
	if !checkCerts() {
		t.Skip("Couldn't run json bad type test due to lack of https")
	}

	var i int64
	elecAddr := heliosServer + "b36cbf0c-250a-11e3-89f4-46d2afa631be"
	_, err := GetJSON(elecAddr, &i)
	if err == nil {
		t.Error("Incorrectly got JSON from an invalid address")
	}
}

func TestGetJSONBadMarshal(t *testing.T) {
	// Try to marshal a type that can't be marshaled in JSON.
	_, err := MarshalJSON(TestGetJSONBadMarshal)
	if err == nil {
		t.Error("Somehow, a function was marshaled as JSON")
	}
}

func TestBallotAudit(t *testing.T) {
	if !checkCerts() {
		t.Skip("Couldn't run ballot audit test due to lack of https")
	}

	// Use a ballot from an IACR election: b36cbf0c-250a-11e3-89f4-46d2afa631be
	fingerprint := "3HknRw5qRLzxs6UQ1XpE8TQznEbN0t8LtISLSPArCj0"
	elecAddr := heliosServer + "b36cbf0c-250a-11e3-89f4-46d2afa631be"
	var e Election
	electionJSON, err := GetJSON(elecAddr, &e)
	if err != nil {
		t.Error("Couldn't get the election data: ", err)
	}

	// Make sure the election is set up properly, e.g., with an ElectionHash.
	e.Init(electionJSON)

	f := "./testdata/test_audit.json"
	file, err := os.Open(f)
	if err != nil {
		t.Error("Couldn't open test ballot audit file: ", err)
	}

	fi, err := file.Stat()
	if err != nil {
		t.Error("Couldn't get the size of the audit file: ", err)
	}

	jsonData := make([]byte, fi.Size())
	_, err = file.Read(jsonData)
	if err != nil {
		t.Error("Couldn't read the whole ballot audit file: ", err)
	}

	var b Ballot
	err = UnmarshalJSON(jsonData, &b)

	if !b.Audit(fingerprint, jsonData, &e) {
		t.Error("The ballot did not pass an audit")
	}

	return
}

func serializedVerificationHelper(file string, t *testing.T) {
	serialized, err := ioutil.ReadFile(file)
	if err != nil {
		t.Error("Couldn't read the file")
	}

	var b ElectionBundle
	err = UnmarshalJSON(serialized, &b)
	if err != nil {
		t.Error("Couldn't unmarshal the serialized JSON")
	}

	t.Log("Instantiating the election data structures")
	if err = b.Instantiate(); err != nil {
		t.Error("Couldn't instantiate the bundle")
	}

	if !b.Verify() {
		t.Error("The election didn't pass verification")
	}

}

func TestSerializedVerification(t *testing.T) {
	f := "./testdata/test.json"
	serializedVerificationHelper(f, t)
}

func TestLongSerializedVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping verification of large election, since testing is short")
	}

	f := "./testdata/iacr2013.json"
	serializedVerificationHelper(f, t)
}
