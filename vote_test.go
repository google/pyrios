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
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang/glog"
)

// Encrypt encrypts the selection for an answer: either this value is
// selected or not. It also generates a DisjunctiveZKProof to show that
// the value is either selected or not. It returns the randomness it
// generated; this is useful for computing the OverallProof for a Question.
func Encrypt(selected bool, pk *Key) (*Ciphertext, *big.Int, DisjunctiveZKProof, error) {
	// If this value is selected, then use g^1; otherwise, use g^0.
	var plaintext *big.Int
	var realExp, fakeExp int64
	if selected {
		plaintext = pk.Generator
		realExp = 1
		fakeExp = 0
	} else {
		plaintext = big.NewInt(1)
		realExp = 0
		fakeExp = 1
	}

	randomness, err := rand.Int(rand.Reader, pk.ExponentPrime)
	if err != nil {
		glog.Error("Couldn't get randomness for an encryption")
		return nil, nil, nil, err
	}

	a := new(big.Int).Exp(pk.Generator, randomness, pk.Prime)
	b := new(big.Int).Exp(pk.PublicValue, randomness, pk.Prime)
	b.Mul(b, plaintext)
	b.Mod(b, pk.Prime)
	c := &Ciphertext{a, b}

	// Real proof of selected and a simulated proof of !selected
	var proof DisjunctiveZKProof
	proof = make([]*ZKProof, 2)

	if err = proof.CreateFakeProof(fakeExp, fakeExp, c, pk); err != nil {
		glog.Error("Couldn't create a simulated proof")
		return nil, nil, nil, err
	}

	if err = proof.CreateRealProof(realExp, c, randomness, pk); err != nil {
		glog.Error("Couldn't create a real proof")
		return nil, nil, nil, err
	}

	return c, randomness, proof, nil
}

// ComputeMax returns the max value for the question, which is the
// value Max in the question if Max > 0, and otherwise is the total
// number of answers.
func (q *Question) ComputeMax() int {
	if q.Max == 0 {
		return len(q.Answers)
	}

	return q.Max
}

// NewBallot takes an Election and a set of responses as input and fills in a Ballot
func NewBallot(election *Election, answers [][]int64) (*Ballot, error) {
	if len(answers) != len(election.Questions) {
		return nil, errors.New("wrong number of answers")
	}

	pk := election.PublicKey

	//vote.ElectionHash = election.ElectionHash
	//vote.ElectionUuid = election.Uuid

	ans := make([]*EncryptedAnswer, len(election.Questions))

	for i, q := range election.Questions {
		a := answers[i]
		results := make([]bool, len(q.Answers))
		sum := int64(len(a))

		min := q.Min
		max := q.ComputeMax()
		if sum < int64(min) || sum > int64(max) {
			glog.Errorf("Sum was %d, min was %d, and max was %d\n", sum, min, max)
			return nil, errors.New("invalid answers: sum must lie between min and max")
		}

		ch := make([]*Ciphertext, len(results))
		ip := make([]DisjunctiveZKProof, len(results))
		rs := make([]*big.Int, len(results))
		as := make([]int64, len(a))
		copy(as, a)

		// Mark each selected value as being voted for.
		for _, index := range a {
			results[index] = true
		}

		// Encrypt and create proofs for the answers, then create an overall proof if required
		tally := &Ciphertext{big.NewInt(1), big.NewInt(1)}
		randTally := big.NewInt(0)
		for j := range q.Answers {
			var err error
			if ch[j], rs[j], ip[j], err = Encrypt(results[j], pk); err != nil {
				glog.Errorf("Couldn't encrypt choice %d for question %d\n", j, i)
				return nil, err
			}

			tally.MulCiphertexts(ch[j], pk.Prime)
			randTally.Add(randTally, rs[j])
			randTally.Mod(randTally, pk.ExponentPrime)
		}

		var op DisjunctiveZKProof
		if q.Max != 0 {
			op = make([]*ZKProof, q.Max-q.Min+1)
			for j := q.Min; j <= q.Max; j++ {
				if int64(j) != sum {
					// Create a simulated proof for the case where the
					// tally actually encrypts the value j.
					if err := op.CreateFakeProof(int64(j-q.Min), int64(j), tally, pk); err != nil {
						glog.Errorf("Couldn't create fake proof %d\n", j)
						return nil, err
					}
				}
			}

			if err := op.CreateRealProof(sum-int64(q.Min), tally, randTally, pk); err != nil {
				glog.Errorf("Couldn't create the real proof")
				return nil, err
			}
		}

		ans[i] = &EncryptedAnswer{ch, ip, op, as, rs}
	}

	return &Ballot{ans, election.ElectionHash, election.Uuid}, nil
}

// NewCastBallot instantiates a CastBallot for a given set of answers for a Voter.
func NewCastBallot(election *Election, answers [][]int64, v *Voter, auditable bool) (*CastBallot, error) {
	// First, create the encrypted vote.
	vote, err := NewBallot(election, answers)
	if err != nil {
		glog.Error("Couldn't encrypt a ballot: ", err)
		return nil, err
	}

	if !auditable {
		// Since this is to be a cast ballot, we must strip the randomness and the answers from it.
		for i := range vote.Answers {
			vote.Answers[i].Answer = nil
			vote.Answers[i].Randomness = nil
		}
	}

	castAt := time.Now().String()
	serializedVote, err := MarshalJSON(vote)
	if err != nil {
		glog.Error("Couldn't marshal the JSON for an encrypted ballot")
		return nil, err
	}

	h := sha256.Sum256(serializedVote)
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	voteHash := encodedHash[:len(encodedHash)-1]

	serializedVoter, err := MarshalJSON(v)
	if err != nil {
		glog.Errorf("Couldn't marshal the JSON for voter %s\n", string(v.Uuid))
		return nil, err
	}

	hv := sha256.Sum256(serializedVoter)
	encodedHV := base64.StdEncoding.EncodeToString(hv[:])
	voterHash := encodedHV[:len(encodedHV)-1]

	cb := &CastBallot{nil, castAt, vote, voteHash, voterHash, v.Uuid}
	cb.JSON, err = MarshalJSON(cb)
	if err != nil {
		glog.Error("Couldn't marshal the JSON for the whole cast ballot")
		return nil, err
	}

	return cb, nil
}

// NewVoter instantiates a new Voter with the given information and a fresh UUID.
func NewVoter(name string, id string, computeHash bool, hash string, voterType string) (*Voter, error) {
	uuid, err := GenUUID()
	if err != nil {
		glog.Error("Couldn't generate a UUID for a new voter")
		return nil, err
	}

	vidHash := hash
	if computeHash {
		if len(hash) > 0 {
			return nil, errors.New("can't pass a non-empty hash and compute the hash")
		}

		if len(id) == 0 {
			return nil, errors.New("can't hash an empty identifier")
		}

		h := sha256.Sum256([]byte(id))
		encodedHash := base64.StdEncoding.EncodeToString(h[:])
		vidHash = encodedHash[:len(encodedHash)-1]
	}

	if voterType != "openid" && voterType != "email" {
		return nil, errors.New("voter must have type 'openid' or 'email'")
	}

	return &Voter{name, uuid, id, vidHash, voterType}, nil
}

// Create instantiates a question with the given answer set and other information.
func NewQuestion(answers []string, max int, min int, question string, resultType string, shortName string) (*Question, error) {
	if max < 0 || min < 0 || min > max {
		return nil, errors.New("invalid question min and max")
	}

	if resultType != "absolute" && resultType != "relative" {
		return nil, errors.New("invalid result type")
	}

	ansURLs := make([]string, len(answers))
	ans := make([]string, len(answers))
	copy(ans, answers)

	// The only possible choice type is "approval", and the only possible
	// tally type is "homomorphic".
	return &Question{ansURLs, ans, "approval", max, min, question, resultType, shortName, "homomorphic"}, nil
}

// NewKeyFromParams uses a given set of parameters to generate a public key.
func NewKeyFromParams(g *big.Int, p *big.Int, q *big.Int) (*Key, *big.Int, error) {
	secret, err := rand.Int(rand.Reader, q)
	if err != nil {
		glog.Error("Couldn't generate a secret for the key")
		return nil, nil, err
	}

	return &Key{g, p, q, new(big.Int).Exp(g, secret, p)}, secret, nil

}

// NewKey generates a fresh set of parameters and a public/private key pair in
// those parameters.
func NewKey() (*Key, *big.Int, error) {
	// Use the DSA crypto code to generate a key pair. For testing
	// purposes, we'll use (2048,224) instead of (2048,160) as used by the
	// current Helios implementation
	params := new(dsa.Parameters)
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L2048N224); err != nil {
		glog.Error("Couldn't generate DSA parameters for the ElGamal group")
		return nil, nil, err
	}

	return NewKeyFromParams(params.G, params.P, params.Q)
}

// NewElection instantiates a new election with the given parameters.
func NewElection(url string, desc string, frozenAt string, name string,
	openreg bool, questions []*Question, shortName string,
	useVoterAliases bool, votersHash string, votingEnd string,
	votingStart string, k *Key) (*Election, *big.Int, error) {
	uuid, err := GenUUID()
	if err != nil {
		glog.Error("Couldn't generate an election UUID")
		return nil, nil, err
	}

	var pk *Key
	var secret *big.Int
	if k == nil {
		if pk, secret, err = NewKey(); err != nil {
			glog.Error("Couldn't generate a new key for the election")
			return nil, nil, err
		}
	} else {
		// Take the public params from k to generate the key.
		if pk, secret, err = NewKeyFromParams(k.Generator, k.Prime, k.ExponentPrime); err != nil {
			glog.Error("Couldn't generate a new key for the election")
			return nil, nil, err
		}
	}

	e := &Election{
		CastURL:         url,
		Description:     desc,
		FrozenAt:        frozenAt,
		Name:            name,
		Openreg:         openreg,
		PublicKey:       pk,
		Questions:       questions,
		ShortName:       shortName,
		UseVoterAliases: useVoterAliases,
		Uuid:            uuid,
		VotersHash:      votersHash,
		VotingEndsAt:    votingEnd,
		VotingStartsAt:  votingStart,
	}

	// Compute the JSON of the election and compute its hash
	json, err := MarshalJSON(e)
	if err != nil {
		glog.Error("Couldn't marshal the election as JSON")
		return nil, nil, err
	}

	h := sha256.Sum256(json)
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	e.ElectionHash = encodedHash[:len(encodedHash)-1]
	e.JSON = json

	return e, secret, nil
}

// GenUUID creates RFC 4122-compliant UUIDs.
// This function was suggested by a post on the golang-nuts mailing list.
func GenUUID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		glog.Error("Could not generate a UUID")
		return "", err
	}

	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:])
	return uuid, nil
}

// Tally computes the tally of an election and returns the result.
// In the process, it generates partial decryption proofs for each of
// the partial decryptions computed by the trustee.
func (e *Election) Tally(votes []*CastBallot, trustees []*Trustee, trusteeSecrets []*big.Int) (Result, error) {
	tallies, voteFingerprints := e.AccumulateTallies(votes)
	// TODO(tmroeder): maybe we should just skip votes that don't pass verification?
	// What does the spec say?
	if len(voteFingerprints) == 0 {
		glog.Error("Couldn't tally the votes")
		return nil, errors.New("couldn't tally the votes")
	}

	var err error
	for k, t := range trustees {
		df := make([][]*big.Int, len(e.Questions))
		dp := make([][]*ZKProof, len(e.Questions))
		for i, q := range e.Questions {
			df[i] = make([]*big.Int, len(q.Answers))
			dp[i] = make([]*ZKProof, len(q.Answers))
			for j := range q.Answers {
				df[i][j] = new(big.Int).Exp(tallies[i][j].Alpha, trusteeSecrets[k], t.PublicKey.Prime)
				if dp[i][j], err = NewPartialDecryptionProof(tallies[i][j], df[i][j], trusteeSecrets[k], t.PublicKey); err != nil {
					glog.Errorf("Couldn't create a proof for (%d, %d) for trustee %d\n", i, j, k)
					return nil, err
				}
			}
		}

		t.DecryptionFactors = df
		t.DecryptionProofs = dp
	}

	// For each question and each answer, reassemble the tally and search for its value.
	// Then put this in the results.
	maxValue := len(votes)
	result := make([][]int64, len(e.Questions))
	for i, q := range e.Questions {
		result[i] = make([]int64, len(q.Answers))
		for j := range q.Answers {
			alpha := big.NewInt(1)
			for k := range trustees {
				alpha.Mul(alpha, trustees[k].DecryptionFactors[i][j])
				alpha.Mod(alpha, trustees[k].PublicKey.Prime)
			}

			beta := new(big.Int).ModInverse(alpha, e.PublicKey.Prime)
			beta.Mul(beta, tallies[i][j].Beta)
			beta.Mod(beta, e.PublicKey.Prime)

			// This decrypted value can be anything between g^0 and g^maxValue.
			// Try all values until we find it.
			temp := new(big.Int)
			val := new(big.Int)
			var v int
			for v = 0; v <= maxValue; v++ {
				val.SetInt64(int64(v))
				temp.Exp(e.PublicKey.Generator, val, e.PublicKey.Prime)
				if temp.Cmp(beta) == 0 {
					result[i][j] = int64(v)
					break
				}
			}

			if v > maxValue {
				glog.Errorf("Couldn't decrypt value (%d, %d)\n", i, j)
				return nil, errors.New("couldn't decrypt part of the tally")
			}
		}
	}

	return result, nil
}
