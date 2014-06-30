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

// Package pyrios implements Helios verification.
// This is for version 3 of the Helios cryptographic voting protocol.
// See https://vote.heliosvoting.org for more details on Helios.
// And see http://documentation.heliosvoting.org/verification-specs/helios-v3-verification-specs
// for the actual v3 data structures and the algorithm specification.
//
// The types in the helios package are translations of the JSON Helios types
// given by the Helios v3 specification.
package pyrios

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/golang/glog"
)

// A Question is part of an Election and specifies a question to be voted on.
type Question struct {
	// AnswerUrls can provide urls with information about answers. These
	// urls can be empty.
	AnswerUrls []string `json:"answer_urls"`

	// Answers is the list of answer choices for this question.
	Answers []string `json:"answers"`

	// ChoiceType specifies the possible ways to evaluate responses. It can
	// currently only be set to 'approval'.
	ChoiceType string `json:"choice_type"`

	// Maximum specifies the maximum value of a vote for this Question. If
	// Max is not specified in the JSON structure, then there will be no
	// OverallProof, since any number of values is possible, up to the
	// total number of answers. This can be detected by looking at
	// OverallProof in the given Ballot.
	Max int `json:"max"`

	// Min specifies the minimum number of answers. This can be as low as
	// 0.
	Min int `json:"min"`

	// Question gives the actual question to answer
	Question string `json:"question"`

	// ResultType specifies the way in which results should be calculated:
	// 'absolute' or 'relative'.
	ResultType string `json:"result_type"`

	// ShortName gives a short representation of the Question.
	ShortName string `json:"short_name"`

	// TallyType specifies the kind of tally to perform. The only valid
	// value here is 'homomorphic'.
	TallyType string `json:"tally_type"`
}

// A Key is an ElGamal public key. There is one Key in each Election, and it
// specifies the group in which computations are to be performed. Encryption of
// a value m is performed as (g^r, g^m * y^r) mod p.
type Key struct {
	// Generator is the generator element g used in ElGamal encryptions.
	Generator *big.Int `json:"g"`

	// Prime is the prime p for the group used in encryption.
	Prime *big.Int `json:"p"`

	// ExponentPrime is another prime that specifies the group of exponent
	// values in the exponent of Generator. It is used in challenge
	// generation and verification.
	ExponentPrime *big.Int `json:"q"`

	// PublicValue is the public-key value y used to encrypt.
	PublicValue *big.Int `json:"y"`
}

// An Election contains all the information about a Helios election.
type Election struct {
	// JSON stores the original JSON for the election. This is not part of
	// the Helios JSON structure but is added here for convenience.
	JSON []byte `json:"-"`

	// ElectionHash stores the SHA256 hash of the JSON value, since this is
	// needed to verify each ballot. This is not part of the original
	// Helios JSON structure but is added here for convenience.
	ElectionHash string `json:"-"`

	// CastURL is the url that can be used to cast ballots; casting ballots
	// is not currently supported by this go package. Ballots must still be
	// cast using the online Helios service.
	CastURL string `json:"cast_url"`

	// Description is a plaintext description of the election.
	Description string `json:"description"`

	// FrozenAt is the date at which the election was fully specified and
	// frozen.
	FrozenAt string `json:"frozen_at"`

	// Name is the full name of the election.
	Name string `json:"name"`

	// Openreg specifies whether or not voters can be added after the
	// election has started.
	Openreg bool `json:"openreg"`

	// PublicKey is the ElGamal public key associated with the election.
	// This is the key used to encrypt all ballots and to create and verify
	// proofs.
	PublicKey *Key `json:"public_key"`

	// Questions is the list of questions to be voted on in this election.
	Questions []*Question `json:"questions"`

	// ShortName provides a short plaintext name for this election.
	ShortName string `json:"short_name"`

	// UseVoterAliases specifies whether or not voter names are replaced by
	// alises (like V153) that leak no information about the voter
	// identities. This can be used instead of encrypting voter names if the
	// election creators want to be sure that voter identities will remain
	// secret forever, even in the face of future cryptanalytic advances.
	UseVoterAliases bool `json:"use_voter_aliases"`

	// Uuid is a unique identifier for this election. This uuid is used in
	// the URL of the election itself: the URL of the JSON version of this
	// Election data structure is
	// https://vote.heliosvoting.org/helios/elections/<uuid>
	Uuid string `json:"uuid"`

	// VotersHash provides the hash of the list of voters.
	VotersHash string `json:"voters_hash"`

	VotingEndsAt   string `json:"voting_ends_at"`
	VotingStartsAt string `json:"voting_starts_at"`
}

// Init saves the original election JSON and computes the election hash.
func (election *Election) Init(json []byte) {
	election.JSON = json
	h := sha256.Sum256(election.JSON)
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	election.ElectionHash = encodedHash[:len(encodedHash)-1]
}

// AccumulateTallies combines the ballots homomorphically for each question and answer
// to get an encrypted tally for each. It also compute the ballot tracking numbers for
// each of the votes.
func (election *Election) AccumulateTallies(votes []*CastBallot) ([][]*Ciphertext, []string) {
	// Initialize the tally structures for homomorphic accumulation.

	tallies := make([][]*Ciphertext, len(election.Questions))
	fingerprints := make([]string, len(votes))
	for i := range tallies {
		tallies[i] = make([]*Ciphertext, len(election.Questions[i].Answers))
		for j := range tallies[i] {
			// Each tally must start at 1 for the multiplicative
			// homomorphism to work.
			tallies[i][j] = &Ciphertext{big.NewInt(1), big.NewInt(1)}
		}
	}

	// Verify the votes and accumulate the tallies.
	resp := make(chan bool)
	for i := range votes {
		// Shadow i as a new variable for the goroutine.
		i := i
		go func(c chan bool) {
			glog.Infof("Verifying vote from %s\n", votes[i].VoterUuid)
			c <- votes[i].Vote.Verify(election)
			return
		}(resp)

		h := sha256.Sum256(votes[i].JSON)
		encodedHash := base64.StdEncoding.EncodeToString(h[:])
		fingerprint := encodedHash[:len(encodedHash)-1]
		fingerprints = append(fingerprints, fingerprint)

		for j, q := range election.Questions {
			for k := range q.Answers {
				// tally_j_k = (tally_j_k * ballot_i_j_k) mod p
				tallies[j][k].MulCiphertexts(votes[i].Vote.Answers[j].Choices[k], election.PublicKey.Prime)
			}
		}
	}

	// Make sure all the votes passed verification.
	for _ = range votes {
		if !<-resp {
			glog.Error("Vote verification failed")
			return nil, nil
		}
	}

	return tallies, fingerprints
}

// Retally checks the proofs for a purported Election Result, given the partial
// decryption proofs from the Trustee data, and given a list of CastBallot
// values that were used in the tally. It recomputes the encrypted tally value
// homomorphically, checking the ZKProof values for each CastBallot, and checks
// the partial decryption proofs for each partial decryption that goes into the
// tally computation. It then checks the purported tally value in the Result by
// exponentiating the Election.PublicKey.Generator value with this value and
// checking that it matches the decrypted value.
func (election *Election) Retally(votes []*CastBallot, result Result, trustees []*Trustee) bool {
	tallies, voteFingerprints := election.AccumulateTallies(votes)
	if len(voteFingerprints) == 0 {
		glog.Error("Some votes didn't pass verification")
		return false
	}

	glog.Info("All cast ballots pass verification")

	if len(result) != len(election.Questions) {
		glog.Error("The results do not contain the right number of answers")
		glog.Error("Maybe the election hasn't closed yet?")
		return false
	}

	glog.Info("Checking the final tally")
	for i, q := range election.Questions {
		if len(result[i]) != len(q.Answers) {
			glog.Errorf("The results for question %d don't have the right length\n", i)
			return false
		}

		for j := range q.Answers {
			decFactorCombination := big.NewInt(1)
			for _, t := range trustees {
				if !t.DecryptionProofs[i][j].VerifyPartialDecryption(
					tallies[i][j],
					t.DecryptionFactors[i][j],
					t.PublicKey) {
					glog.Errorf("The partial decryption proof for %d, %d failed\n", i, j)
					return false
				}

				// Combine this partial decryption using the
				// homomorphism.
				decFactorCombination.Mul(decFactorCombination, t.DecryptionFactors[i][j])
			}

			// Contrary to how it's written in the published spec,
			// the result must be represented as g^m rather than m,
			// since everything is done in exponential ElGamal.
			bigResult := big.NewInt(result[i][j])
			bigResult.Exp(election.PublicKey.Generator, bigResult, election.PublicKey.Prime)
			lhs := big.NewInt(1)
			// (decFactorCombination * bigResult) mod p
			lhs.Mul(decFactorCombination, bigResult)
			lhs.Mod(lhs, election.PublicKey.Prime)

			rhs := big.NewInt(1)
			// tally_i_j.Beta mod p
			rhs.Mod(tallies[i][j].Beta, election.PublicKey.Prime)

			// These should match if the combination of the partial
			// decryptions was correct.
			if lhs.Cmp(rhs) != 0 {
				glog.Errorf("The decryption factor check failed for question %d and answer %d\n", i, j)
				return false
			}
		}
	}

	return true
}

// A Ciphertext is an ElGamal ciphertext, where g is Key.Generator, r is a
// random value, m is a message, and y is Key.PublicValue.
type Ciphertext struct {
	// Alpha = g^r
	Alpha *big.Int `json:"alpha"`

	// Beta = g^m * y^r
	Beta *big.Int `json:"beta"`
}

// MulCiphertexts multiplies an ElGamal Ciphertext value element-wise into an
// existing Ciphertext. This has the effect of adding the value encrypted in the
// other Ciphertext to the prod Ciphertext. The prime specifies the group in
// which these multiplication operations are to be performed.
func (prod *Ciphertext) MulCiphertexts(other *Ciphertext, prime *big.Int) *Ciphertext {
	prod.Alpha.Mul(prod.Alpha, other.Alpha)
	prod.Alpha.Mod(prod.Alpha, prime)
	prod.Beta.Mul(prod.Beta, other.Beta)
	prod.Beta.Mod(prod.Beta, prime)
	return prod
}

// A Voter represents a single voter in an Election.
type Voter struct {
	// Name is the name of the voter. This can be an alias like "V155", if
	// voter aliases are used in this Election.
	Name string `json:"name"`

	// Uuid is a unique identifier for this voter; Helios uses the Uuid as
	// a key for many of its operations. For example, given a voter uuid
	// and an election uuid, the last CastBallot for a voter can be
	// downloaded at
	// https://vote.heliosvoting.org/helios/elections/<election uuid>/ballots/<uuid>/last
	Uuid string `json:"uuid"`

	// VoterID is a string representing the voter. It can be a URL (like an
	// OpenID URL), or it can be an email address. Or it can be absent.
	VoterID string `json:"voter_id"`

	// VoterIDHash is the hash of a VoterID; this can be present even if the
	// VoterID is absent.
	VoterIDHash string `json:"voter_id_hash"`

	// VoterType is the type of voter, either "openid" or "email".
	VoterType string `json:"voter_type"`
}

// An EncryptedAnswer is part of a Ballot cast by a Voter. It is the answer to
// a given Question in an Election.
type EncryptedAnswer struct {
	// Choices is a list of votes for each choice in a Question. Each choice
	// is encrypted with the Election.PublicKey.
	Choices []*Ciphertext `json:"choices"`

	// IndividualProofs gives a proof that each corresponding entry in
	// Choices is well formed: this means that it is either 0 or 1. So, each
	// DisjunctiveZKProof is a list of two ZKProofs, the first proving the 0
	// case, and the second proving the 1 case. One of these proofs is
	// simulated, and the other is real: see the comment for ZKProof for the
	// algorithm and the explanation.
	IndividualProofs []DisjunctiveZKProof `json:"individual_proofs"`

	// OverallProof shows that the set of choices sum to an acceptable
	// value: one that falls between Question.Min and Question.Max. If there
	// is no Question.Max, then OverallProof will be empty and does not need
	// to be checked.
	OverallProof DisjunctiveZKProof `json:"overall_proof"`

	// Answer is the actual answer that is supposed to be encrypted in
	// EncryptedAnswer. This is not serialized/deserialized if not present.
	// This must only be present in a spoiled ballot because SECRECY.
	Answer []int64 `json:"answer,omitempty"`

	// Randomness is the actual randomness that is supposed to have been
	// used to encrypt Answer in EncryptedAnswer. This is not serialized or
	// deserialized if not present. This must only be present in a spoiled
	// ballot because SECRECY.
	Randomness []*big.Int `json:"randomness,omitempty"`
}

// VerifyAnswer checks the DisjunctiveZKProof values for a given
// EncryptedAnswer. It first checks each of the EncryptedAnswer.IndividualProof
// values to make sure it encodes either 0 or 1 (either that choice was voted
// for or not). Then it checks the OverallProof (if there is one) to make sure
// that the homomorphic sum of the ciphertexts is a value between min and max.
// If there is no OverallProof, then it makes sure that this is an approval
// question so that this last check doesn't matter.
func (answer *EncryptedAnswer) VerifyAnswer(min int, max int, choiceType string, publicKey *Key) bool {
	prod := &Ciphertext{big.NewInt(1), big.NewInt(1)}
	for i := range answer.Choices {
		proof := answer.IndividualProofs[i]
		// Each answer can only be 0 or 1.
		if !proof.Verify(0, 1, answer.Choices[i], publicKey) {
			glog.Errorf("The proof for choice %d did not pass verification\n", i)
			return false
		}
		prod.MulCiphertexts(answer.Choices[i], publicKey.Prime)
	}

	if len(answer.OverallProof) == 0 {
		if choiceType != "approval" {
			glog.Error("Couldn't check a null overall proof")
			return false
		}
	} else if !answer.OverallProof.Verify(min, max, prod, publicKey) {
		glog.Error("The overall proof did not pass verification")
		return false
	}

	return true
}

// A Ballot is a cryptographic vote in an Election.
type Ballot struct {
	// Answers is a list of answers to the Election specified by
	// ElectionUuid and ElectionHash.
	Answers []*EncryptedAnswer `json:"answers"`

	// ElectionHash is the SHA-256 hash of the Election specified by
	// ElectionUuid.
	ElectionHash string `json:"election_hash"`

	// ElectionUuid is the unique identifier for the Election that Answers
	// apply to.
	ElectionUuid string `json:"election_uuid"`
}

// Verify checks the hash of the election against the hash stored in this
// Ballot and checks the DisjunctiveZKProofs of the Answer values against the
// Question.Min and Question.Max.
func (vote *Ballot) Verify(election *Election) bool {
	if election.ElectionHash != vote.ElectionHash {
		glog.Error("The election hash in the vote did not match the election")
		return false
	}

	for i := range vote.Answers {
		q := election.Questions[i]
		if !vote.Answers[i].VerifyAnswer(q.Min, q.Max, q.ChoiceType, election.PublicKey) {
			glog.Errorf("Answer %d did not pass verification\n", i)
			return false
		}
	}

	return true
}

// A CastBallot wraps a Ballot and gives more context to it. The JSON version of
// this type can be found for a voter with uuid vuuid in election euuid at
// https://vote.heliosvoting.org/helios/elections/<euuid>/ballots/<vuuid>/last
type CastBallot struct {
	// JSON is the JSON string corresponding to this type. This is not part
	// of the original JSON structure (obviously).
	JSON []byte `json:"-"`

	// CastAt gives the time at which Vote was cast.
	CastAt string `json:"cast_at"`

	// Vote is the cast Ballot itself.
	Vote *Ballot `json:"vote"`

	// VoteHash is the SHA-256 hash of the JSON corresponding to Vote.
	VoteHash string `json:"vote_hash"`

	// VoterHash is the SHA-256 hash of the Voter JSON corresponding to
	// VoterUuid.
	VoterHash string `json:"voter_hash"`

	// VoterUuid is the unique identifier for the Voter that cast Vote.
	VoterUuid string `json:"voter_uuid"`
}

// A Result is a list of tally lists, one tally list per Question. Each tally
// list consists of one integer per choice in the Question.
type Result [][]int64

// A Trustee represents the public information for one of the keys used to
// tally and decrypt the election results.
type Trustee struct {
	// DecryptionFactors are the partial decryptions of each of the
	// homomorphic tally results.
	DecryptionFactors [][]*big.Int `json:"decryption_factors"`

	// DecryptionProofs are the proofs of correct partial decryption for
	// each of the DecryptionFactors.
	DecryptionProofs [][]*ZKProof `json:"decryption_proofs"`

	// PoK is a proof of knowledge of the private key share held by this
	// Trustee and used to create the DecryptionFactors.
	PoK *SchnorrProof `json:"pok"`

	// PublicKey is the ElGamal public key of this Trustee.
	PublicKey *Key `json:"public_key"`

	// PublicKeyHash is the SHA-256 hash of the JSON representation of
	// PublicKey.
	PublicKeyHash string `json:"public_key_hash"`

	// Uuid is the unique identifier for this Trustee.
	Uuid string `json:"uuid"`
}

// A LabeledEntry is an answer associated with a result count field.
type LabeledEntry struct {
	Answer string
	Count  int64
}

// A LabeledQuestion is a question along with the labeled answers to this
// question.
type LabeledQuestion struct {
	Question string
	Answers  []LabeledEntry
}

// A LabeledResult is the labeled results for an election or a ballot.
type LabeledResult []LabeledQuestion

// LabelResults matches up the string questions and answers from an election
// with the results provided by a tally.
func (election *Election) LabelResults(results [][]int64) LabeledResult {
	labeledRes := make([]LabeledQuestion, len(results))
	for i, r := range results {
		q := election.Questions[i]
		labeledRes[i].Question = q.Question
		labeledRes[i].Answers = make([]LabeledEntry, len(q.Answers))
		for j := range q.Answers {
			labeledRes[i].Answers[j] = LabeledEntry{q.Answers[j], r[j]}
		}

	}

	return labeledRes
}

// String creates a printable representation of a LabeledResult.
func (labeledResults LabeledResult) String() string {
	result := ""
	for i := range labeledResults {
		result += labeledResults[i].Question + "\n"
		ans := labeledResults[i].Answers
		for j := range ans {
			result += fmt.Sprintf("\t%s: %d\n", ans[j].Answer, ans[j].Count)
		}
	}

	return result
}

// Audit checks a spoiled ballot to make sure it was formed correctly.  Note
// that this only works on SPOILED ballots---i.e., ones that actually have the
// answers and randomness in them. Ballots that are cast don't have this
// information in them, natch.
func (vote *Ballot) Audit(fingerprint string, ballotJSONData []byte, election *Election) bool {
	// A basic requirement for a ballot is that it pass zero-knowledge-proof verification.
	if !vote.Verify(election) {
		glog.Error("The spoiled ballot did not even pass ZK proof verification")
		return false
	}

	glog.Info("The ballot passed zero-knowledge-proof verification")

	// Then we need to check the supplied fingerprint and all the answers/randomness.
	for i, a := range vote.Answers {
		if len(a.Choices) != len(a.Randomness) {
			glog.Errorf("Answer %d does not have the right amount of randomness\n", i)
			return false
		}

		// This code checks the encryptions based on the definition of exponential ElGamal:
		// Enc(y, m ; r) = (g^r, g^y * g^m)
		for j, c := range a.Choices {
			r := a.Randomness[j]

			// If this is a real answer (in some votes, there can be more than one), then use g^1, otherwise use g^0.
			plaintext := big.NewInt(1)
			for _, val := range a.Answer {
				if int64(j) == val {
					plaintext.Mul(plaintext, election.PublicKey.Generator)
					break
				}
			}

			lhs := new(big.Int)
			// g^randomness mod p == ciphertext.Alpha
			lhs.Exp(election.PublicKey.Generator, r, election.PublicKey.Prime)
			if lhs.Cmp(c.Alpha) != 0 {
				glog.Errorf("The first component of choice %d in answer %d was not correctly encrypted\n", j, i)
				return false
			}

			rhs := new(big.Int)
			// y^randomness * plaintext mod p == ciphertext.Beta
			rhs.Exp(election.PublicKey.PublicValue, r, election.PublicKey.Prime)
			rhs.Mul(rhs, plaintext)
			rhs.Mod(rhs, election.PublicKey.Prime)
			if rhs.Cmp(c.Beta) != 0 {
				glog.Errorf("The second component of choice %d in answer %d was not correctly encrypted\n", j, i)
				return false
			}

		}
	}

	glog.Info("All answers were encrypted correctly")

	answerRegex := regexp.MustCompile(`, "answer": \[[^\]]*\]`)
	randomnessRegex := regexp.MustCompile(`, "randomness": \[[^\]]*\]`)
	ballotMinusAnswers := answerRegex.ReplaceAll(ballotJSONData, []byte(``))
	parsedData := randomnessRegex.ReplaceAll(ballotMinusAnswers, []byte(``))

	h := sha256.Sum256([]byte(strings.TrimSpace(string(parsedData))))
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	computedFingerprint := encodedHash[:len(encodedHash)-1]

	if fingerprint != computedFingerprint {
		glog.Errorf("The fingerprint %s did not match the computed fingerprint %s\n", fingerprint, computedFingerprint)
		return false
	}

	return true
}

// ExtractResult creates a Result from a spoiled Ballot (one that has plaintext
// answers). It returns nil if plaintext answers are missing from the ballot.
func (vote *Ballot) ExtractResult(e *Election) Result {
	r := make([][]int64, len(vote.Answers))
	for i := range vote.Answers {
		r[i] = make([]int64, len(e.Questions[i].Answers))
		for _, a := range vote.Answers[i].Answer {
			r[i][a]++
		}
	}

	return r
}

// GetJSON gets the JSON from the Helios server and converts it into the
// appropriate type, unmarshalling it into the value v. It returns the original
// JSON. It changes the JSON in one way before unmarshalling: it converts all
// big integer values of the form "[0-9]+" into [0-9]+ (i.e., it removes the
// quotes from big integers). This is necessary to get big.Int to unmarshal the
// values from JSON as big integers.
func GetJSON(addr string, v interface{}) ([]byte, error) {
	var err error
	var jsonData []byte
	resp, err := http.Get(addr)
	if err != nil {
		glog.Errorf("Could not get data from the Helios server: %s\n", err)
		return nil, err
	}

	defer resp.Body.Close()
	jsonData, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("Couldn't read the body of the response: %s\n", err)
		return nil, err
	}

	err = UnmarshalJSON(jsonData, v)
	if err != nil {
		glog.Errorf("Could not unmarshal the Helios data: %s\n", err)
		return nil, err
	}

	return jsonData, err
}

// The regular expression used to fix bigIntegers in UnmarshalJSON.
// Technically, this isn't exactly correct, since in principle,
// a hash could consist entirely of numbers. So, this should really be changed
// to know a more detailed context. However, the odds of that happening are
// astronomical. More dangerous would be a string field that happens to contain
// all numbers. This would be parsed incorrectly and would fail in unmarshalling.
// TODO(tmroeder): add more context to the regular expression.
var quotedBigIntRegex = regexp.MustCompile(`"([0-9][0-9]*)"`)

// UnmarshalJSON wraps json.Marshal and fixes inconsistencies between Helios JSON and Go JSON.
// Note that this function doesn't have to undo everything that MarshalJSON does.
func UnmarshalJSON(jsonData []byte, v interface{}) error {
	parsedData := quotedBigIntRegex.ReplaceAll(jsonData, []byte(`$1`))
	err := json.Unmarshal(parsedData, v)
	if err != nil {
		glog.Errorf("Could not unmarshal the data: %s\n", err)
	}

	return err
}

// A non-quoted big integer, used in MarshalJSON.
var bigIntRegex = regexp.MustCompile(`":([0-9][0-9]*)([\]},])`)

// An empty string: these are replaced by null literals in Helios.
var emptyStringRegex = regexp.MustCompile(`""`)

// The max/min numbers are not written as strings, even though the big numbers are.
var maxMinRegex = regexp.MustCompile(`"(max|min)":"([0-9][0-9]*)"`)

// MarshalJSON wraps json.Marshal and fixes inconsistencies between Helios JSON and Go JSON.
func MarshalJSON(v interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	quoted := bigIntRegex.ReplaceAll(jsonData, []byte(`":"$1"$2`))
	nullReplaced := emptyStringRegex.ReplaceAll(quoted, []byte(`null`))
	serialized := maxMinRegex.ReplaceAll(nullReplaced, []byte(`"$1":$2`))
	return serialized, err
}
