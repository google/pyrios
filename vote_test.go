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
func (c *Ciphertext) Encrypt(selected bool, proof *DisjunctiveZKProof, pk *Key) (*big.Int, error) {
	// If this value is selected, then use g^1; otherwise, use g^0.
	var plaintext *big.Int
	var realExp, fakeExp int64
	if selected {
		plaintext = &pk.Generator
		realExp = 1
		fakeExp = 0
	} else {
		plaintext = big.NewInt(1)
		realExp = 0
		fakeExp = 1
	}

	var randomness *big.Int
	var err error
	if randomness, err = rand.Int(rand.Reader, &pk.ExponentPrime); err != nil {
		glog.Error("Couldn't get randomness for an encryption")
		return nil, err
	}

	c.Alpha.Exp(&pk.Generator, randomness, &pk.Prime)
	c.Beta.Exp(&pk.PublicValue, randomness, &pk.Prime)
	c.Beta.Mul(&c.Beta, plaintext)
	c.Beta.Mod(&c.Beta, &pk.Prime)

	// Real proof of selected and a simulated proof of !selected
	*proof = make([]ZKProof, 2)

	if err = (*proof).CreateFakeProof(fakeExp, fakeExp, c, pk); err != nil {
		glog.Error("Couldn't create a simulated proof")
		return nil, err
	}

	if err = (*proof).CreateRealProof(realExp, c, randomness, pk); err != nil {
		glog.Error("Couldn't create a real proof")
		return nil, err
	}

	return randomness, nil
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

// Create takes an Election and a set of responses as input and fills in a Ballot
func (vote *Ballot) Create(election *Election, answers [][]int64) error {
	if len(answers) != len(election.Questions) {
		return errors.New("wrong number of answers")
	}

	pk := &election.PublicKey

	vote.ElectionHash = election.ElectionHash
	vote.ElectionUuid = election.Uuid

	vote.Answers = make([]EncryptedAnswer, len(election.Questions))

	for i := range election.Questions {
		q := &election.Questions[i]
		a := answers[i]
		results := make([]bool, len(q.Answers))
		sum := int64(len(a))

		min := q.Min
		max := q.ComputeMax()
		if sum < int64(min) || sum > int64(max) {
			glog.Errorf("Sum was %d, min was %d, and max was %d\n", sum, min, max)
			return errors.New("invalid answers: sum must lie between min and max")
		}

		encAnswer := &vote.Answers[i]
		encAnswer.Choices = make([]Ciphertext, len(results))
		encAnswer.IndividualProofs = make([]DisjunctiveZKProof, len(results))
		encAnswer.Randomness = make([]big.Int, len(results))

		encAnswer.Answer = make([]int64, len(a))
		copy(encAnswer.Answer, a)

		// Mark each selected value as being voted for.
		for _, index := range a {
			results[index] = true
		}

		// Encrypt and create proofs for the answers, then create an overall proof if required
		tally := &Ciphertext{*big.NewInt(1), *big.NewInt(1)}
		randTally := big.NewInt(0)
		for j := range q.Answers {
			var r *big.Int
			var err error
			if r, err = encAnswer.Choices[j].Encrypt(results[j], &encAnswer.IndividualProofs[j], pk); err != nil {
				glog.Errorf("Couldn't encrypt choice %d for question %d\n", j, i)
				return err
			}

			encAnswer.Randomness[j] = *r

			tally.MulCiphertexts(&encAnswer.Choices[j], &pk.Prime)
			randTally.Add(randTally, r)
			randTally.Mod(randTally, &pk.ExponentPrime)
		}

		if q.Max == 0 {
			encAnswer.OverallProof = nil
		} else {
			encAnswer.OverallProof = make([]ZKProof, q.Max-q.Min+1)
			for j := q.Min; j <= q.Max; j++ {
				if int64(j) != sum {
					// Create a simulated proof for the case where the
					// tally actually encrypts the value j.
					if err := encAnswer.OverallProof.CreateFakeProof(int64(j-q.Min), int64(j),
						tally, pk); err != nil {
						glog.Errorf("Couldn't create fake proof %d\n", j)
						return err
					}
				}
			}

			if err := encAnswer.OverallProof.CreateRealProof(sum-int64(q.Min), tally, randTally, pk); err != nil {
				glog.Errorf("Couldn't create the real proof")
				return err
			}
		}
	}

	return nil
}

// Create instantiates a CastBallot for a given set of answers for a Voter.
func (cb *CastBallot) Create(election *Election, answers [][]int64, v *Voter, auditable bool) error {
	// First, create the encrypted vote.
	if err := cb.Vote.Create(election, answers); err != nil {
		glog.Error("Couldn't encrypt a ballot: ", err)
		return err
	}

	if !auditable {
		// Since this is to be a cast ballot, we must strip the randomness and the answers from it.
		for i := range cb.Vote.Answers {
			cb.Vote.Answers[i].Answer = nil
			cb.Vote.Answers[i].Randomness = nil
		}
	}

	cb.CastAt = time.Now().String()
	serializedVote, err := MarshalJSON(&cb.Vote)
	if err != nil {
		glog.Error("Couldn't marshal the JSON for an encrypted ballot")
		return err
	}

	h := sha256.Sum256(serializedVote)
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	cb.VoteHash = encodedHash[:len(encodedHash)-1]

	serializedVoter, err := MarshalJSON(v)
	if err != nil {
		glog.Errorf("Couldn't marshal the JSON for voter %s\n", string(v.Uuid))
		return err
	}

	hv := sha256.Sum256(serializedVoter)
	encodedHV := base64.StdEncoding.EncodeToString(hv[:])
	cb.VoterHash = encodedHV[:len(encodedHV)-1]

	cb.VoterUuid = v.Uuid
	cb.JSON, err = MarshalJSON(cb)
	if err != nil {
		glog.Error("Couldn't marshal the JSON for the whole cast ballot")
		return err
	}

	return nil
}

// Create instantiates a new Voter with the given information and a fresh UUID.
func (v *Voter) Create(name string, id string, computeHash bool, hash string, voterType string) error {
	v.Name = name
	var err error
	if v.Uuid, err = GenUUID(); err != nil {
		glog.Error("Couldn't generate a UUID for a new voter")
		return err
	}

	v.VoterID = id
	if computeHash {
		if len(hash) > 0 {
			return errors.New("can't pass a non-empty hash and compute the hash")
		}

		if len(id) == 0 {
			return errors.New("can't hash an empty identifier")
		}

		h := sha256.Sum256([]byte(id))
		encodedHash := base64.StdEncoding.EncodeToString(h[:])
		v.VoterIDHash = encodedHash[:len(encodedHash)-1]
	} else {
		v.VoterIDHash = hash
	}

	if voterType != "openid" && voterType != "email" {
		return errors.New("voter must have type 'openid' or 'email'")
	}

	return nil
}

// Create instantiates a question with the given answer set and other information.
func (q *Question) Create(answers []string, max int, min int, question string, resultType string, shortName string) error {
	if max < 0 || min < 0 || min > max {
		return errors.New("invalid question min and max")
	}

	if resultType != "absolute" && resultType != "relative" {
		return errors.New("invalid result type")
	}

	q.AnswerUrls = make([]string, len(answers))
	q.Answers = make([]string, len(answers))
	copy(q.Answers, answers)

	// This is the only possible choice type in Helios v3
	q.ChoiceType = "approval"
	q.Max = max
	q.Min = min
	q.Question = question
	q.ShortName = shortName

	// This is the only possible tally type in Helios v3
	q.TallyType = "homomorphic"

	return nil
}

// Create uses a given set of parameters to generate a public key.
func (k *Key) CreateFromParams(g *big.Int, p *big.Int, q *big.Int) (*big.Int, error) {
	k.Generator = *g
	k.Prime = *p
	k.ExponentPrime = *q

	secret, err := rand.Int(rand.Reader, q)
	if err != nil {
		glog.Error("Couldn't generate a secret for the key")
		return nil, err
	}

	k.PublicValue.Exp(g, secret, p)
	return secret, nil

}

// Create generates a fresh set of parameters and a public/private key pair in
// those parameters.
func (k *Key) Create() (*big.Int, error) {
	// Use the DSA crypto code to generate a key pair. For testing
	// purposes, we'll use (2048,224) instead of (2048,160) as used by the
	// current Helios implementation
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N224); err != nil {
		glog.Error("Couldn't generate DSA parameters for the ElGamal group")
		return nil, err
	}

	return k.CreateFromParams(params.G, params.P, params.Q)
}

// Create instantiates a new election with the given parameters.
func (e *Election) Create(url string, desc string, frozenAt string, name string,
	openreg bool, questions []Question, shortName string,
	useVoterAliases bool, votersHash string, votingEnd string,
	votingStart string, k *Key) (*big.Int, error) {
	e.CastURL = url
	e.Description = desc
	e.FrozenAt = frozenAt
	e.Name = name
	e.Openreg = openreg
	e.Questions = questions
	e.ShortName = shortName
	e.UseVoterAliases = useVoterAliases

	var err error
	if e.Uuid, err = GenUUID(); err != nil {
		glog.Error("Couldn't generate an election UUID")
		return nil, err
	}

	var secret *big.Int
	if k == nil {
		if secret, err = e.PublicKey.Create(); err != nil {
			glog.Error("Couldn't generate a new key for the election")
			return nil, err
		}
	} else {
		// Take the public params from k to generate the key.
		if secret, err = e.PublicKey.CreateFromParams(&k.Generator, &k.Prime, &k.ExponentPrime); err != nil {
			glog.Error("Couldn't generate a new key for the election")
			return nil, err
		}
	}

	e.VotersHash = votersHash
	e.VotingEndsAt = votingEnd
	e.VotingStartsAt = votingStart

	// Compute the JSON of the election and compute its hash
	if e.JSON, err = MarshalJSON(e); err != nil {
		glog.Error("Couldn't marshal the election as JSON")
		return nil, err
	}

	h := sha256.Sum256(e.JSON)
	encodedHash := base64.StdEncoding.EncodeToString(h[:])
	e.ElectionHash = encodedHash[:len(encodedHash)-1]

	return secret, nil
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
func (e *Election) Tally(votes []CastBallot, trustees []Trustee, trusteeSecrets []big.Int) Result {
	tallies, voteFingerprints := e.AccumulateTallies(votes)
	// TODO(tmroeder): maybe we should just skip votes that don't pass verification?
	// What does the spec say?
	if len(voteFingerprints) == 0 {
		glog.Error("Couldn't tally the votes")
		return nil
	}

	for k := range trustees {
		t := &trustees[k]
		t.DecryptionFactors = make([][]big.Int, len(e.Questions))
		t.DecryptionProofs = make([][]ZKProof, len(e.Questions))
		for i := range e.Questions {
			q := &e.Questions[i]
			t.DecryptionFactors[i] = make([]big.Int, len(q.Answers))
			t.DecryptionProofs[i] = make([]ZKProof, len(q.Answers))
			for j := range q.Answers {
				t.DecryptionFactors[i][j].Exp(&tallies[i][j].Alpha,
					&trusteeSecrets[k], &t.PublicKey.Prime)
				if err := t.DecryptionProofs[i][j].CreatePartialDecryptionProof(
					&tallies[i][j], &t.DecryptionFactors[i][j], &trusteeSecrets[k], &t.PublicKey); err != nil {
					glog.Errorf("Couldn't create a proof for (%d, %d) for trustee %d\n", i, j, k)
					return nil
				}
			}
		}
	}

	// For each question and each answer, reassemble the tally and search for its value.
	// Then put this in the results.
	maxValue := len(votes)
	result := make([][]int64, len(e.Questions))
	for i := range e.Questions {
		q := &e.Questions[i]
		result[i] = make([]int64, len(q.Answers))
		for j := range q.Answers {
			alpha := big.NewInt(1)
			for k := range trustees {
				alpha.Mul(alpha, &trustees[k].DecryptionFactors[i][j])
				alpha.Mod(alpha, &trustees[k].PublicKey.Prime)
			}

			var beta big.Int
			beta.ModInverse(alpha, &e.PublicKey.Prime)
			beta.Mul(&beta, &tallies[i][j].Beta)
			beta.Mod(&beta, &e.PublicKey.Prime)

			// This decrypted value can be anything between g^0 and g^maxValue.
			// Try all values until we find it.
			var temp big.Int
			var val big.Int
			var v int
			for v = 0; v <= maxValue; v++ {
				val.SetInt64(int64(v))
				temp.Exp(&e.PublicKey.Generator, &val, &e.PublicKey.Prime)
				if temp.Cmp(&beta) == 0 {
					result[i][j] = int64(v)
					break
				}
			}

			if v > maxValue {
				glog.Errorf("Couldn't decrypt value (%d, %d)\n", i, j)
				return nil
			}
		}
	}

	return result
}
