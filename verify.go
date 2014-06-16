package pyrios

import (
	"crypto/sha1"
	"math/big"
	"strings"

	"github.com/golang/glog"
)

// A SchnorrProof is the proof that a Trustee knows the private key share
// corresponding to Trustee.DecryptionFactors. The Commitment in this case is
// only a single integer rather than a two-part commitment like in ZKProof.
type SchnorrProof struct {
	// Challenge is the value sent by the Verifier to the Prover.
	Challenge big.Int `json:"challenge"`

	// Commitment is a commitment to a random value used in the proof. It
	// is sent from the Prover to the Verifier.
	Commitment big.Int `json:"commitment"`

	// Response is the response to the Challenge. It is sent from the
	// Prover to the Verifier.
	Response big.Int `json:"response"`
}

// A Commit is the commitment part of a Chaum-Pedersen proof of knowledge. To
// prove knowledge of a value r, the prover first commits to a random value w
// by sending an instance of a Commit.
type Commit struct {
	// A is the first part of a commitment: A = g^w mod p.
	A big.Int `json:"a"`

	// B is the second part of a commitment: B = y^w mod p.
	B big.Int `json:"b"`
}

// A ZKProof is a Chaum-Pedersen zero-knowledge proof of knowledge of a random
// value r. The interactive version of the protocol works like this:
// 0. Prover creates commitment for random value w mod Key.ExponentPrime.
// 1. Prover -> Verifier: commitment Commit.
// 2. Verifier -> Prover: challenge big.Int (random value mod Key.ExponentPrime).
// 3. Prover -> Verifier: response big.Int  (response = w + challenge * r).
// Verifier checks the ZKProof using the algorithm in Verify.
//
// This is turned into a non-interactive proof (called a NIZKPOK) for a
// DisjunctiveZKProof with n ZKProof components by constructing the challenges
// using a hash function over the commitments: compute sha1.Sum(A_0.String() +
// "," + B_0.String() + ... + A_n.String() + "," + B_n.String()), then split
// this digest into n challenges mod q (just like in (n, n) secret sharing) by
// choosing the first n-1 challenges c_0, ..., c_{n-2} as needed to fake the
// simulated proofs, and doing a real proof for c_{n-1} = (digest - sum(c_0,
// ..., c_{n-2})) mod q.  Under the random-oracle assumption on the hash
// function, this makes c_{n-1} unpredictable, hence the ZKProof using c_{n-1}
// must be real and not faked.  And this one proof must be for the actual value
// used in the encryption, since (with overwhelming probability) the prover
// wouldn't be able to successfully prove anything else against a random
// challenge value.
type ZKProof struct {
	Challenge  big.Int `json:"challenge"`
	Commitment Commit  `json:"commitment"`
	Response   big.Int `json:"response"`
}

// Verify checks the Chaum-Pedersen zero-knowledge proof for the
// well-formedness of a Ciphertext, given the purported plaintext and the public
// key. Note that a ZKProof might pass verification and yet be a simulated (i.e.,
// fake) proof in a sequence of ZKProof values that make up a
// DisjunctiveZKProof. This is the case because ZKProof is merely the transcript
// of a sigma protocol. And this is OK because at least one proof in a
// DisjunctiveZKProof must be real, as checked by Verify for DisjunctiveZKProof.
func (proof *ZKProof) Verify(ciphertext *Ciphertext, plaintext *big.Int, publicKey *Key) bool {
	lhs := new(big.Int)
	// g^response mod p
	lhs = lhs.Exp(&publicKey.Generator, &proof.Response, &publicKey.Prime)
	rhs := new(big.Int)
	// alpha^challenge mod p
	rhs = rhs.Exp(&ciphertext.Alpha, &proof.Challenge, &publicKey.Prime)
	// A * alpha^challenge mod p
	rhs = rhs.Mul(rhs, &proof.Commitment.A)
	rhs = rhs.Mod(rhs, &publicKey.Prime)
	if lhs.Cmp(rhs) != 0 {
		glog.Error("The first proof verification check failed")
		return false
	}

	BetaOverM := new(big.Int)
	// g^plaintext mod p
	BetaOverM = BetaOverM.Exp(&publicKey.Generator, plaintext, &publicKey.Prime)
	// 1/g^plaintext mod p
	BetaOverM = BetaOverM.ModInverse(BetaOverM, &publicKey.Prime)
	// beta/g^plaintext mod p
	BetaOverM = BetaOverM.Mul(BetaOverM, &ciphertext.Beta)
	BetaOverM = BetaOverM.Mod(BetaOverM, &publicKey.Prime)

	// y^response mod p
	lhs = lhs.Exp(&publicKey.PublicValue, &proof.Response, &publicKey.Prime)
	// (beta/g^plaintext)^challenge mod p
	rhs = rhs.Exp(BetaOverM, &proof.Challenge, &publicKey.Prime)
	// B * (beta/g^plaintext)^challenge mod p
	rhs = rhs.Mul(rhs, &proof.Commitment.B)
	rhs = rhs.Mod(rhs, &publicKey.Prime)

	if lhs.Cmp(rhs) != 0 {
		glog.Error("The second proof check failed")
		return false
	}

	return true
}

// VerifyPartialDecryption checks a given partial decryption proof produced by
// a Trustee with Trustee.PublicKey = publicKey. It is given the encrypted
// answer in ciphertext and the supposed partial decryption in decFactor. Note
// that since the DDH tuple this time is (g, y, alpha, decFactor), the
// commitment has A = g^w and B = alpha^w.
func (proof *ZKProof) VerifyPartialDecryption(ciphertext *Ciphertext, decFactor *big.Int, publicKey *Key) bool {
	lhs := big.NewInt(1)
	// g^response mod p
	lhs.Exp(&publicKey.Generator, &proof.Response, &publicKey.Prime)

	rhs := big.NewInt(1)
	// y^challenge mod p
	rhs.Exp(&publicKey.PublicValue, &proof.Challenge, &publicKey.Prime)
	// A * y^challenge mod p
	rhs.Mul(rhs, &proof.Commitment.A)
	rhs.Mod(rhs, &publicKey.Prime)
	if lhs.Cmp(rhs) != 0 {
		glog.Error("The first check failed in a partial decryption proof")
		return false
	}

	// alpha^response mod p
	lhs.Exp(&ciphertext.Alpha, &proof.Response, &publicKey.Prime)

	// decFactor^challenge mod p
	rhs.Exp(decFactor, &proof.Challenge, &publicKey.Prime)
	// B * decFactor^challenge mod p
	rhs.Mul(rhs, &proof.Commitment.B)
	rhs.Mod(rhs, &publicKey.Prime)
	if lhs.Cmp(rhs) != 0 {
		glog.Error("The second check failed in a partial decryption proof")
		return false
	}

	// The challenge creation in this case is simple, since there's only one
	// proof value.
	stringToHash := proof.Commitment.A.String() + "," + proof.Commitment.B.String()
	hashedChall := sha1.Sum([]byte(stringToHash))

	var computedChall big.Int
	computedChall.SetBytes(hashedChall[:])

	if computedChall.Cmp(&proof.Challenge) != 0 {
		glog.Error("The computed challenge in a partial decryption proof didn't match")
		return false
	}

	return true
}

// A DisjunctiveZKProof is a sequence of ZKProofs for values Min through Max
// (usually corresponding to Question.Min and Question.Max). Only one of the
// values is a real ZKProof; the others are simulated. It is constructed using
// the Fiat-Shamir heuristic as described in the comment for ZKProof.
type DisjunctiveZKProof []ZKProof

// Verify checks the validity of a sequence of ZKProof values that are supposed
// to encode proofs that the ciphertext is a value in [min, max].
func (zkproof *DisjunctiveZKProof) Verify(min int, max int, ciphertext *Ciphertext, publicKey *Key) bool {
	// The computed challenge is the sum mod q of all the challenges, as
	// described in the documentation of ZKProof. Since it's a sum, it must
	// start at 0.
	computedChall := big.NewInt(0)
	var commitVals []string
	val := min
	total := max - min + 1
	if total != len(*zkproof) {
		glog.Errorf("Wrong number of proofs provided to VerifyDisjunctiveProof: expected %d but saw %d\n",
			total, len(*zkproof))
		return false
	}

	for i := range *zkproof {
		plaintext := big.NewInt(int64(val))
		val++
		p := &((*zkproof)[i])
		if !p.Verify(ciphertext, plaintext, publicKey) {
			glog.Errorf("Couldn't verify the proof for plaintext %s\n", plaintext)
			return false
		}

		// Accumulate the homomorphic product to sum the challenge
		// values.
		computedChall.Add(computedChall, &p.Challenge)

		commitVals = append(commitVals, p.Commitment.A.String())
		commitVals = append(commitVals, p.Commitment.B.String())
	}

	computedChall.Mod(computedChall, &publicKey.ExponentPrime)

	// Check that the challenge was well-formed.
	stringToHash := strings.Join(commitVals, ",")
	hashedCommits := sha1.Sum([]byte(stringToHash))

	var hashedChall big.Int
	hashedChall.SetBytes(hashedCommits[:])
	if hashedChall.Cmp(computedChall) != 0 {
		glog.Error("The computed challenge did not match the hashed challenge")
		return false
	}

	return true
}
