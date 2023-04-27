package nitriding

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"context"

	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/docker/docker/client"
)

const (
	nonceLen       = 20           // The size of a nonce in bytes.
	nonceNumDigits = nonceLen * 2 // The number of hex digits in a nonce.
	maxAttDocLen   = 5000         // A (reasonable?) upper limit for attestation doc lengths.
	hashPrefix     = "sha256:"
	hashSeparator  = ";"
)

var (
	errMethodNotGET      = "only HTTP GET requests are allowed"
	errMethodNotPOST     = "only HTTP POST requests are allowed"
	errBadForm           = "failed to parse POST form data"
	errNoNonce           = "could not find nonce in URL query parameters"
	errBadNonceFormat    = fmt.Sprintf("unexpected nonce format; must be %d-digit hex string", nonceNumDigits)
	errFailedAttestation = "failed to obtain attestation document from hypervisor"
	nonceRegExp          = fmt.Sprintf("[a-f0-9]{%d}", nonceNumDigits)

	// getPCRValues is a variable pointing to a function that returns PCR
	// values.  Using a variable allows us to easily mock the function in our
	// unit tests.
	getPCRValues = func() (map[uint][]byte, error) { return _getPCRValues() }
)

// AttestationHashes contains hashes over public key material which we embed in
// the enclave's attestation document for clients to verify.
type AttestationHashes struct {
	tlsKeyHash [sha256.Size]byte // Always set.
	appKeyHash [sha256.Size]byte // Sometimes set, depending on application.
}

// Serialize returns a byte slice that contains our concatenated hashes.  Note
// that all hashes are always present.  If a hash was not initialized, it's set
// to 0-bytes.
func (a *AttestationHashes) Serialize() []byte {
	str := fmt.Sprintf("%s%s%s%s%s",
		hashPrefix,
		a.tlsKeyHash,
		hashSeparator,
		hashPrefix,
		a.appKeyHash)
	return []byte(str)
}

// attestationHandler takes as input an AttestationHashes struct and returns a
// HandlerFunc.  This HandlerFunc expects a nonce in the URL query parameters
// and subsequently asks its hypervisor for an attestation document that
// contains both the nonce and the hashes in the given struct.  The resulting
// Base64-encoded attestation document is then returned to the requester.
func attestationHandler(hashes *AttestationHashes) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, errMethodNotGET, http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, errBadForm, http.StatusBadRequest)
			return
		}

		rawDoc, err := attest(nil, hashes.Serialize(), nil)
		if err != nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Write(rawDoc)
	}
}

// certHandler takes as input a pointer to a byte slice that contains a
// certificate.  It returns a HandlerFunc that returns the certificate to the
// requester.  If the certificate is nil, the HandlerFunc returns an error.
func certHandler(cert *[]byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, errMethodNotGET, http.StatusMethodNotAllowed)
			return
		}

		if cert == nil {
			http.Error(w, errFailedAttestation, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Write(*cert)
	}
}

// certHandler takes as input a pointer to a byte slice that contains a
// certificate.  It returns a HandlerFunc that returns the certificate to the
// requester.  If the certificate is nil, the HandlerFunc returns an error.
func imageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()

		if r.Method != http.MethodPost {
			http.Error(w, errMethodNotPOST, http.StatusMethodNotAllowed)
			return
		}

		file, _, err := r.FormFile("image")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cli.Close()

		imgLoadResp, err := cli.ImageLoad(ctx, file, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		imgLoadResp.Body.Close()

		ports := make(map[nat.Port][]nat.PortBinding)
		ports["8000/tcp"] = []nat.PortBinding{nat.PortBinding{
			HostIP: "127.0.0.1",
			HostPort: "8000",
		}}

		resp, err := cli.ContainerCreate(ctx, &container.Config{
			Image: "box",
		}, &container.HostConfig{
			PortBindings: ports,
		}, nil, nil, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	
		if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(200)
	}
}

// _getPCRValues returns the enclave's platform configuration register (PCR)
// values.
func _getPCRValues() (map[uint][]byte, error) {
	rawAttDoc, err := attest(nil, nil, nil)
	if err != nil {
		return nil, err
	}

	res, err := nitrite.Verify(rawAttDoc, nitrite.VerifyOptions{})
	if err != nil {
		return nil, err
	}

	return res.Document.PCRs, nil
}

// arePCRsIdentical returns true if (and only if) the two given PCR maps are
// identical.
func arePCRsIdentical(ourPCRs, theirPCRs map[uint][]byte) bool {
	if len(ourPCRs) != len(theirPCRs) {
		return false
	}

	for pcr, ourValue := range ourPCRs {
		theirValue, exists := theirPCRs[pcr]
		if !exists {
			return false
		}
		if !bytes.Equal(ourValue, theirValue) {
			return false
		}
	}
	return true
}

// attest takes as input a nonce, user-provided data and a public key, and then
// asks the Nitro hypervisor to return a signed attestation document that
// contains all three values.
func attest(nonce, userData, publicKey []byte) ([]byte, error) {
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = s.Close(); err != nil {
			elog.Printf("Attestation: Failed to close default NSM session: %s", err)
		}
	}()

	res, err := s.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}
