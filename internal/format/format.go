// Package format defines gitsafe's on-disk (in-git) ciphertext envelope and the
// locked-notice placeholder shown to users without read access.
//
// The envelope wraps raw age ciphertext with a small, public header recording
// the recipient set it was encrypted to. The header lets the clean filter keep
// encryption deterministic: when re-staging an unchanged secret to the same
// readers, it can recognize the stored blob and re-emit it byte-for-byte
// instead of producing fresh (randomized) age ciphertext that git would see as
// a spurious modification.
//
// Wire layout:
//
//	MAGIC (9 bytes: "\x00gitsafe\x00")
//	uint32 big-endian header length
//	header JSON: {"v":1,"recipients":["age1...",...]}  (recipients sorted)
//	age ciphertext (binary, to end of blob)
package format

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Magic identifies a gitsafe-encrypted blob. The leading NUL marks it binary to
// git and avoids colliding with any plaintext file.
var Magic = []byte("\x00gitsafe\x00")

// Version is the current envelope format version.
const Version = 1

// maxHeaderLen caps the declared header length Parse will honor. The header only
// holds a small JSON recipient list; a larger value means a corrupt or hostile
// blob, and the cap stops it from forcing a large slice/allocation.
const maxHeaderLen = 1 << 20 // 1 MiB

// header is the JSON metadata carried in plaintext alongside the ciphertext.
type header struct {
	V          int      `json:"v"`
	Recipients []string `json:"recipients"`
}

// Envelope is a parsed gitsafe blob.
type Envelope struct {
	Recipients []string
	Ciphertext []byte
}

// IsWrapped reports whether data is a gitsafe envelope.
func IsWrapped(data []byte) bool {
	return bytes.HasPrefix(data, Magic)
}

// Wrap builds an envelope from the recipient set and raw age ciphertext.
// recipients must already be sorted (policy.Recipients sorts them).
func Wrap(recipients []string, ciphertext []byte) []byte {
	h, _ := json.Marshal(header{V: Version, Recipients: recipients})
	var buf bytes.Buffer
	buf.Write(Magic)
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(h)))
	buf.Write(lenb[:])
	buf.Write(h)
	buf.Write(ciphertext)
	return buf.Bytes()
}

// Parse decodes a gitsafe envelope.
func Parse(data []byte) (*Envelope, error) {
	if !IsWrapped(data) {
		return nil, fmt.Errorf("not a gitsafe envelope")
	}
	rest := data[len(Magic):]
	if len(rest) < 4 {
		return nil, fmt.Errorf("truncated gitsafe header length")
	}
	hlen := binary.BigEndian.Uint32(rest[:4])
	if hlen > maxHeaderLen {
		return nil, fmt.Errorf("gitsafe header length %d exceeds maximum %d (corrupt blob)", hlen, maxHeaderLen)
	}
	rest = rest[4:]
	if uint32(len(rest)) < hlen {
		return nil, fmt.Errorf("truncated gitsafe header")
	}
	var h header
	if err := json.Unmarshal(rest[:hlen], &h); err != nil {
		return nil, fmt.Errorf("parse gitsafe header: %w", err)
	}
	if h.V != Version {
		return nil, fmt.Errorf("unsupported gitsafe envelope version %d", h.V)
	}
	return &Envelope{Recipients: h.Recipients, Ciphertext: rest[hlen:]}, nil
}

// placeholderMarker is the stable first line of a locked placeholder. The clean
// filter keys off it to avoid ever encrypting a placeholder over the real
// secret (which would destroy data for everyone).
const placeholderMarker = "#gitsafe-locked-placeholder v1"

// LockedPlaceholder returns the deterministic working-tree content shown to a
// user who cannot decrypt path on this branch. Deterministic content keeps
// `git status` clean for locked users (re-cleaning it reproduces the stored
// ciphertext, see the clean filter).
func LockedPlaceholder(path string) []byte {
	return []byte(placeholderMarker + "\n" +
		"# This file is gitsafe-encrypted and you do not have read access to it\n" +
		"# on the current branch. Path: " + path + "\n" +
		"# Do NOT edit or commit this placeholder; doing so is rejected to protect\n" +
		"# the underlying secret. Ask an admin for read access, then re-checkout.\n")
}

// IsLockedPlaceholder reports whether data is a gitsafe locked placeholder.
func IsLockedPlaceholder(data []byte) bool {
	return bytes.HasPrefix(data, []byte(placeholderMarker))
}
