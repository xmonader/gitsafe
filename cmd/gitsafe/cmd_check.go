package main

import (
	"fmt"

	"gitsafe/internal/format"
	"gitsafe/internal/gitx"
	"gitsafe/internal/secret"
)

// cmdCheck inspects what is staged and fails if any gitsafe-marked file is about
// to be committed as plaintext — the footgun that happens when the filters are
// not active (a fresh clone before 'gitsafe init', a misconfigured CI runner, or
// an unpinned clone). It is meant to be wired as a pre-commit hook:
//
//	# .git/hooks/pre-commit
//	exec gitsafe check
func cmdCheck(args []string) error {
	rc, err := loadRepo()
	if err != nil {
		return err
	}
	marked, err := gitx.FilteredFiles()
	if err != nil {
		return err
	}
	markedSet := map[string]bool{}
	for _, f := range marked {
		markedSet[f] = true
	}
	staged, err := gitx.StagedFiles()
	if err != nil {
		return err
	}

	// Also treat files matching the policy's secret_paths as secrets, even if a
	// missing .gitattributes entry means git never ran the filter on them — the
	// exact gap (filters not active) this check exists to catch.
	var secretPaths []string
	pol, _ := rc.store.Load()
	if pol != nil {
		secretPaths = pol.SecretPaths
	}

	// The set of age recipients that SHOULD be able to read secrets on this
	// branch, used to flag a staged secret encrypted to anyone who is not a
	// current reader. Best-effort and advisory: a resolution error just skips the
	// recipient warning rather than failing the plaintext check below.
	authorized := map[string]bool{}
	if pol != nil {
		if res, rerr := gitx.BranchResource(); rerr == nil {
			for _, r := range pol.Recipients(res) {
				authorized[r] = true
			}
		}
	}

	var leaking []string
	var misEncrypted []string
	for _, f := range staged {
		isSecret := markedSet[f] || secret.Match(f, secretPaths)
		if !isSecret {
			continue
		}
		blob, found, err := gitx.StoredBlob(f) // reads the staged (index) blob first
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		// A valid envelope must PARSE, not merely start with the magic bytes —
		// otherwise a plaintext secret crafted to begin with the magic would pass
		// the check while sitting in git as cleartext.
		env, perr := format.Parse(blob)
		if perr != nil {
			leaking = append(leaking, f)
			continue
		}
		// Advisory: warn if the secret is encrypted to a recipient who is not a
		// current reader of this branch — a foreign recipient (possible
		// mis-encryption) or a revoked member still able to decrypt until you
		// rotate. A reader missing from the header (not yet rotated in) is benign
		// and not flagged, so this stays quiet for ordinary not-yet-rotated state.
		if len(authorized) > 0 {
			for _, r := range env.Recipients {
				if !authorized[r] {
					misEncrypted = append(misEncrypted, f)
					break
				}
			}
		}
	}

	if len(leaking) > 0 {
		fmt.Println("gitsafe check FAILED — these marked secrets are staged as PLAINTEXT:")
		for _, f := range leaking {
			fmt.Printf("  %s\n", f)
		}
		return fmt.Errorf("refusing to let plaintext secrets be committed; ensure gitsafe is initialized and trusted ('gitsafe init' then 'gitsafe trust'), then 're-stage' the files")
	}
	if len(misEncrypted) > 0 {
		fmt.Println("gitsafe check WARNING — these staged secrets are encrypted to a recipient who is not a current reader of this branch:")
		for _, f := range misEncrypted {
			fmt.Printf("  %s\n", f)
		}
		fmt.Println("(a revoked member can still decrypt until you run 'gitsafe rotate'; an unexpected recipient may mean a mis-encrypted blob)")
	}
	fmt.Println("gitsafe check OK — no marked secret is staged as plaintext.")
	return nil
}
