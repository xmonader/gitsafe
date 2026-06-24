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
	if pol, _ := rc.store.Load(); pol != nil {
		secretPaths = pol.SecretPaths
	}

	var leaking []string
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
		if _, perr := format.Parse(blob); perr != nil {
			leaking = append(leaking, f)
		}
	}

	if len(leaking) > 0 {
		fmt.Println("gitsafe check FAILED — these marked secrets are staged as PLAINTEXT:")
		for _, f := range leaking {
			fmt.Printf("  %s\n", f)
		}
		return fmt.Errorf("refusing to let plaintext secrets be committed; ensure gitsafe is initialized and trusted ('gitsafe init' then 'gitsafe trust'), then 're-stage' the files")
	}
	fmt.Println("gitsafe check OK — no marked secret is staged as plaintext.")
	return nil
}
