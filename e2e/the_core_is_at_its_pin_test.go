package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMain refuses to run the end-to-end tests against a core that is not the
// one this repository pins. The e2e module builds the core from the submodule
// third_party/identity-bot, so a submodule moved to another commit, or edited
// in place, would make these tests prove something about code nobody
// committed. ALLOW_UNPINNED_CORE=1 runs them anyway, for deliberate work on the
// core.
func TestMain(m *testing.M) {
	if os.Getenv("ALLOW_UNPINNED_CORE") != "1" {
		if err := theCoreIsAtItsPin(); err != nil {
			fmt.Fprintln(os.Stderr, "e2e:", err, "(ALLOW_UNPINNED_CORE=1 to run anyway)")
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func theCoreIsAtItsPin() error {
	const sub = "third_party/identity-bot"
	git := func(args ...string) (string, error) {
		out, err := exec.Command("git", args...).Output()
		return strings.TrimSpace(string(out)), err
	}
	top, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("cannot find the repository: %w", err)
	}
	// The commit the parent records for the submodule: "160000 commit <sha>\t<path>".
	entry, err := git("-C", top, "ls-tree", "HEAD", sub)
	if err != nil || entry == "" {
		return fmt.Errorf("%s is not recorded in this commit", sub)
	}
	fields := strings.Fields(entry)
	if len(fields) < 3 {
		return fmt.Errorf("cannot read the pin of %s: %q", sub, entry)
	}
	pinned := fields[2]
	head, err := git("-C", top+"/"+sub, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("%s is not checked out (git submodule update --init %s)", sub, sub)
	}
	if head != pinned {
		return fmt.Errorf("%s is at %s, but this commit pins %s", sub, head, pinned)
	}
	dirty, err := git("-C", top+"/"+sub, "status", "--porcelain")
	if err != nil {
		return fmt.Errorf("cannot read the state of %s: %w", sub, err)
	}
	if dirty != "" {
		return fmt.Errorf("%s has uncommitted changes", sub)
	}
	return nil
}
