// Command release-gate validates release notes headings and required CI on a SHA.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var requiredHeadings = []string{
	"Highlights",
	"Added",
	"Residual",
	"Deployment and operations",
	"CI and release evidence",
}

var requiredCIJobs = []string{
	"format", "lint", "unit", "race", "fuzz-smoke", "documentation",
	"config-compat", "changelog", "generated-file", "parity", "security-scan",
	"container-test", "web",
}

func main() {
	notesOnly := flag.Bool("notes-only", false, "validate notes headings only")
	notes := flag.String("notes", "", "path to docs/releases/vX.Y.Z.md")
	requireCI := flag.Bool("require-ci", false, "require green CI on GITHUB_SHA or HEAD")
	flag.Parse()
	if *notesOnly {
		if *notes == "" {
			fatal(fmt.Errorf("-notes-only requires -notes"))
		}
		if err := validateNotes(*notes); err != nil {
			fatal(err)
		}
		return
	}
	if *requireCI {
		if err := requireGreenCI(); err != nil {
			fatal(err)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "usage: release-gate -notes-only -notes PATH | -require-ci\n")
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "release-gate: %v\n", err)
	os.Exit(1)
}

func validateNotes(path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(body)
	for _, h := range requiredHeadings {
		if !strings.Contains(text, "## "+h) && !strings.Contains(text, "# "+h) {
			return fmt.Errorf("notes %s missing heading %q", path, h)
		}
	}
	for _, bad := range []string{"TODO", "TBD", "FIXME"} {
		if strings.Contains(text, bad) {
			return fmt.Errorf("notes %s contains %s", path, bad)
		}
	}
	return nil
}

// releaseTag is the bare tag the gate must match against headBranch.
// GITHUB_REF wins when it is a tag ref; otherwise GITHUB_REF_NAME is used.
// Both sources are stripped of a refs/tags/ prefix. An empty result, including
// a branch ref with an empty name, is an error.
func releaseTag() (string, error) {
	ref := strings.TrimSpace(os.Getenv("GITHUB_REF"))
	name := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
	var tag string
	switch {
	case strings.HasPrefix(ref, "refs/tags/"):
		tag = strings.TrimPrefix(ref, "refs/tags/")
	case strings.HasPrefix(ref, "refs/heads/") && name == "":
		return "", fmt.Errorf("release tag is empty")
	default:
		tag = strings.TrimPrefix(name, "refs/tags/")
	}
	if tag == "" {
		return "", fmt.Errorf("release tag is empty")
	}
	return tag, nil
}

func requireGreenCI() error {
	sha := strings.TrimSpace(os.Getenv("GITHUB_SHA"))
	if sha == "" {
		out, err := exec.Command("git", "rev-parse", "HEAD").Output()
		if err != nil {
			return fmt.Errorf("rev-parse HEAD: %w", err)
		}
		sha = strings.TrimSpace(string(out))
	}
	tag, err := releaseTag()
	if err != nil {
		return err
	}
	cmd := exec.Command("gh", "run", "list",
		"--workflow=ci.yml",
		"--commit="+sha,
		"--json", "databaseId,conclusion,status,headSha,event,displayTitle,headBranch")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("gh run list: %w", err)
	}
	var runs []struct {
		DatabaseID int    `json:"databaseId"`
		Conclusion string `json:"conclusion"`
		Status     string `json:"status"`
		HeadSHA    string `json:"headSha"`
		HeadBranch string `json:"headBranch"`
		Event      string `json:"event"`
	}
	if err := json.Unmarshal(out, &runs); err != nil {
		return fmt.Errorf("parse gh run list: %w", err)
	}
	found := false
	var newest struct {
		DatabaseID int
		Status     string
	}
	for _, r := range runs {
		if r.Event != "push" || r.HeadSHA != sha || r.HeadBranch != tag {
			continue
		}
		if !found || r.DatabaseID > newest.DatabaseID {
			newest.DatabaseID = r.DatabaseID
			newest.Status = r.Status
			found = true
		}
	}
	if !found {
		return fmt.Errorf("no matching run for tag %s commit %s", tag, sha)
	}
	if newest.Status != "completed" {
		return fmt.Errorf("CI run %d for tag %s is pending (status %s)", newest.DatabaseID, tag, newest.Status)
	}
	id := newest.DatabaseID
	view := exec.Command("gh", "run", "view", fmt.Sprintf("%d", id), "--json", "jobs")
	jobJSON, err := view.Output()
	if err != nil {
		return fmt.Errorf("gh run view: %w", err)
	}
	var payload struct {
		Jobs []struct {
			Name       string `json:"name"`
			Conclusion string `json:"conclusion"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(jobJSON, &payload); err != nil {
		return fmt.Errorf("parse jobs: %w", err)
	}
	got := map[string]string{}
	for _, j := range payload.Jobs {
		got[j.Name] = j.Conclusion
	}
	var missing []string
	for _, name := range requiredCIJobs {
		if got[name] != "success" {
			missing = append(missing, fmt.Sprintf("%s=%s", name, got[name]))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required CI jobs not green: %s", strings.Join(missing, ", "))
	}
	return nil
}
