package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func successJobsJSON() string {
	return jobsJSON(nil)
}

func jobsJSON(overrides map[string]string) string {
	var b strings.Builder
	b.WriteString(`{"jobs":[`)
	for i, name := range requiredCIJobs {
		if i > 0 {
			b.WriteByte(',')
		}
		conclusion := "success"
		if overrides != nil {
			if v, ok := overrides[name]; ok {
				conclusion = v
			}
		}
		fmt.Fprintf(&b, `{"name":%q,"conclusion":%q}`, name, conclusion)
	}
	b.WriteString(`]}`)
	return b.String()
}

func runRow(id int, event, status, sha, branch, conclusion string) string {
	return fmt.Sprintf(
		`{"databaseId":%d,"conclusion":%q,"status":%q,"headSha":%q,"event":%q,"headBranch":%q,"displayTitle":"t"}`,
		id, conclusion, status, sha, event, branch,
	)
}

func installFakeGH(t *testing.T, listBody string, jobsByID map[string]string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "list.json"), []byte(listBody), 0o644); err != nil {
		t.Fatal(err)
	}
	for id, body := range jobsByID {
		name := "jobs.json"
		if id != "" {
			name = "jobs-" + id + ".json"
		}
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\n" +
		"dir=$(CDPATH= cd -- \"$(dirname \"$0\")\" && pwd)\n" +
		"if [ \"$1\" = \"run\" ] && [ \"$2\" = \"list\" ]; then\n" +
		"  cat \"$dir/list.json\"\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"run\" ] && [ \"$2\" = \"view\" ]; then\n" +
		"  id=\"$3\"\n" +
		"  if [ -f \"$dir/jobs-$id.json\" ]; then\n" +
		"    cat \"$dir/jobs-$id.json\"\n" +
		"    exit 0\n" +
		"  fi\n" +
		"  if [ -f \"$dir/jobs.json\" ]; then\n" +
		"    cat \"$dir/jobs.json\"\n" +
		"    exit 0\n" +
		"  fi\n" +
		"fi\n" +
		"echo \"unexpected gh $*\" >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func setTagEnv(t *testing.T, sha string) {
	t.Helper()
	t.Setenv("GITHUB_SHA", sha)
	t.Setenv("GITHUB_REF", "refs/tags/v1.2.3")
	t.Setenv("GITHUB_REF_NAME", "v1.2.3")
}

// TestRequireGreenCIRejectsNonPushRun asserts the tag gate does not
// accept a completed pull_request run just because it shares GITHUB_SHA.
func TestRequireGreenCIRejectsNonPushRun(t *testing.T) {
	const sha = "abc123deadbeef"
	installFakeGH(t, "["+runRow(42, "pull_request", "completed", sha, "feature", "success")+"]", map[string]string{
		"42": successJobsJSON(),
	})
	setTagEnv(t, sha)
	err := requireGreenCI()
	if err == nil || !strings.Contains(err.Error(), "no matching run") {
		t.Fatalf("err=%v want no matching run", err)
	}
}

// TestRequireGreenCIAcceptsTagPush is the guard: the tag's own completed
// push run, with every required job green, satisfies the gate.
func TestRequireGreenCIAcceptsTagPush(t *testing.T) {
	const sha = "abc123deadbeef"
	installFakeGH(t, "["+runRow(7, "push", "completed", sha, "v1.2.3", "success")+"]", map[string]string{
		"7": successJobsJSON(),
	})
	setTagEnv(t, sha)
	if err := requireGreenCI(); err != nil {
		t.Fatal(err)
	}
}

// TestRequireGreenCIRejectsMainPushSameSHA asserts a main-branch push of
// the tagged SHA does not satisfy the tag gate.
func TestRequireGreenCIRejectsMainPushSameSHA(t *testing.T) {
	const sha = "abc123deadbeef"
	installFakeGH(t, "["+runRow(7, "push", "completed", sha, "main", "success")+"]", map[string]string{
		"7": successJobsJSON(),
	})
	setTagEnv(t, sha)
	err := requireGreenCI()
	if err == nil || !strings.Contains(err.Error(), "no matching run") {
		t.Fatalf("err=%v want no matching run", err)
	}
}

// TestRequireGreenCIRejectsInProgressTagPush asserts the newest tag push
// still in progress fails the gate even when an older tag push is green.
func TestRequireGreenCIRejectsInProgressTagPush(t *testing.T) {
	const sha = "abc123deadbeef"
	list := "[" + runRow(10, "push", "completed", sha, "v1.2.3", "success") + "," +
		runRow(20, "push", "in_progress", sha, "v1.2.3", "") + "]"
	installFakeGH(t, list, map[string]string{"10": successJobsJSON()})
	setTagEnv(t, sha)
	err := requireGreenCI()
	if err == nil {
		t.Fatal("in-progress tag push must not fall through to an older green run")
	}
	if !strings.Contains(err.Error(), "pending") || strings.Contains(err.Error(), "no matching run") {
		t.Fatalf("err=%v want pending and not no matching run", err)
	}
}

// TestRequireGreenCIIgnoresInProgressPullRequest asserts an in-progress
// pull_request run does not hide a completed green tag push.
func TestRequireGreenCIIgnoresInProgressPullRequest(t *testing.T) {
	const sha = "abc123deadbeef"
	list := "[" + runRow(10, "push", "completed", sha, "v1.2.3", "success") + "," +
		runRow(20, "pull_request", "in_progress", sha, "v1.2.3", "") + "]"
	installFakeGH(t, list, map[string]string{"10": successJobsJSON()})
	setTagEnv(t, sha)
	if err := requireGreenCI(); err != nil {
		t.Fatal(err)
	}
}

// TestRequireGreenCINewestTagRunRedNoFallthrough asserts a completed red
// tag run is selected over an older green tag run.
func TestRequireGreenCINewestTagRunRedNoFallthrough(t *testing.T) {
	const sha = "abc123deadbeef"
	list := "[" + runRow(10, "push", "completed", sha, "v1.2.3", "success") + "," +
		runRow(20, "push", "completed", sha, "v1.2.3", "failure") + "]"
	installFakeGH(t, list, map[string]string{
		"10": successJobsJSON(),
		"20": jobsJSON(map[string]string{"format": "failure"}),
	})
	setTagEnv(t, sha)
	err := requireGreenCI()
	if err == nil {
		t.Fatal("newest red tag run must not fall through to an older green run")
	}
	if strings.Contains(err.Error(), "pending") || strings.Contains(err.Error(), "no matching run") {
		t.Fatalf("err=%v want a job-conclusion failure", err)
	}
}

// TestRequireGreenCIResolvesDispatchRef covers tag resolution when the
// workflow ref is a branch and the name is the tag, and when the name is empty.
func TestRequireGreenCIResolvesDispatchRef(t *testing.T) {
	const sha = "abc123deadbeef"
	list := "[" + runRow(7, "push", "completed", sha, "v1.2.3", "success") + "]"
	t.Run("ref-name", func(t *testing.T) {
		installFakeGH(t, list, map[string]string{"7": successJobsJSON()})
		t.Setenv("GITHUB_SHA", sha)
		t.Setenv("GITHUB_REF", "refs/heads/main")
		t.Setenv("GITHUB_REF_NAME", "v1.2.3")
		if err := requireGreenCI(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("empty-name", func(t *testing.T) {
		installFakeGH(t, list, map[string]string{"7": successJobsJSON()})
		t.Setenv("GITHUB_SHA", sha)
		t.Setenv("GITHUB_REF", "refs/heads/main")
		t.Setenv("GITHUB_REF_NAME", "")
		if err := requireGreenCI(); err == nil {
			t.Fatal("refs/heads with an empty name must not select a run")
		}
	})
}

// runValues returns each run: value in a workflow file. A block value runs
// until the next key at the run key's indentation. env, with, if, and
// concurrency values are not run values.
func runValues(body string) []string {
	lines := strings.Split(body, "\n")
	var values []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimLeft(line, " ")
		if !strings.HasPrefix(trim, "run:") {
			continue
		}
		indent := len(line) - len(trim)
		rest := strings.TrimSpace(strings.TrimPrefix(trim, "run:"))
		if rest == "" || rest == "|" || rest == ">" || rest == "|-" || rest == ">-" || rest == "|+" || rest == ">+" {
			var b strings.Builder
			for j := i + 1; j < len(lines); j++ {
				next := lines[j]
				if strings.TrimSpace(next) == "" {
					b.WriteByte('\n')
					continue
				}
				nextTrim := strings.TrimLeft(next, " ")
				nextIndent := len(next) - len(nextTrim)
				if nextIndent <= indent {
					break
				}
				b.WriteString(next)
				b.WriteByte('\n')
				i = j
			}
			values = append(values, b.String())
			continue
		}
		values = append(values, rest)
	}
	return values
}

func runValuesContainExpr(body string) bool {
	for _, v := range runValues(body) {
		if strings.Contains(v, "${{") {
			return true
		}
	}
	return false
}

func TestRunValueDetector(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		bad  bool
	}{
		{name: "inline", yaml: "  - name: x\n    run: echo ${{ github.ref }}\n", bad: true},
		{name: "block", yaml: "  - name: x\n    run: |\n      echo ${{ github.ref }}\n", bad: true},
		{name: "with", yaml: "  - uses: actions/checkout\n    with:\n      ref: ${{ github.ref }}\n", bad: false},
		{name: "concurrency", yaml: "concurrency:\n  group: release-${{ github.ref }}\n", bad: false},
		{name: "env", yaml: "  - name: x\n    env:\n      FOO: ${{ github.ref }}\n    run: echo \"$FOO\"\n", bad: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runValuesContainExpr(tc.yaml); got != tc.bad {
				t.Fatalf("bad=%v want %v values=%q", got, tc.bad, runValues(tc.yaml))
			}
		})
	}
}

// TestReleaseWorkflowPassesTagAsEnv asserts the tag name is not spliced
// into a release or CI shell script, and that the notes step rejects a
// ref that is not a version tag.
func TestReleaseWorkflowPassesTagAsEnv(t *testing.T) {
	root := repoRootForTest(t)
	for _, rel := range []string{filepath.Join(".github", "workflows", "release.yml"), filepath.Join(".github", "workflows", "ci.yml")} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		if runValuesContainExpr(string(body)) {
			t.Fatalf("%s interpolates ${{ inside a run: script", rel)
		}
	}
	body, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, `ref="${{ github.event.inputs.ref || github.ref_name }}"`) {
		t.Fatal("release workflow interpolates the tag into a shell script")
	}
	if !strings.Contains(text, "timeout-minutes: 45") {
		t.Fatal("tag-gate timeout-minutes must be 45")
	}
	if !strings.Contains(text, "set -uo pipefail") {
		t.Fatal("require-ci retry must use set -uo pipefail")
	}
	if !strings.Contains(text, "pending") || !strings.Contains(text, "no matching run") {
		t.Fatal("require-ci retry must match pending and no matching run")
	}
	if !strings.Contains(text, "sleep 30") {
		t.Fatal("require-ci must poll every 30s")
	}
	if !strings.Contains(text, "RELEASE_REF:") || !strings.Contains(text, "DIGEST:") {
		t.Fatal("tag and digest must be passed through env")
	}
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ci), "tags:") || !strings.Contains(string(ci), `"v*"`) {
		t.Fatal("ci.yml must run on v* tag pushes")
	}
	if !strings.Contains(text, `re='^v[0-9A-Za-z.+-]+$'`) {
		t.Fatal("resolve-notes must assign the tag regex unquoted")
	}
	if strings.Contains(text, `=~ "`) || strings.Contains(text, `=~ '`) {
		t.Fatal("tag regex on the right of =~ must be unquoted")
	}
	if !strings.Contains(text, `[[ ! "$ref" =~ $re ]]`) && !strings.Contains(text, `[[ "$ref" =~ $re ]]`) {
		t.Fatal("resolve-notes must match the tag with [[ =~ $re ]]")
	}
	script := `ref="${1#refs/tags/}"; re='^v[0-9A-Za-z.+-]+$'; [[ "$ref" =~ $re ]]`
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{in: "v1.2.3", ok: true},
		{in: "refs/tags/v1.2.3", ok: true},
		{in: "v1.2.3;touch", ok: false},
	} {
		cmd := exec.Command("bash", "-c", script, "bash", tc.in)
		err := cmd.Run()
		if tc.ok && err != nil {
			t.Fatalf("%s rejected: %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s accepted", tc.in)
		}
	}
}
