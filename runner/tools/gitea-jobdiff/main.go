// Command gitea-jobdiff reads Gitea and Forgejo tasks (the answers of FetchTask, as the files of
// runner/src/gitea/testdata/corpus hold them) with Gitea's own workflow model, gitea.dev/actionslib's
// pkg/model (derived from nektos/act), and writes what the model makes of each task's job as
// normalized JSON, one line for each task: its steps with their kind, `uses`, `run` text, `if`, `with` and `env`, and its
// env, container, services, defaults, outputs and matrix. The runner's side,
// runner/tools/giteajobcorpus.zig, builds the job.Job from the same task and compares the two.
// .github/scripts/gitea-job-diff.sh does all of it.
//
//	go run . -out <answers.jsonl> <corpus dir>
//
// The model is Gitea's reading of the workflow, not GitHub's: a disagreement says that one of the
// two is wrong, and it is settled against GitHub's behaviour.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gitea.dev/actionslib/pkg/model"
	"go.yaml.in/yaml/v4"
)

type fetched struct {
	Task struct {
		WorkflowPayload string `json:"workflowPayload"`
	} `json:"task"`
}

type container struct {
	Image       string            `json:"image"`
	Env         map[string]string `json:"env"`
	Ports       []string          `json:"ports"`
	Volumes     []string          `json:"volumes"`
	Options     string            `json:"options"`
	Credentials map[string]string `json:"credentials"`
}

type step struct {
	Kind            string            `json:"kind"`
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	If              string            `json:"if"`
	Uses            string            `json:"uses"`
	Run             string            `json:"run"`
	Shell           string            `json:"shell"`
	WorkingDir      string            `json:"working_directory"`
	Env             map[string]string `json:"env"`
	With            map[string]string `json:"with"`
	ContinueOnError string            `json:"continue_on_error"`
	TimeoutMinutes  string            `json:"timeout_minutes"`
}

type normalized struct {
	Name            string               `json:"name"`
	RunsOn          []string             `json:"runs_on"`
	If              string               `json:"if"`
	TimeoutMinutes  string               `json:"timeout_minutes"`
	ContinueOnError string               `json:"continue_on_error"`
	Env             map[string]string    `json:"env"`
	Defaults        map[string]string    `json:"defaults_run"`
	Container       *container           `json:"container"`
	ContainerBroken bool                 `json:"container_unreadable"`
	Services        map[string]container `json:"services"`
	Outputs         map[string]string    `json:"outputs"`
	MatrixCount     int                  `json:"matrix_count"`
	Matrix          map[string]any       `json:"matrix"`
	Strategy        map[string]any       `json:"strategy"`
	Steps           []step               `json:"steps"`
}

func main() {
	out := flag.String("out", "", "file for the answers, one JSON line for each task")
	flag.Parse()
	if *out == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gitea-jobdiff -out <answers.jsonl> <corpus dir>")
		os.Exit(2)
	}
	files, err := filepath.Glob(filepath.Join(flag.Arg(0), "*.json"))
	if err != nil || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "no tasks in", flag.Arg(0))
		os.Exit(2)
	}
	sort.Strings(files)
	var lines bytes.Buffer
	failed := 0
	for _, f := range files {
		n, err := read(f)
		var model any = n
		if err != nil {
			// A task the model refuses is written as the refusal, and compared too.
			model = map[string]string{"error": err.Error()}
			fmt.Fprintf(os.Stderr, "%s: the model refuses it: %v\n", filepath.Base(f), err)
			failed++
		}
		line, err := json.Marshal(map[string]any{"file": filepath.Base(f), "model": model})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		lines.Write(line)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(*out, lines.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%d tasks read by the model, %d refused\n", len(files)-failed, failed)
}

func read(file string) (*normalized, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var f fetched
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(f.Task.WorkflowPayload)
	if err != nil {
		return nil, err
	}
	// The same reader Gitea's runner reads a task's payload with.
	wf, err := model.ReadWorkflowPayload(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	ids := wf.GetJobIDs()
	if len(ids) != 1 {
		return nil, fmt.Errorf("%d jobs", len(ids))
	}
	return normalize(wf, wf.GetJob(ids[0]))
}

func normalize(wf *model.Workflow, j *model.Job) (*normalized, error) {
	n := &normalized{
		Name:            j.Name,
		RunsOn:          j.RunsOn(),
		TimeoutMinutes:  j.TimeoutMinutes,
		ContinueOnError: j.RawContinueOnError,
		Env:             map[string]string{},
		Defaults:        map[string]string{},
		Services:        map[string]container{},
		Outputs:         j.Outputs,
		Matrix:          map[string]any{},
		Strategy:        map[string]any{},
	}
	if n.Outputs == nil {
		n.Outputs = map[string]string{}
	}
	// The job's `if` as the payload has it; GetJob fills `success()` in where there is none.
	if j.If.Value != "success()" {
		n.If = j.If.Value
	}
	// The workflow's env, then the job's: the later one wins.
	for k, v := range wf.Env {
		n.Env[k] = v
	}
	for k, v := range j.Environment() {
		n.Env[k] = v
	}
	// The job's defaults.run replaces the workflow's whole.
	run := wf.Defaults.Run
	if j.Defaults.Run != (model.RunDefaults{}) {
		run = j.Defaults.Run
	}
	if run.Shell != "" {
		n.Defaults["shell"] = run.Shell
	}
	if run.WorkingDirectory != "" {
		n.Defaults["working-directory"] = run.WorkingDirectory
	}
	if j.RawContainer.Kind != 0 {
		if c := j.Container(); c != nil {
			n.Container = specOf(c)
		} else {
			n.ContainerBroken = true
		}
	}
	for name, s := range j.Services {
		if s != nil {
			n.Services[name] = *specOf(s)
		}
	}
	combos, err := j.GetMatrixes()
	if err != nil {
		return nil, err
	}
	n.MatrixCount = len(combos)
	if len(combos) == 1 && j.Strategy != nil {
		n.Matrix = combos[0]
	}
	if j.RawStrategy.Kind == yaml.MappingNode {
		var s map[string]any
		if err := j.RawStrategy.Decode(&s); err == nil {
			delete(s, "matrix")
			n.Strategy = s
		}
	}
	for _, s := range j.Steps {
		cond := ""
		if s.If.Kind != 0 {
			cond = strings.TrimSpace(s.If.Value)
		}
		n.Steps = append(n.Steps, step{
			Kind:            s.Type().String(),
			ID:              s.ID,
			Name:            s.Name,
			If:              cond,
			Uses:            s.Uses,
			Run:             s.Run,
			Shell:           s.Shell,
			WorkingDir:      s.WorkingDirectory,
			Env:             nonNil(s.Environment()),
			With:            nonNil(s.With),
			ContinueOnError: s.RawContinueOnError,
			TimeoutMinutes:  s.TimeoutMinutes,
		})
	}
	return n, nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func specOf(c *model.ContainerSpec) *container {
	out := &container{
		Image:       c.Image,
		Env:         nonNil(c.Env),
		Ports:       c.Ports,
		Volumes:     c.Volumes,
		Options:     c.Options,
		Credentials: nonNil(c.Credentials),
	}
	if out.Ports == nil {
		out.Ports = []string{}
	}
	if out.Volumes == nil {
		out.Volumes = []string{}
	}
	return out
}
