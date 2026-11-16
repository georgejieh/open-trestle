package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/evaluation"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/localreview"
)

func runEvaluateModelResult(args []string, stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil {
		return 2
	}
	values := map[string]string{}
	sourceArgs := []string{}
	if len(args) != 20 {
		writeEvaluateModelResultUsage(stderr)
		return 2
	}
	for i := 0; i < len(args); i += 2 {
		key, value := args[i], args[i+1]
		if value == "" || values[key] != "" {
			writeEvaluateModelResultUsage(stderr)
			return 2
		}
		values[key] = value
		switch key {
		case "--result", "--result-sha256", "--case":
		default:
			sourceArgs = append(sourceArgs, key, value)
		}
	}
	options, repository, base, head, err := parseLocalGitChangeOptions(sourceArgs)
	if err != nil || values["--result"] == "" || values["--result-sha256"] == "" || values["--case"] == "" {
		writeEvaluateModelResultUsage(stderr)
		return 2
	}
	fail := func() int { fmt.Fprintln(stderr, "model result evaluation import failed"); return 1 }
	captured, err := readRegularBoundedFile(values["--result"], localreview.MaxResultJSONBytes)
	if err != nil {
		return fail()
	}
	root, err := os.OpenRoot(options.objectsRoot)
	if err != nil {
		return fail()
	}
	defer root.Close()
	store, err := scm.NewLocalGitObjectStore(root, repository)
	if err != nil {
		return fail()
	}
	defer store.Close(context.Background())
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		return fail()
	}
	baseRequest, err := evidence.NewRepositoryAcquisitionRequest(repository, base, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		return fail()
	}
	headRequest, err := evidence.NewRepositoryAcquisitionRequest(repository, head, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		return fail()
	}
	source, err := scm.ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		return fail()
	}
	report, err := evaluation.ImportModelResult(captured, values["--result-sha256"], values["--case"], source)
	if err != nil {
		return fail()
	}
	if store.Close(context.Background()) != nil || root.Close() != nil {
		return fail()
	}
	n, err := stdout.Write(append(report, '\n'))
	if err != nil || n != len(report)+1 {
		return fail()
	}
	return 4
}

func writeEvaluateModelResultUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle evaluate model-result --result PATH --result-sha256 SHA256 --case CASE_ID --objects-root DIR --repository-authority HOST --repository-namespace PATH --repository-name NAME --revision-algorithm sha1 --base-revision-digest DIGEST --head-revision-digest DIGEST")
}
