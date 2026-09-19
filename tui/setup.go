package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

// ErrSetupCheckUnavailable indicates that the local terminal controller has no checker configuration for a selected requirement.
var ErrSetupCheckUnavailable = errors.New("setup check unavailable")

// SetupService reads one protected setup plan and runs only explicitly configured checkers.
type SetupService interface {
	Current(context.Context) (setupcore.Plan, error)
	RunCheck(context.Context, setupcore.CheckKey, string) (setupcore.Plan, setupcore.CheckReceipt, error)
}

// SetupOptions controls bounded terminal rendering.
type SetupOptions struct {
	Width int
	Plain bool
	Once  bool
}

// SetupInterface is a foreground keyboard-first view over one protected setup plan.
type SetupInterface struct {
	service SetupService
	input   io.Reader
	output  io.Writer
	options SetupOptions
}

// NewSetup constructs a setup interface without reading state or running a check.
func NewSetup(service SetupService, input io.Reader, output io.Writer, options SetupOptions) (*SetupInterface, error) {
	if options.Width == 0 {
		options.Width = defaultWidth
	}
	if isNilValue(service) || isNilValue(input) || isNilValue(output) || options.Width < minimumWidth || options.Width > maximumWidth {
		return nil, ErrInvalidInterface
	}
	return &SetupInterface{service, input, output, options}, nil
}

type setupView struct {
	plan       setupcore.Plan
	selected   int
	pendingRun setupcore.CheckKey
	notice     string
}

// Run renders the protected plan and accepts bounded line-oriented keyboard commands until quit or input close.
func (i *SetupInterface) Run(ctx context.Context) error {
	if i == nil || ctx == nil {
		return ErrInvalidInterface
	}
	plan, err := i.service.Current(ctx)
	if err != nil || plan.Validate() != nil {
		return ErrInvalidSnapshot
	}
	view := setupView{plan: plan, selected: nextSetupRequirement(plan, 0)}
	if err = i.renderSetup(view); err != nil || i.options.Once {
		return err
	}
	commands := readCommands(ctx, i.input)
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, open := <-commands:
			if !open {
				return nil
			}
			if result.err != nil {
				return result.err
			}
			if result.eof {
				return nil
			}
			quit, handleErr := i.handleSetupCommand(ctx, result.value, &view)
			if handleErr != nil {
				return handleErr
			}
			if quit {
				return nil
			}
		}
	}
}
func (i *SetupInterface) handleSetupCommand(ctx context.Context, raw string, view *setupView) (bool, error) {
	requirements := view.plan.Requirements()
	command := strings.TrimSpace(raw)
	switch command {
	case "q", "quit":
		return true, nil
	case "j", "next":
		if view.selected < len(requirements)-1 {
			view.selected++
		}
		view.pendingRun = ""
		view.notice = ""
	case "k", "previous":
		if view.selected > 0 {
			view.selected--
		}
		view.pendingRun = ""
		view.notice = ""
	case "r", "refresh":
		view.pendingRun = ""
		plan, err := i.service.Current(ctx)
		if err != nil || plan.Validate() != nil || plan.RootIdentity() != view.plan.RootIdentity() {
			view.notice = "Refresh failed; the last verified plan is unchanged."
		} else {
			view.plan = plan
			if view.selected >= len(plan.Requirements()) {
				view.selected = len(plan.Requirements()) - 1
			}
			view.notice = "Plan refreshed."
		}
	case "x":
		if len(requirements) == 0 {
			return false, ErrInvalidSnapshot
		}
		requirement := requirements[view.selected]
		view.pendingRun = ""
		if requirement.Source() == setupcore.CheckDeterministic {
			view.notice = "This requirement is established by the setup plan."
		} else if requirement.State() == setupcore.CheckPassed {
			view.notice = "This requirement already has a passing receipt."
		} else {
			view.pendingRun = requirement.Key()
			view.notice = "Type run " + string(requirement.Key()) + " to confirm this receipt write."
			if requirement.Key() == setupcore.CheckIntegrationPermissionsValidated {
				view.notice = "Create GitHub installation token? Type run integration_permissions_validated."
			}
		}
	case "":
		view.pendingRun = ""
		view.notice = ""
	default:
		if view.pendingRun != "" && command == "run "+string(view.pendingRun) {
			if err := i.executeSetupCheck(ctx, view, view.pendingRun); err != nil {
				return false, err
			}
		} else if strings.HasPrefix(command, "run ") {
			view.pendingRun = ""
			view.notice = "Confirmation did not match the selected requirement."
		} else {
			view.pendingRun = ""
			view.notice = "Unknown command. Use j, k, r, x, or q."
		}
	}
	return false, i.renderSetup(*view)
}
func (i *SetupInterface) executeSetupCheck(ctx context.Context, view *setupView, key setupcore.CheckKey) error {
	view.pendingRun = ""
	current, err := i.service.Current(ctx)
	if err != nil || current.Validate() != nil || current.Identity() != view.plan.Identity() {
		view.notice = "Plan changed; refresh before running the check."
		return nil
	}
	plan, receipt, err := i.service.RunCheck(ctx, key, view.plan.Identity())
	if errors.Is(err, ErrSetupCheckUnavailable) {
		view.notice = "No checker is configured for this requirement."
		return nil
	}
	if err != nil {
		view.notice = "Check failed; the verified plan is unchanged."
		return nil
	}
	if plan.Validate() != nil || receipt.Validate() != nil || plan.RootIdentity() != view.plan.RootIdentity() || receipt.Key() != key {
		return ErrInvalidSnapshot
	}
	view.plan = plan
	view.notice = "Check completed: " + string(receipt.State()) + "."
	if receipt.State() == setupcore.CheckPassed {
		view.selected = nextSetupRequirement(plan, view.selected)
	}
	return nil
}
func nextSetupRequirement(plan setupcore.Plan, start int) int {
	requirements := plan.Requirements()
	if len(requirements) == 0 {
		return 0
	}
	if start < 0 {
		start = 0
	}
	for index := start; index < len(requirements); index++ {
		if requirements[index].State() != setupcore.CheckPassed {
			return index
		}
	}
	for index := 0; index < start && index < len(requirements); index++ {
		if requirements[index].State() != setupcore.CheckPassed {
			return index
		}
	}
	return min(start, len(requirements)-1)
}
func (i *SetupInterface) renderSetup(view setupView) error {
	var builder strings.Builder
	if !i.options.Plain {
		builder.WriteString("\x1b[H\x1b[2J")
	} else {
		builder.WriteString("---\n")
	}
	width := i.options.Width
	builder.WriteString("OPEN TRESTLE SETUP\n")
	writeAmbassadorBridgeMark(&builder)
	writeSetupWrapped(&builder, "Scope      ", view.plan.TenantID()+" / "+view.plan.RepositoryID(), width)
	fmt.Fprintf(&builder, "Profile    %s\n", strings.ReplaceAll(string(view.plan.Profile()), "_", " "))
	fmt.Fprintf(&builder, "Readiness  %-12s revision %d\n", string(view.plan.Status()), view.plan.Revision())
	fmt.Fprintf(&builder, "Root       %s\n", truncateTerminalText(view.plan.RootIdentity(), 20))
	posture := view.plan.Posture()
	writeSetupWrapped(&builder, "Boundary   ", fmt.Sprintf("%s inference, %s egress, publication %s", strings.ReplaceAll(string(posture.Inference()), "_", " "), posture.Egress(), enabledWord(posture.PublicationEnabled())), width)
	builder.WriteString("\nRequirements\n")
	keyWidth := (width - 27) / 2
	sourceWidth := 14
	stateWidth := 12
	fmt.Fprintf(&builder, "  %-*s %-*s %-*s %s\n", keyWidth, "REQUIREMENT", sourceWidth, "SOURCE", stateWidth, "STATE", "RECOVERY")
	requirements := view.plan.Requirements()
	for index, requirement := range requirements {
		marker := " "
		if index == view.selected {
			marker = ">"
		}
		recovery := string(requirement.RecoveryAction())
		if recovery == "" {
			recovery = "none"
		}
		fmt.Fprintf(&builder, "%s %-*s %-*s %-*s %s\n", marker, keyWidth, truncateTerminalText(strings.ReplaceAll(string(requirement.Key()), "_", " "), keyWidth), sourceWidth, strings.ReplaceAll(string(requirement.Source()), "_", " "), stateWidth, string(requirement.State()), truncateTerminalText(strings.ReplaceAll(recovery, "_", " "), width-keyWidth-sourceWidth-stateWidth-6))
	}
	if len(requirements) > 0 && view.selected < len(requirements) {
		selected := requirements[view.selected]
		builder.WriteString("\nSelected\n")
		fmt.Fprintf(&builder, "%s\n", strings.ReplaceAll(string(selected.Key()), "_", " "))
		writeSetupWrapped(&builder, "State      ", fmt.Sprintf("%s. Source %s. Recovery %s.", selected.State(), strings.ReplaceAll(string(selected.Source()), "_", " "), setupRecoveryText(selected.RecoveryAction())), width)
		writeSetupWrapped(&builder, "Action     ", setupRequirementAction(selected), width)
	}
	receipts := view.plan.Receipts()
	builder.WriteString("\nReceipt history\n")
	if len(receipts) == 0 {
		builder.WriteString("No environment check has completed.\n")
	} else {
		start := max(0, len(receipts)-5)
		for _, receipt := range receipts[start:] {
			fmt.Fprintf(&builder, "%-12s %-28s %s\n", receipt.State(), truncateTerminalText(strings.ReplaceAll(string(receipt.Key()), "_", " "), 28), truncateTerminalText(receipt.Identity(), 18))
		}
	}
	if view.notice != "" {
		fmt.Fprintf(&builder, "\n%s\n", truncateTerminalText(view.notice, width))
	}
	builder.WriteString("\nCommands: j next  k previous  x run selected\n          r refresh  q quit\n")
	_, err := i.output.Write([]byte(builder.String()))
	return err
}
func writeSetupWrapped(builder *strings.Builder, prefix, text string, width int) {
	text = safeTerminalText(text)
	continuation := strings.Repeat(" ", utf8.RuneCountInString(prefix))
	for {
		available := width - utf8.RuneCountInString(prefix)
		characters := []rune(text)
		if len(characters) <= available {
			builder.WriteString(prefix)
			builder.WriteString(text)
			builder.WriteByte('\n')
			return
		}
		cut := available
		for index := available; index > 0; index-- {
			if characters[index-1] == ' ' {
				cut = index - 1
				break
			}
		}
		if cut == 0 {
			cut = available
		}
		builder.WriteString(prefix)
		builder.WriteString(strings.TrimSpace(string(characters[:cut])))
		builder.WriteByte('\n')
		text = strings.TrimSpace(string(characters[cut:]))
		prefix = continuation
	}
}

func setupRequirementAction(requirement setupcore.Requirement) string {
	if requirement.State() == setupcore.CheckPassed {
		return "Inspect its receipt or continue to the next pending requirement."
	}
	switch requirement.Key() {
	case setupcore.CheckStateStoragePostureValidated:
		return "Provide --storage-root when starting this interface, then run the selected check."
	case setupcore.CheckBackupValidated:
		return "Create an exact snapshot separately, provide --backup-snapshot, then run the selected check."
	case setupcore.CheckLocalAdministratorValidated:
		return "Provide --administrator-approved-by matching the named recovery owner, then run the selected check."
	case setupcore.CheckObserverCredentialPostureValidated:
		return "Set distinct operator and observer token environments, then run the selected check."
	case setupcore.CheckPostgresStorageValidated:
		return "Approve the identity from trestle admin postgres identity, then run this explicit read-only database check."
	case setupcore.CheckEnvelopeStorageValidated:
		return "Approve the identity from trestle admin envelope identity, then run this explicit encrypted object create, read, exact delete, and absence check."
	case setupcore.CheckSecretBackendValidated:
		return "Approve the identity from trestle admin kms identity, then run this explicit tenant-key generate and unwrap check."
	case setupcore.CheckRemoteProviderAuthorized:
		return "Approve the protected route inventory, runtime policy, and review policy identities, then run this credential-free remote-provider authorization check."
	case setupcore.CheckIntegrationPermissionsValidated:
		return "Approve the exact GitHub broker and permission authorities and explicitly allow token creation. This check creates a short-lived read-only installation token for selected-repository inspection and permits renewal only on foreground demand. Owner records remain after close; restart requires an explicitly approved fresh generation."
	case setupcore.CheckWebhookValidated:
		return "Approve the exact GitHub webhook authority, then run the local signature, filtering, idempotency, conflict, and cleanup check."
	case setupcore.CheckSharedRateLimitValidated:
		return "Approve the exact PostgreSQL shared rate-limit authority, then prove cross-instance quota, cardinality, expiry, and cleanup behavior."
	case setupcore.CheckReplicaReconciliationValidated:
		return "Approve the exact PostgreSQL reconciliation authority, then run the bounded two-instance journal, lease, finalization, and cleanup check."
	case setupcore.CheckSignedBundleValidated:
		return "Approve the exact opaque bundle digest, size, Ed25519 public key, and signature authority, then stream the local verification check."
	case setupcore.CheckPolicyValidated:
		return "Provide the protected policy paths and all three approved identities, then run the selected check."
	case setupcore.CheckLocalInferenceValidated:
		return "Pass the exact policy check, provide the same policy authority, then run this explicit local model probe."
	case setupcore.CheckDryRunValidated:
		return "Pass the exact policy check first, then run this non-publishing dry run."
	case setupcore.CheckProfileSelected, setupcore.CheckScopeValid, setupcore.CheckEffectPostureLocked, setupcore.CheckRecoveryOwnerNamed:
		return "This fact is fixed by the protected setup plan."
	default:
		return "Complete the named dependency. No built-in local checker is available here yet."
	}
}

func setupRecoveryText(action setupcore.RecoveryAction) string {
	if action == setupcore.RecoveryNone {
		return "none"
	}
	return strings.ReplaceAll(string(action), "_", " ")
}
func enabledWord(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}
