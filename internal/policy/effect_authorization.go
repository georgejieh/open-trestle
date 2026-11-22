package policy

// AuthorizationReason identifies the trusted control that produced an effect decision.
type AuthorizationReason uint8

const (
	AuthorizationExplicitUserApproval AuthorizationReason = iota + 1
	AuthorizationRepositoryPolicy
	AuthorizationAdministratorPolicy
)

func (r AuthorizationReason) String() string {
	switch r {
	case AuthorizationExplicitUserApproval:
		return "explicit_user_approval"
	case AuthorizationRepositoryPolicy:
		return "repository_policy"
	case AuthorizationAdministratorPolicy:
		return "administrator_policy"
	default:
		return ""
	}
}
