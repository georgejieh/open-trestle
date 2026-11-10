// Package alias resolves alternative names.
package alias

// Registry maps alias names to canonical names. The zero Registry has no
// aliases and resolves every name to itself.
type Registry struct {
	aliases map[string]string
}

// Add records alias as another name for canonical.
func (r *Registry) Add(alias, canonical string) {
	if r.aliases == nil {
		r.aliases = make(map[string]string)
	}
	r.aliases[alias] = canonical
}

// Resolve returns the canonical name for name.
func (r *Registry) Resolve(name string) string {
	if canonical, ok := r.aliases[name]; ok {
		return canonical
	}
	return name
}
