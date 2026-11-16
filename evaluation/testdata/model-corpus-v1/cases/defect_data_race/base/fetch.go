// Package fetch measures remote resources.
package fetch

// Size reports the size in bytes of the resource at url.
type Size func(url string) (int, error)

// First returns the size of the first url whose size can be read.
func First(urls []string, size Size) (int, bool) {
	for _, u := range urls {
		if n, err := size(u); err == nil {
			return n, true
		}
	}
	return 0, false
}
