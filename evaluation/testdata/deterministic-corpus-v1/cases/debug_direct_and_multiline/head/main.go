package sample

import (
	alias "fmt"
	"fmt"
)

func direct() { fmt.Println("debug") }
func multi() {
	alias.Println(
		"debug",
	)
}
