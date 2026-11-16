package sample

import "fmt"

func existing() { fmt.Println("debug") }
func candidate() {
	// fmt.Println("debug")
	_ = `fmt.Println("debug")`
	fmt.Println("trace")
	fmt := struct{ Println func(string) }{}
	fmt.Println("debug")
}
