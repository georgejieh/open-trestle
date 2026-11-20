package repoindex

import (
	"fmt"
	"testing"
)

func TestDiffLinesRecordWhereLinesWereOnlyRemoved(t *testing.T) {
	base := "1\n2\n3\n4\n5\n6\n7\n8\n"
	head := "1\n3\n4\nfive\n6\n7\n"
	c, ok := diffLines("f.txt", []byte(base), []byte(head))
	if !ok {
		t.Fatal("the diff failed")
	}
	if got := fmt.Sprint(c.HeadLines, c.BaseLines, c.DeletionPoints); got != "[{4 4}] [{2 2} {5 5} {8 8}] [2 7]" {
		t.Fatalf("lines = %s", got)
	}
}
