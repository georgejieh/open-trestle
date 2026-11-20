package main

type daemonCloserFunc func() error

func (f daemonCloserFunc) Close() error { return f() }
