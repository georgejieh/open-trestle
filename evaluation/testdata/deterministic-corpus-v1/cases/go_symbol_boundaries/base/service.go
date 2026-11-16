package sample

type Service struct{}

func Work() int {
	return 1
}

func (Service) Run() int {
	return 1
}

type Config struct {
	Value int
}

var Count = 1
