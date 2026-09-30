package sample

type Service struct{}

func Work() int {
	return 2
}

func (Service) Run() int {
	return 2
}

type Config struct {
	Value string
}

var Count = 2
