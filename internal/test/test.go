package test

import "fmt"

type Export struct {
}

func (c Export) DoMagic() {
	fmt.Println("Magic function was called")
}

func (c Export) String() string {
	return fmt.Sprint("ta da! \n")
}
