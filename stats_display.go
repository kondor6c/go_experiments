package main

// an exercise where I am not going to "google" anything, use only reference docs

import (
	"fmt"
	"syscall"
)

func main() {
	var cwd_fd int
	var err error
	cwd_fd, err := syscall.Getcwd([]byte("/"))
	if err != nil {
		panic(err)
	}
	fmt.Println(cwd_fd)
}
