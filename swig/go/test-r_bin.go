package main

import (
	"fmt"
	"r_bin"
)

func main() {
	b := r_bin.NewRBin ();
	b.Load ("/bin/ls", "")
	baddr := b.GetBaddr ()
	sv := b.Get_sections ()
	fmt.Println ("-> Sections")
	fmt.Printf ("baddr=%08x\n", baddr)
	nsects := sv.Size ()
	for i := 0; i < nsects; i++ {
		s := sv.Get (i);
		fmt.Printf ("offset=0x%08x va=0x%08x size=%05d %s\n",
				s.GetOffset (), baddr+s.GetRva (), s.GetSize (), s.GetName())
	}
	/*
	for _, s:= range b.Get_sections () {
		fmt.Printf ("offset=0x%08x va=0x%08x size=%05d %s\n",
				s.GetOffset (), baddr+s.GetRva (), s.GetSize (), s.GetName())
	}
	*/
}
