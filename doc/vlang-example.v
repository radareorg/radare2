fn entry(core &R2) {
	println('hello world')
	println(core.cmd('pd 10'))
	s := core.cmd('pxwj 64')
	args := s.substr(1, s.len-1).split(',')
	for i := 0 ; i < args.len; i++ {
		n := args[i]
		println(n)
	}
	println(args[0])
}
