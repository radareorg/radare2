"-----------------------------"
" copy this file to ~/.vimrc  "
" or load it with :source vim "
"-----------------------------"

" my own indentation for C using the coding styles
set cindent
set tabstop=4
set noexpandtab
set smartindent
set cino=:0,+0,(2,J0,{1,}0,>4,)1,m2

" pancake's exposee for vim:
let fs=0
fun Exposee()
if (g:fs == 0)
  res 1000
  vertical res 1000
  let g:fs=1
else
  exe "normal \<C-W>="
  let g:fs=0
endif
endfun
map <F10> :call Exposee()<cr>

"some nice keymappings
map <F1> :vsp<cr>
map <F2> :sp<cr>
map <F3> :sp<cr>:e .<cr>
map <F4> :q<cr>
map <F5> <C-W>=

map <F9> :make<cr>
map <C-F9> :cnext<cr>
map <S-F9> :cprevious<cr>

" fine zooming
map <C-J> 2<C-W>+
map <C-K> 2<C-W>-
map <C-L> 2<C-W>>
map <C-H> 2<C-W><

" fine frame moving
map <C-Y> <C-W>h
map <C-U> <C-W>j
map <C-I> <C-W>k
map <C-O> <C-W>l

au BufNewFile,BufRead *.vala setf cs
au BufNewFile,BufRead *.vapi setf cs
au BufNewFile,BufRead *.gtkaml setf cs
au BufNewFile,BufRead *.gtkon setf cs

filetype indent on
colorscheme pablo
set foldmethod=marker
set hlsearch
set paste
sy on

