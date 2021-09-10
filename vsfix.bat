@cd vs\libr
@for /r %%d in (*.dll) do @copy /Y "%%d" ..\binr\radare2 > NUL
@cd ..\..