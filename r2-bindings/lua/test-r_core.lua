-- using RCore API as the unique entrypoint --
require "r_core"

c = r_core.RCore ()
print(c)
c:prompt_loop()

