+++
title = 'Easy Password Reverse by Clyax'
date = 2024-03-12T15:02:14+02:00
draft = false
showpage = true
+++

### Finding the Solution

Walking through the `exe` in a dissassembler, we can find the main function.

Near the end of the function you'll see that the pass condition is a `cmp [rsp+2C], edx`.
Lets keep this in mind as we disect the program.

From the top, we can see what seems to be our username being stored into `[rsp+30]` from a call to `fgets`.
This seems to be when we are prompted to enter our username. Our username also seems to be loaded into `rbx` with the
`lea rbx, [rsp+30]` call.

Further down we can see a `printf` call for our password, but its storage is a little odd.
It makes a call to some function with the argument `%u` and the address of `rsp+2C`.
Walking through this function it seems to be reading from stdin and storing the result into the passed pointer.
But it only does so while the first argument (`rcx`) is satisfied.
With this information, we can conclude that our password (`rbp+2C`, inferred from the pass condition)
is not actually the text we input- but actually just the part of our password that is an unsigned int (`%u`).
More specifically, up *until* our password is no longer an unsigned int. For example, if we input our password as `123a`
our actual password would be `123`, but if we input `1a23` our actual password would be `1`- not `123`, as
it would stop at the first unsigned int (`a`).

Further down we see a loop through a short `jmp`.
The loop seems to be going until `rax` is equal to `r8` (`cmp rax, r8`).
Going up a bit, we can see where these are set:

```asm
mov     rcx, rbx
call    strlen
xor     edx, edx
mov     r8, rax
mov     rax, rbx
add     r8, rbx
```

Recall that `rbx` contains our username. And seeing as `rax` contains the result from the `strlen` call- we can infer
that `r8` contains the length of our username (`mov r8, rax`). Although a bit further down (`add r8, rbx`) we see it
adjusted by our username (or the address of our username)- meaning it now points to the character after our string
(the null terminator).

We also see that `rax` is being made to point to our username (`mov rax, rbx`).

With this new infromation, we can conclude that the loop is progressing through each of the characters in
our username:

```asm
movsx ecx, byte ptr [rax]
add rax, 1
```

In doing so, it seems to be keeping a running total of the bytes `add edx, ecx`. Chars are technically just ASCII
ints in memory, so it seems that `edx` is keeping a running total of the ASCII values of our username.

After this loop completes, it lands on our original pass condition: `cmp [rsp+2C], edx`.

With our new-found knowledge, we now know that `[rsp+2C]` points to the count of unsigned ints in our password,
and `edx` contains the total ASCII value of our username.

## Solution

A password is the total ASCII value of the username. That is, the total of the ASCII equivilent value of each character in the username.
