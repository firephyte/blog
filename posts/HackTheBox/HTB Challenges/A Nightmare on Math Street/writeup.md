# HTB Challenge Writeup: A Nightmare on Math Street
### By: gnos1s

### Challenge Category: Misc
### Challenge Difficulty: Easy

A fun, easy misc challenge that involves evaluating a maths equation using a weird order of operation. It was straightforward and enjoyable the whole way through. Let's just jump in!

When we first connect to the server, we are presented with a math equation that we need to solve:

```
$ nc 167.172.61.89 30013

#####################################################################
#                                                                   #
# I told you not to fall asleep!                                    #
#                                                                   #
# A 500 question quiz is coming up.                                 #
#                                                                   #
# Be careful; Dream math works a little differently:                #
# Addition and multiplication have the REVERSE order of operation.  #
#                                                                   #
# And remember, if you fail in your sleep, you fail in real life... #
#                                                                   #
#####################################################################


[001]: 23 * 32 * 8 + (13 * (45 * 70 + (65 * 84) * 26)) = ?
>
```

We are supposed to enter the answer of that math equation. But there's a twist: Addition and multiplication have the REVERSE order of operation. Meaning that addition comes first before multiplication.

There are also apparently 500 questions, so we're gonna have to write a script for this.

The hardest part of this challenge will be to work out how to do the "order of operations change" thing. Normally, we would just have to work out the value of the equation using the eval() function in Python, but here we can't do that. We need a way to put addition in front of multiplication. 

How do we change it so that addition goes before multiplication? In other words, we need a way to put addition "before" multiplication.

Remember that everything in brackets gets operated before anything else. Meaning as long as we put the adding numbers inside brackets, we're guaranteeing that the addition will come first.

I'm not sure if this is the simplest way to do that, but it's the first thing that came to my mind - and it seems to work. So we'll be using this method. There's probably a faster way but I can't come up with it.

As said before, we'll need a script for this. So the first thing I'm gonna do is set up the connection:

```
hostname = "167.172.61.89"
port = 30013

conn = remote(hostname, port)
conn.recvlines(15)

_input = conn.recvlines(1)
```

Now, we can start doing the math. (The reason why we received 15 lines is to skip all of the introduction. The 16th line will be the math equation that we have to solve. After that we're gonna grab the line with the math equation: _input holds that string.)

If we look closely at the string of math equation, we'll need to remove some parts off it that aren't a part of the equation. So we'll slice off the front and the end like this

```
_slice = _input[0][7:-4]
```

Now we're left with the math expression itself.

First, the string is decoded into bytes. Then, we process the string to add brackets around all of the plus signs.

This part of the code is messy, but I tried my best to add comments to explain what's going on:

```
    _slice = _slice.decode()

    amount = _slice.count('+') # The amount of plus signs in the equation. This will be useful later.
    i = 0 # Counter of which position we're at when parsing the string.
    while i < len(_slice) - 1: # When i reaches the end of the string, the loop stops.
        if _slice[i] == '+': # If dealing with a plus sign.
            # Dealing with the number in front of the plus.
            for j in range(10000): # Here, 10000 doesn't mean anything. It's just that we don't know if the number is 1, 2, 3, or more digits. So we need to search for the place where the number ends. So we need a big number to loop with.
                if i - 2 - j <= 0: # If the plus sign is at the very start, just add a bracket at the very start.
                    _slice = '(' + _slice # Adding a bracket.
                    break
                elif _slice[i - 2 - j] == ' ': # A blank means we've reached befoer the start of the number's digits. In other words the position to insert the bracket is found.
                    _slice = _slice[0:i - 2 - j] + '(' + _slice[i - 2 - j:len(_slice)] # Inserting in the bracket.
                    break
            # Dealing with the number behind the plus.
            for j in range(10000): # Same as the above for loop, but getting the position of the number on the left.
                if i + 2 + j >= len(_slice) - 1: # If the plus sign is at the very end, just put the bracket at the end.
                    _slice = _slice + ')' # Adding the bracket at the very end.
                    break
                elif _slice[i + 3 + j] == ' ': # Same as before, but looking for the end position to slide in the bracket.
                    _slice = _slice[0:i + 3 + j] + ')' + _slice[i + 3 + j:len(_slice)] # Inserting in the bracket.
                    break
            i += 1 # Adding 1 to i because by inserting in the left bracket, the entire array is pushed forward by one. If we didn't have this line the loop would just keep adding brackets again and again, creating an infinite loop.
        i += 1 
```

Next, it's simply just evaluating, sending, and repeating 500 times.

### Side Note

Acutally, some of you may have come up with situations where my algorithm won't work. What if there are more than two numbers. Wouldn't your algorithm fall apart?

Surprisingly, no. Let's start with this math equation:

```
51 + 26 + 33
```

After the first plus sign, the equation would be changed to:

```
(51 + 26) + 33
```

After the second plus sign, the equation would be changed to:

```
(51 + (26) + 33)
```

This looks very strange, but it's technically still correct since there are the same amount of opening and closing brackets. And eval() can evaluate this! It most likely just removes the brackets around the 26 to simplify.

So my way does work, although I have to admit I did get quite lucky.

### Final Script

Here is my finished script:

```
import PIL
from pwn import *

hostname = "167.172.61.89"
port = 30013

conn = remote(hostname, port)
conn.recvlines(15)

for k in range(501):
    _input = conn.recvlines(1)
    print(_input)

    _slice = "lol"
    if k == 0:
        _slice = _input[0][7:-4]
    else:
        _slice = _input[0][8:-4]

    print(_slice)

    _slice = _slice.decode()

    amount = _slice.count('+')
    i = 0
    while i < len(_slice) - 1:
        if _slice[i] == '+':
            for j in range(10000):
                if i - 2 - j <= 0:
                    _slice = '(' + _slice
                    break
                elif _slice[i - 2 - j] == ' ':
                    _slice = _slice[0:i - 2 - j] + '(' + _slice[i - 2 - j:len(_slice)]
                    break
            for j in range(10000):
                if i + 2 + j >= len(_slice) - 1:
                    _slice = _slice + ')'
                    break
                elif _slice[i + 3 + j] == ' ':
                    _slice = _slice[0:i + 3 + j] + ')' + _slice[i + 3 + j:len(_slice)]
                    break
            i += 1
        i += 1


    print(_slice)

    value = eval(_slice)

    print(value)

    conn.sendline(str(value).encode())
```

When executed, it solves the math equations one by one:

```
[+] Opening connection to 167.172.61.89 on port 30013: Done
[b'[001]: 34 + 44 + (23 + 10 * (18 * 92 + 99) + 42 * 79) + 63 = ?']
b'34 + 44 + (23 + 10 * (18 * 92 + 99) + 42 * 79) + 63'
(34 +( 44) +( (23) + 10) * (18 *( 92 +( 99)) + 42) *( 79) + 63)
9072501
[b'> [002]: (62 * 82 + 88) * 23 + (2 * 53) + (34 * 66) * 55 = ?']
b' (62 * 82 + 88) * 23 + (2 * 53) + (34 * 66) * 55'
 (62 *( 82 + 88)) *( 23 + (2) *( 53) + (34) * 66) * 55
1375628100
[b'> [003]: 95 * 89 + 29 * 98 * 34 + 99 + 43 * 28 * 44 + 71 = ?']
b' 95 * 89 + 29 * 98 * 34 + 99 + 43 * 28 * 44 + 71'
 95 *( 89 + 29) * 98 *( 34 +( 99) + 43) * 28 *( 44 + 71)
622587257600

<snip>

[b'> [499]: 10 * 67 + 39 * 7 + 22 * 73 + 100 * 71 + 88 * 80 = ?']
b' 10 * 67 + 39 * 7 + 22 * 73 + 100 * 71 + 88 * 80'
 10 *( 67 + 39) *( 7 + 22) *( 73 + 100) *( 71 + 88) * 80
67645214400
[b'> [500]: 88 + 4 + 38 * 81 + (80 + 64) + 36 + 18 = ?']
b' 88 + 4 + 38 * 81 + (80 + 64) + 36 + 18'
( 88 +( 4) + 38) *( 81 +( (80) +( 64)) +( 36) + 18)
36270
[b"> Well done! Here's the flag: HTB{do_it_yourself!}"]
```

And there's the flag. Thank you so much for reading, and have a good one!