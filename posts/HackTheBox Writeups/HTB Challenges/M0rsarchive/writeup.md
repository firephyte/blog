# HTB Challenge Writeup: M0rsarchive
### By: gnos1s

### Challenge Category: Misc
### Challenge Difficulty: Easy

A pretty fun and simple misc challenge that involves writing a Python script to read morse code from images.

Unzipping the challenge gives two files. One called flag_999.zip and one called pwd.png.

```
$ ls
flag_999.zip	pwd.png
```

We can't open the flag_999 zip file because we don't know it's password. The pwd.png file is really odd too: It's a very small image that seems to show some kind of code.

![pwd.png](assets/pwd.png)

Here is the zoomed-in image:

![zoomed.png](assets/zoomed.png)

At first glance, this looks like morse code. The code is composed of dots and dashes. Using a morse code lookup table, the image shows "9". We use that as the password of the zip archive and it works.

But when we see what was unzipped, it's the exact same thing: One zip file and one password image. This time the image is different though, so we're gonna have to do this again and again.

The zip archives also started with the name flag_999.zip. The new zip archive is called flag_998.zip. This will most likely keep going on and on until we reach flag_1.zip or flag_0.zip. That's 1000 zip archives we need to go through.

We can't do this by hand. An automation script is needed. Here is my thought process on what the script should do:

- Step 1: The script reads the image and produces a morse code string.
- Step 2: The script converts the morse code string to a byte string using a lookup table.
- Step 3: The script unzips the file using the password from step 2.

We can just do the above steps 1000 times to unzip all of the archives. Now, let's see how to do each one of these steps.

### Reading the image

One thing making this easier is that the image is very small and only has two colors. This means that we can read the image as a string using the PIL Image library and then translate that into morse code. We just have to work out what the background color is, and then we can assemble the morse code together.

First, we load the libraries and open the image. We also need a stirng for storing the morse characters so let's add that:

```
from PIL import Image
import re

image = Image.open(filename, 'r')

c = [] # String for storing the morse code
```

Next, we get the background color. We can be sure that the first byte of an image is background.

```
bg = image.getdata()[0]
```

We now open the image up, with background being a space and non-background being a *:

```
for i, v in enumerate(list(image.getdata())):
        if v == bg:
            c.append(" ")
        else:
            c.append("*")
```

The next part is to convert the string we currently have to morse code format. We know that 3 \* in a row is a dash and 1 * is a dot. This piece of code looks complicated but really all it's doing is converting \*\*\* into a dash and \* into a dot.

```
current_len = 0
    white_len = 0
    flag = 0

    decode = ""

    for i in range(len(c)):
        if c[i] == " ":
            if current_len == 1:
                decode = decode + '.'
            elif current_len == 3:
                decode = decode + '-'
            current_len = 0
            white_len += 1
        else:
            if white_len > 1 and flag == 1:
                decode += " "
            white_len = 0
            current_len += 1
            flag = 1

    print(decode)

    pwd = morse(decode)

    print(pwd)
    return pwd
```

Now, we have a function for converting the image into a morse code string.

### Decoding the morse code

The next thing we need to do is to decode the morse code. I found a really useful article on GeeksForGeeks describing how to do this.
First, we need a lookup array:

```
MORSE_CODE_DICT = { 'a':'.-', 'b':'-...',
                    'c':'-.-.', 'd':'-..', 'e':'.',
                    'f':'..-.', 'g':'--.', 'h':'....',
                    'i':'..', 'j':'.---', 'k':'-.-',
                    'l':'.-..', 'm':'--', 'n':'-.',
                    'o':'---', 'p':'.--.', 'q':'--.-',
                    'r':'.-.', 's':'...', 't':'-',
                    'u':'..-', 'v':'...-', 'w':'.--',
                    'x':'-..-', 'y':'-.--', 'z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}
```

Next, we grab a decoding algorithm that the article provided:

```
def morse_decrypt(message):
    i = 0
    # extra space added at the end to access the
    # last morse code
    message += ' '

    decipher = ''
    citext = ''
    for letter in message:

        # checks for space
        if (letter != ' '):

            # counter to keep track of space
            i = 0

            # storing morse code of a single character
            citext += letter

        # in case of space
        else:
            # if i = 1 that indicates a new character
            i += 1

            # if i = 2 that indicates a new word
            if i == 2 :

                 # adding space to separate words
                decipher += ' '
            else:

                # accessing the keys using their values (reverse of encryption)
                decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(citext)]
                citext = ''

    return decipher
```

This function can now decrypt a morse code message.

### Unzipping the file

The last step is to unzip the file. We can do this by making use of the zipfile library:

```
import zipfile
```

Then, we extract using a password we got from the prevoius step:

```
password = decrypt(path + "pwd.png").encode()

    with zipfile.ZipFile(path + "flag_" + str(count) + ".zip", 'r') as zip_ref:
        zip_ref.extractall(pwd=password)
```

Now, we just need to repeat this 1000 times:

```
count = 999
path = ""

for i in range(1000):
    password = decrypt(path + "pwd.png").encode()

    with zipfile.ZipFile(path + "flag_" + str(count) + ".zip", 'r') as zip_ref:
        zip_ref.extractall(pwd=password)

    if count == 999:
        path = path + "flag/" # I'm too lazy to do anyting else so I'll just add all of the zip files into one place

    count = count - 1
```

Here is the full script I'm using now:

```
from PIL import Image

import re
import zipfile

MORSE_CODE_DICT = { 'a':'.-', 'b':'-...',
                    'c':'-.-.', 'd':'-..', 'e':'.',
                    'f':'..-.', 'g':'--.', 'h':'....',
                    'i':'..', 'j':'.---', 'k':'-.-',
                    'l':'.-..', 'm':'--', 'n':'-.',
                    'o':'---', 'p':'.--.', 'q':'--.-',
                    'r':'.-.', 's':'...', 't':'-',
                    'u':'..-', 'v':'...-', 'w':'.--',
                    'x':'-..-', 'y':'-.--', 'z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}

def morse(message):
    i = 0
    # extra space added at the end to access the
    # last morse code
    message += ' '

    decipher = ''
    citext = ''
    for letter in message:

        # checks for space
        if (letter != ' '):

            # counter to keep track of space
            i = 0

            # storing morse code of a single character
            citext += letter

        # in case of space
        else:
            # if i = 1 that indicates a new character
            i += 1

            # if i = 2 that indicates a new word
            if i == 2 :

                 # adding space to separate words
                decipher += ' '
            else:

                # accessing the keys using their values (reverse of encryption)
                decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(citext)]
                citext = ''

    return decipher

def decrypt(filename):
    image = Image.open(filename, 'r')

    c = []

    bg = image.getdata()[0]

    for i, v in enumerate(list(image.getdata())):
        if v == bg:
            c.append(" ")
        else:
            c.append("*")

    current_len = 0
    white_len = 0
    flag = 0

    decode = ""

    for i in range(len(c)):
        if c[i] == " ":
            if current_len == 1:
                decode = decode + '.'
            elif current_len == 3:
                decode = decode + '-'
            current_len = 0
            white_len += 1
        else:
            if white_len > 1 and flag == 1:
                decode += " "
            white_len = 0
            current_len += 1
            flag = 1

    print(decode)

    pwd = morse(decode)

    print(pwd)
    return pwd

count = 999

path = ""

for i in range(999):
    password = decrypt(path + "pwd.png").encode()

    with zipfile.ZipFile(path + "flag_" + str(count) + ".zip", 'r') as zip_ref:
        zip_ref.extractall(pwd=password)

    if count == 999:
        path = path + "flag/"

    count = count - 1
```

We'll just let this run and it's going to open the zip files one by one:

```
----.
9
----- ---..
08
...-- --... -....
376
---.. ...-- --... ..---
8372

<snip>

..--- --... ---.. . .-. --... ..- -..- --.- --- .---- --... --. . ----- .-. .--. ---.. ----. ---.. ..--- --... -... .-. .--. ..---
278er7uxqo17ge0rp89827brp2
.--. .--. ....- .. .--- .---- --- ...-- ...- .... ...- .---- -.... ---.. ---.. .... .--- ..- -.-. ----- --.. ..--- ... --- -.-- -
pp4ij1o3vhv1688hjuc0z2soyt
```

The last file we got is flag_0.zip. We just have to unzip the last one and we get the flag!

```
$ cat flag
HTB{do_it_yourself!}
```