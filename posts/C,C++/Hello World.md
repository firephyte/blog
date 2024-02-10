## Hello World!

Let's have a look at this simple C program:

```c
#include <stdio.h>

int main()
{
	printf("Hello World!\n");
}
```
This is often the first piece of code taught to new C programmers. You are often taught that this program outputs "Hello World!" when it is ran. But why?

I personally feel like this piece of code shouldn't be taught so early on, because new programmers simply do not understand what's going on here. What does the include mean? What does the int mean? What does the printf mean? C is a complicated language, and there's a lot of important concepts converged into this small piece of code. So here, I'm going to dissect every part of this 6-line code and explain every single step in as much detail as possible.

## Line 1

```c
#include <stdio.h>
```
What does the "#include" mean?

When programming, we often don't have to write every single piece of code ourselves; that would take way too long. Think of it like when you have to do a math problem, 2 + 2. When you solve this problem, do you have to reinvent what the '+' represents? or what the '2' represents? No. You simply know them as numbers and operators, and you understand what you are supposed to do to solve the equation.

The same is true in computer science. If someone else already wrote a useful piece of code before, it doesn't make sense for you to have to write it again - that would take way too much time. The '#include' simply allows you to import code from somewhere else, and you're free to use any of that code later in your program.

After the include, there is a space, then the string '<stdio.h>'. Remember, with the '#include' statement, we say that we're importing code from somewhere. Well, the next thing we need to specify is where to import code from. That's exactly what the '<stdio.h>' is doing. But what is stdio.h?

### glibc

glibc, or the GNU C library, is what we often call the "C standard library". It's basically just a massive library of functions (we'll get into that later) and code that's useful in almost any C program. glibc is available on all major operating systems today.

stdio.h is a part of glibc. "Stdio" stands for "STanDard Input / Output". So essentially, it declares a bunch of functions that deal with standard input and output. The function we'll see later, printf, is a part of this library - we can use that function because we already imported stdio.h.

You may be wondering why there is a '.h' at the end. Well, in C you have programs (which are in the file format .c), but you also have something called a header file (which are in the file format .h). Header files don't contain any actual code - We'll get into more detail on that later! But for now, just assume that we successfully imported the stdio.h 'library'.

And that's pretty much what line 1 of the code is doing! It imports everything from a library called 'stdio.h', which is a part of the C standard library.

## Line 2-3

Line 2 is just a space, we'll skip over that. Let's have a look at line 3.

```c
int main()
```

Right here, we have our first example of something called a 'function'. Functions are essentially blocks of code that execute when you call it. We'll get into that in the next section! RIght now, I just want you to assume that when this code ran, the operating system will run your 'main' function as the entrypoint to your program.

The 'int' in front stands for 'INTeger'. Functions can have a return value that is returned when the function has finished executing (more on that later!). When you run a program, it's useful to know what happened in the program. Did it run successfully? Did it fail? Did it crash? That's why the 'main' function has a return value. In modern architectures, the return value is almost always an integer, which is why we specify the main function to return an integer. A return value of 0 means that the function ran successfully, and any other value reports some kind of error.

After the space is 'main', and that's just a function name. All functions need to have a name so that your computer knows which function to run.

Next is an opening bracket and a closing bracket. I don't want to go too deep into function parameters right now, we'll do that in the next section. So just assume that the () tells the compiler "This is a function, not a variable!"

## Lines 4 and 6

```c
{

}
```

Lines 4 and 6 contain an opening curly bracket '{' and a closing curly bracket '}'. These curly brackets essentially determine the boundaries of the 'main' function. Any code inside these brackets (line 5) is executed when the function is called. And remember, before we assumed that the 'main' function is ran as the entrypoint to the program. This means that when the program starts, any code inside the 'main' function is ran.

After all of that, it's finally time to have a look at line 5.

## Line 5

```c
	printf("Hello World!\n");
```

Do you still remember on line 1 when we said that we're importing 'stdio.h'? Well, this is when we're going to use a function in that library. STDIO stands for Standard Input / Output, and remember what I said at the start? This program prints "Hello World", and printing is a part of output. The 'printf' is also a function, and it's declared inside stdio.h. printf stands for 'PRINT Formatted', but just think of it as printing something to the output of your program. You'll also notice that before, in line 3, the function 'main' had a type 'int'. This function printf doesn't have a return value, because nothing needs to be returned!

After printf, we have a string "Hello World!\\n" inside two brackets. We're essentially passing the string (more on that later) as a parameter into the function printf. We're telling printf "Hey, I want you to print this string out for me.".

There's something weird about this string though: What is the '\\n'? It simply means 'new line'.

At the very end of the line, there's a semicolon ';'. Semicolons are mandatory in C: They basically tell the compiler when you want to end a line of code. Always add them at the end of a line of code inside a function (not strictly accurate, but I don't want to get into any advanced concepts right now. Just don't forget to add your semicolons!).

With that, we have fully explained 6 lines of code in over 1000 words! Amazing! We can try compiling and running the code as we explained in the previous section:

```
$ gcc file.c
$ ./a.out
Hello World!
$
```
If we didn't add the '\\n' at the end of the code there, the output would look like this:

```
$ ./a.out
Hello World!$
```
Do you see the difference? By adding the newline at the end, it looks much nicer.

That's it for my explanation of printing 'Hello World!' in C. Click [Here](Functions.md) to continue into the next section!