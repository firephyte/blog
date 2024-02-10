## What are functions?

We already gave a brief explanation of what functions are in the previous section, but now I'd like to go a lot more in depth into how functions are compiled and ran.

A function is simply a block of code that can be called. Parameters can be passed into the function, and functions can return a return value.

### Parameters

You can pass parameters into a function for the function to execute exactly what you want it to. For example, let's say there is a function for finding the square root of a number. How will the function know what number you want to take the square root for? You have to pass it in as a parameter.

In C, you can pass parameters into a function inside the brackets. Here's an example:

```c

```

You already know what a function is from the previous section. Here's the big question I would like to answer in this section: **How does a CPU run functions?**
## Call stack

First of all, I would like to talk about some implications of the question:
- Each function has it's own variables, meaning it needs it's own memory.
- Once you call a function, that function can than call another function, and so on. Functions can be infinitely nested inside each other.

### Stacks

A stack is a type of data structure that enables us to answer the question. A stack follows only one rule: First in, last out. Think about it like a stack of books. Let's say you have a stack of ten books, one on top of the other. If you wanted to access a book in the middle or on the bottom of the stack, you can't; only the book at the top of the stack can be easily taken apart without touching any of the other books. That's what the First in, last out means. Once something is inserted (which we call "pushed") onto the stack, everything on top of that "something" needs to be taken off (which we call "popped") off the stack before we can take off that "something". Only the item on the top can be accessed in any given function.

Now, think back to our function problem. **What if each function was an item on the stack?**

That's actually exactly what modern computers do.

When you run a function, you **push** it onto the top of the stack. All of the data and memory used inside the **stack frame**.  Once the function finishes running, you **pop** it from the stack. This is called a **call stack**.

Now we're going to look at how the call stack is formed through machine code.

### Assembly Code Review

```c
#include <stdio.h>

int main()
{

}
```