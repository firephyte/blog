**NOTE**: Pointers are a weird concept to grasp in C, so it's perfectly normal if you're totally lost somewhere in this section! You are not alone. Read this section several times or do some research on other sources if you don't get what pointers are, because they are VERY important to understand.
## What are pointers?

Before we get into what pointers are, let's imagine you're a postman. You want to send mail to a specific address on the street.  TBC

Now think about this from a computer science perspective. Imagine that the town you're in is the memory, and the postman is the CPU. When the CPU wants to access memory, you need an *address* to that memory. A pointer is an address to somewhere else in the memory.

Whenever you have a variable in C, as we saw before that variable is stored somewhere in a memory. And if the variable is *somewhere* in the memory, it has an address. Let's look at this with a practical example. Have a look at the following code:

```c
#include <stdio.h>

int main()
{
	int x = 123;
	printf("%d\n", x);
}
```

We already know that this code prints out the value of x. What if I told you to print out not the **value** of x, but the **address** of x?

In C, we actually can do that. When we want to get the address of something, we used the **&** operator. The & is called the **address-of operator** because it grabs the **memory address** of a variable. Now, I'm going to change the code a little bit:

```c
#include <stdio.h>

int main()
{
	int x = 123;
	printf("%d\n", x);
	printf("%p\n", &x);
}
```

I added one more printf in the code. But if you look closely, there's a small difference. Instead of printing x, we're printing the **address** of x in memory (Notice the & operator). When we want to print a pointer, we also use the **%p** format string in printf. Here is what happens when we run the code:

```
$ gcc pointer.c
$ ./a.out
123
0x7ffec8f75204
$
```
The first value of 123 makes sense, but what is the weird hexadecimal number? That's where the variable x is in memory!

When we want to declare a variable as a pointer towards something else in C, we can set it to be a **pointer variable**. This is where the **\*** operator comes in! Consider the following code:

```c
int main()
{
	int x = 123;
	int *y = &x;
}
```
The variable y is a **pointer** because we put a \* in front of it. We also set the value of y to be the **address** of x (&x). This means that y is a **pointer**, pointing to x.

The other use of the \* operator is to act as a **dereference operator**. Look back to the pointer y in the code above. We know y holds the address of x. What if we wanted to find the **value** at that **address**? That's where **\*** comes in. It will allow you to grab the value **at** that memory address.

This act of following a pointer to an address is what we call **dereferencing** a pointer.

All of this is probably quite confusing, so here's an example putting it all together:

```c
#include <stdio.h>

int main()
{
	int x = 123;
	int *y = &x;
	
	printf("%p\n", y);
	
	printf("%d\n", *y);
}
```

What is happening in this code:
- First of all, we declare a variable x and set the value to 123. Next, we declare a **pointer variable** y that points to an int. We set the value of y to be the **address** of x.
- On the first printf, we print out the value of y. Since y points towards x, the first printf will print the address of x in memory.
- On the second printf, we **dereference** y and get the **value that it is pointing to**. Since y points to x, the second printf should print out the value 123.

Here's what happens when we compile and run the code:
```c
$ gcc file.c
$ ./a.out
0x7fff7227a34c
123
$
```
Exactly what we expected: First the address of x in memory, then the actual value of x.

### The size of pointers

Here's an interesting question: What is the size of a pointer? This is something that newer C programmers commonly get wrong.

In other words, is there a difference in size between a char \* pointer and a int \* pointer?

Remember, a pointer holds an address in memory. This means that the size of a pointer variable is just the size of a memory address! 32-bit architecture is called '32-bit' because the maximum address of the memory is 32 bits, or 4 bytes. This means that in 32-bit architecture, the size of **any** pointer variable would have a size of 4 bytes. Since the size of a memory address in 64-bit architecture is 8 bytes, any pointer variable would have a size of 8 bytes.

What I'm trying to say is that there is no difference between the size of a char \* pointer and a int \* pointer. They are all the same size! The only difference is that the value they **point** to has a different size.
### Double pointers

Here's another interesting question: Can you have double pointers? Can you have a pointer that points to another pointer?

Why not? Have a look at this code:

```c
#include <stdio.h>

int main()
{
	int x = 123;
	int *y = &x;
	int **z = &y;
}
```

This is an example of a double pointer! We declare z as a **double pointer** (notice there are two '\*'), meaning that it's a pointer that points to another pointer. Now, if we dereferenced z twice, we would get the value of x. This is perfectly valid C! 

However, don't make the mistake to do this:

```c
#include <stdio.h>

int main()
{
	int x = 123;
	int **y = &(&x);
}
```

When you try to compile this, you'll get a weird error:

```
$ gcc file.c
file.c: In function ‘main’:
file.c:6:19: error: lvalue required as unary ‘&’ operand
    6 |         int **y = &(&x);
      |                   ^
```

Remember that a pointer points to somewhere in memory, but it still takes up space; pointers are the same size as the size of memory addresses in your computer. '&x' would give you the address of x, but you can't directly take the pointer of that because it doesn't exist in memory! '&x' is not an **lvalue** in the compiler's world; it doesn't exist anywhere in memory, meaning you can't take the address of it with another '&' operator.

Instead, we have to do this:

```c
int x = 123;
int *y = &x;
int **z = &y;
```
This works because we **declared the variable** y. y exists somewhere in memory, and therefore we can take the pointer of it.

You can also have triple pointers (a pointer to a pointer to a pointer), quadruple pointers, and so on... you can go as long as you want. It's just that in practice, you very rarely see more than double pointers because you don't need to go further. However, they do exist; if you ever need to use them, just know that you can.
## Why do pointers exist?

### A practical example

Here is a practical example of how pointers would be used. We've already looked that the printf function from stdio.h lots of times, but we've never talked about input. There is an equivalent function for receiving input in stdio.h, called scanf. Here's an example of it being used:

```c
#include <stdio.h>

int main()
{
	int x;
	scanf("%d", &x);
	printf("The number you entered is: %d\n", x);
}
```

scanf reads the input, and right now we're telling it to read an integer. But if you look closely, we passed the pointer of x to scanf instead of just x. Why would we need to do that?

Back when we were talking about functions, I talked about what happens to parameters when a function is called. When you pass parameters to a function, in 32-bit architecture parameters are pushed onto the stack; in 64-bit architecture, the parameters are passed through 6 different registers (more parameters will be pushed onto the stack). 

No matter what architecture you're in, the variable you're passing as a parameter to a function has the same **value**, but a different **address** from the original variable. This is a little weird to understand, spend some time thinking through this. Look at this example:

```c
#include <stdio.h>

void stuff(int x)
{
	x = 2;
	printf("I changed x\n");
}

int main()
{
	int x = 1;
	
	printf("Right now, x is %d\n", x);
	stuff(x);
	printf("The value of x is now %d\n", x);
}
```
Here's the output:

```
$ gcc file.c
$ ./a.out
Right now, x is 1
I changed x
The value of x is now 1
```
The value of x in **stuff** changed, but the value of x in **main** never changed. The two x's in the different functions have a different address; changing the value of one will not impact the other.

So how could you change the value of a parameter? Pointers! Here's the code that would have worked:

```c
#include <stdio.h>

void stuff(int *x)
{
	*x = 2;
	printf("I changed x\n");
}

int main()
{
	int x = 1;
	
	printf("Right now, x is %d\n", x);
	stuff(&x);
	printf("The value of x is now %d\n", x);
}
```
And here's the output:

```
$ gcc file.c
$ ./a.out
Right now, x is 1
I changed x
The value of x is now 2
```

We successfully changed x this time! That's because we passed the **pointer** of x into stuff (I'm going to be calling the function stuff() 'stuff' and main() 'main' here). Because we passed the pointer of x, the variable \*x in stuff still points to that same x in main! This means when the value of x is **dereferenced** in stuff, we are modifying the value of x in main.

If we think back to scanf, that's why we had to pass the pointer of x. If we didn't, the value of x in our functions would not have been modified; we need to pass the **pointer** of x so that scanf can write the input into the correct place where we can see it.

This is just one example of how pointers are used. Pointers allows us to directly interact and manipulate the computer's memory; pointers are something that makes C stand out from other languages. We'll be looking in the next section how pointers are used to store strings and arrays in C.

## Void pointers

Lastly, I want to talk a bit about void pointers. Void pointers are essentially pointers that **do not have a type**. Void pointers are declared like this:

```c
#include <stdio.h>

int main()
{
	void *p;
}
```

Here, p is a void pointer; it does not have a type associated with it. This also means that you can't dereference it since the CPU doesn't know what type the pointer has! If you try, you'll just get an error:

```
$ gcc file.c
file.c: In function ‘main’:
file.c:6:9: error: dereferencing ‘void *’ pointer
    6 |         *p;
      |         ^~
$
```

You may ask, why would void pointers be useful. Well, they're useful when you don't know what type you're going to be dealing with. I can't really explain this well with how much you currently know about data structures, but if you're interested, I have an explanation linked [here](Linked_lists.md) when I talk about linked lists.

