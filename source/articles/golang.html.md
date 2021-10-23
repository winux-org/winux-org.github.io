---
title:  Golang bridging
date:   2016-10-19 12:09:07 +0200
categories: golang
---

The Go tools are capable of static and dynamic linking with other libraries, and also there is possbility to create static and dynamic library, therefore it is possible to create a bridge between golang and the other language both ways.

### Creating shared and static library in Go

Let's create library we will use in external systems. Here is an example. File `example.go`:

```go
package main

import "C"
import "fmt"

//export SayHello
func SayHello(hello *C.char) {
		fmt.Print(C.GoString(hello))
}

func main() {}
```

and `Makefile` that will contain build script that you can invoke by `make static` or `make shared`. I am not sure if my solution present shows a good practice. Feel free to send a PR with improvement.

{% highlight make %}
static example.a:
	go build -o example.a -buildmode=c-archive example.go
shared example.dylib:
	go build -o example.dylib -buildmode=c-shared example.go
{% endhighlight %}

As far as I understand the main function is neccecery to include into library, because the final product has to have for example GC rutines. The comment starting from `//export {function name}` tells the comiler that this the function will be called from the outside.

### Calling functrion from library in Go

First off we will create C++ library that we will use in out Go program.
File `example.cxx`:

{% highlight c++ %}
#include <stdio.h>

extern "C" {

void PrintHello(const char* u) {
    printf("Hello: %s\n", u);
}

}
{% endhighlight %}

And `example.hxx`:

{% highlight c++ %}
#pragma once
void PrintHello(const char* u)
{% endhighlight %}

`extern "C" {}` informs the compiler that we want the function names to be preserved. That is, to not "mangle" the names as is done for C++ code.
`Makefile`:

{% highlight make %}
static example.a:
	clang++ -c -Wall -o lib.o ./example.cxx
	ar rc ./libexample.a ./lib.o
shared example.dylib:
	clang++ -dynamiclib -o libexample.dylib example.cxx
{% endhighlight %}


#### Statically linking an example library 

{% highlight go %}
package main

// #cgo CFLAGS: -I.
// #cgo LDFLAGS: -L. -lexample
//
// #include <example.hxx>
import "C"

func main() {
	C.PrintHello(C.CString("Hello Golang"))
}
{% endhighlight %}

The program is linked staticaly with libexample when you build it.

#### Example of using library with FFI

{% highlight shell %}
gem install ffi
{% endhighlight %}

{% highlight ruby %}
require 'ffi'
module Example
  extend FFI::Library
  ffi_lib './example.dylib'
  attach_function :SayHello, [:string]
end

Example.SayHello("Hello")
{% endhighlight %}

More informations about FFI: https://en.wikipedia.org/wiki/Foreign_function_interface

#### Call shared library from Python

{% highlight python %}
import ctypes
libc = ctypes.CDLL('./example.dylib')
libc.SayHello("Hello")
{% endhighlight %}

## Interesting websites

- https://blog.filippo.io/building-python-modules-with-go-1-5/
- https://id-rsa.pub/post/go15-calling-go-shared-libs-from-firefox-addon/