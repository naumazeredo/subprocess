# tiny-process-library
A small platform independent library making it simple to create and stop new processes in C++, as well as writing to stdin and reading from stdout and stderr of a new process.

### Features
* Header-only project
* No external dependencies
* Simple to use
* Platform independent
  * Creating processes using executables is supported on all platforms
  * Creating processes using functions is only possible on Unix-like systems
* Read separately from stout and stderr using anonymous functions
* Write to stdin
* Kill a running process (SIGTERM is supported on Unix-like systems)
* Correctly closes file descriptors/handles

### Usage

TODO
