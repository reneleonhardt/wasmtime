# Using linear memory

You can also browse this source code online and clone the wasmtime
repository to run the example locally:

* [Rust](https://github.com/bytecodealliance/wasmtime/blob/main/examples/memory.rs)
* [C](https://github.com/bytecodealliance/wasmtime/blob/main/examples/memory.c)
* [C++](https://github.com/bytecodealliance/wasmtime/blob/main/examples/memory.cc)

This example shows off how to interact with wasm memory in a module. Be sure to
read the documentation for [`Memory`] as well.

[`Memory`]: https://bytecodealliance.github.io/wasmtime/api/wasmtime/struct.Memory.html

## Wasm Source

```wat
{{#include ../examples/memory.wat}}
```

## Host Source

<!-- langtabs-start -->

```rust
{{#include ../examples/memory.rs}}
```

```c
{{#include ../examples/memory.c}}
```

```cpp
{{#include ../examples/memory.cc}}
```

<!-- langtabs-end -->

## Linux memory locking

[`Config::memory_locking`] can lock new linear memories and exclude them from
Linux core dumps. The CLI option is `-O memory-locking=<bytes>`. The byte limit
caps each protected reservation. The process's `RLIMIT_MEMLOCK` must cover all
protected reservations, including unused pages. Growth stays within the initial
reservation. This option requires the on-demand allocator and is disabled by default.

This protects linear memory against swapping and native core dumps. It does not
add guard pages around guest allocations or protect copies outside linear memory.

[`Config::memory_locking`]: https://docs.wasmtime.dev/api/wasmtime/struct.Config.html#method.memory_locking
