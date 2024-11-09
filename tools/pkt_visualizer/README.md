# PKT Visualizer

This tool shows part of the contents of a PKT file.

It shows the first and last 5 entries as well as 20 entries from the middle of the dataset.

## Dependencies

- [CMake](https://cmake.org/)

## How to compile

1. Setup and create the build directory
```sh
mkdir build && cd build
```

2. Generate the build files using cmake
```sh
cmake ..
```

3. Compile the tool
```sh
make
```

## How to use the tool

For the execution of the tool, there is only one parameter required:
1. The PKT file.

Example:
```sh
pkt-visualizer -f /path/to/file.pkt
```
