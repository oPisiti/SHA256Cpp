# SHA256 algorithm
SHA256 implementation in C++.

## Compilation

```bash
g++ SHA256.cpp -o SHA256
```
Then, add the binary to your PATH or execute from current directory.

## Usage

```bash
SHA256 [file] [-t text]
```

To hash multiple files or text strings, simply append their names separated by a space, as in:
```bash
SHA256 <file1> <file2> <file3>
```
