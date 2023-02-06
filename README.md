# GuyInTheMiddle

GuyInTheMiddle (GITM) is a tool for intercepting and manipulating HTTP/S traffic.  
GITM is cross-platform (currently tested on Windows and Linux).  
GITM is currently in development but is already capable of basic interception and manipulation.

## Building

### Dependencies:

- CMake 3.6+
- Qt 6.0+ (Core, GUI, Widgets)
- OpenSSL
- Boost 1.71 (zlib, iostreams, log)
- [Brotli](https://github.com/google/brotli)

**Make sure you set all the environment variables for the dependencies so CMake can find them.**

---

```sh
git clone https://github.com/Guy293/GITM
cd GITM
cmake .
make
```

## Certificate

Currently GITM can't generate a certificate for HTTPS interception. You can either use the one provided in the
repository or generate your own.

Install the certificate either in your system or directly in your browser.

Note: The cert.crt and cert.key needs to be in the same directory as the executable.
