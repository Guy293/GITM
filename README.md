# GuyInTheMiddle

GuyInTheMiddle (GITM) is a tool for intercepting and manipulating HTTP/S traffic.  
GITM is cross-platform (currently tested on Windows and Linux).  
GITM is currently in development but is already capable of basic interception and manipulation.

## Building

### Dependencies:

- CMake 3.6+
- Qt 6.0+ (Core, GUI, Widgets)
- OpenSSL
- Boost 1.71+ (zlib, iostreams, log)
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

GITM will generate a certificate for HTTPS interception on first run and store it in the `settings.ini` file.  
You can download the certificate by connecting to the proxy and visiting either <http://gitm/>, <http://certificate/>
or <http://cert/>.  
Install the certificate either in your system (Trusted Root Certification Authorities on Windows) or directly in your
browser.

#### Tutorials:

- [Windows](https://learn.microsoft.com/en-us/skype-sdk/sdn/articles/installing-the-trusted-root-certificate)
- [Android](https://stackoverflow.com/a/65319223/9039217) (You might need to bypass some apps ssl pinning)
- [Firefox](https://docs.vmware.com/en/VMware-Adapter-for-SAP-Landscape-Management/2.1.0/Installation-and-Administration-Guide-for-VLA-Administrators/GUID-0CED691F-79D3-43A4-B90D-CD97650C13A0.html)