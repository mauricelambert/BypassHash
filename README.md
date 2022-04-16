![BypassHash logo](https://mauricelambert.github.io/info/go/security/BypassHash_small.png "BypassHash logo")

# BypassHash

## Description

This tool downloads an executable file via HTTP(S) and randomizes its contents before writing it to a file to bypass simple hash-based antivirus checks.

## Requirements

### Download

 - *No requirements*

### Compilation

 - Go
 - Go Standard library

## Installation

### Download

Download the executable from [Github](https://github.com/mauricelambert/BypassHash/releases/latest/) or [Sourceforge](https://sourceforge.net/projects/BypassHash/files/).

### Compilation

```bash
git clone https://github.com/mauricelambert/BypassHash.git
cd BypassHash
go build BypassHash.go
```

## Usages

```bash
BypassHash <url> <filename>

BypassHash.exe http://127.0.0.1:8000/hello.exe test.exe
```

## Links

 - [Executable - Github](https://github.com/mauricelambert/BypassHash/releases/latest/)
 - [Executable - SourceForge](https://sourceforge.net/projects/BypassHash/files/)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).