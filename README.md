# Zeek Intel URL Path Package
This package that extends the Intel framework to alert on URL paths (URIs).

## Installation

This package can be installed using the [Zeek Package Manager](https://packages.zeek.org/):

```
$ zkg install zeek-intel-path
```

## Usage

This package adds a new intel type: `Intel::URL_PATH`. Here is an example intel file that uses this type:

```
#fields	indicator	indicator_type	meta.source
/malware	Intel::URL_PATH	Test IOC
```

Alerts will be generated in the `intel.log` and however else you have the Intel framework configured (e.g., email, `notice.log`, etc.).