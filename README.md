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

By default, this package only alerts on the HTTP `original_URI`, which is the raw URL path seen on the network. To alert on the `unescaped_URI` (which decodes anything that is URL encoded), add the following to your `local.zeek`:

```zeek
redef Intel::seen_unescaped_uri = T;
```

You can also disable alerting on the `original_URI` with the following:

```zeek
redef Intel::seen_original_uri = T;
```