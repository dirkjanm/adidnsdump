# Active Directory Integrated DNS dump tool

![Python 2.7 and 3 compatible](https://img.shields.io/badge/python-2.7%2C%203.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/adidnsdump.svg)
![License: MIT](https://img.shields.io/pypi/l/adidnsdump.svg)

By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones, similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.

For more info, read the [associated blog post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

# Install and usage
You can either install the tool via pip with `pip install adidnsdump` or install it from git to have the latest version:

```
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .
```

or

```
pip install git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump
```

The tool requires `impacket` and `dnspython` to function. While the tool works with both Python 2 and 3, Python 3 support requires you to install [impacket from GitHub](https://github.com/CoreSecurity/impacket).

Installation adds the `adidnsdump` command to your `PATH`. For help, try `adidnsdump -h`.
The tool can be used both directly from the network and via an implant using proxychains. If using proxychains, make sure to specify the `--dns-tcp` option.
