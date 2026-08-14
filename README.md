# Active Directory Integrated DNS dump tool

![Python 3](https://img.shields.io/badge/python-3.x-blue.svg)
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

The tool requires `impacket` and `dnspython` to function. 

Installation adds the `adidnsdump` command to your `PATH`. For help, try `adidnsdump -h`.
The tool can be used both directly from the network and via an implant using proxychains. If using proxychains, make sure to specify the `--dns-tcp` option.

## Kerberos authentication

Use `-k` to authenticate with Kerberos (GSSAPI). Obtain a ticket first with `kinit`, do not specify a username or password:

```
adidnsdump -k hostname
```

Requires the `gssapi` package and a valid `krb5.conf` / credential cache.

## LDAP channel binding (CBT)

Domain Controllers with the "LDAP channel binding" policy enabled (this enforces channel binding for LDAP, returning `80090346` / SEC_E_BAD_BINDINGS on normal binds) require the patched `ldap3` fork and LDAPS with channel binding:

```
pip install git+https://github.com/ly4k/ldap3
adidnsdump --ssl --ldap-channel-binding -u DOMAIN\\user -p pass hostname
```

or install the optional dependency via pip:

```
pip install 'adidnsdump[channel-binding]'
```

## SRV records

Use `--srv` to also resolve and dump hidden SRV records (e.g. `_kerberos._tcp`, `_ldap._tcp`) when combined with `-r`:
