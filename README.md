# openvpn-ldap

A multi-threaded authentication plugin for OpenVPN to allow authentication against an LDAP directory server such as Active Directory without blocking traffic and causing packet loss.

## Building

To build, you'll need the following:

* OpenLDAP development files (openldap-devel on RHEL/CentOS)
* Rust compiler v1.40+ (https://rustup.rs)

Once you have those installed, you can build the plugin by cloning this repository and running the following command in the project root:

```bash
cargo build --release
```

If all goes well, you should now have the compiled plugin in `target/release/libopenvpn_ldap.so`

## Configuring OpenVPN

Once built, copy the compiled plugin to `/usr/local/lib/libopenvpn_ldap.so`.

Copy & rename `example.conf` to a location readable by OpenVPN, and update the settings to reflect your desired LDAP configuration.

Add the following to you OpenVPN server config file:

```
plugin /usr/local/lib/libopenvpn_ldap.so "<config_file_path>"
```

where `<config_file_path>` is the absolute path of your plugin configuration file.

Restart OpenVPN and test.
