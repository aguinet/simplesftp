# simplesftp

`simplesftp` is a very simple read-only SFTP server that serves one directory of your system over SFTP.

If you just want to serve some directory over SFTP without any headaches or
fear or misconfiguration, that's the tool you need!

Features/goals:

* serves one directory in read-only mode
* enforces read-only at the server level: the server won't accept any "write"
  command from the client
* supports multiple users authenticated with passwords and/or public keys

Non-goals:

* per-user directories (maybe in some future?)
* any form of shell for users

## Quick start

```
# Generate a host key with no password
$ ssh-keygen -t rsa -b 4096 -f host_key

# Setup users in a YAML file
$ cat users.yaml
pass:
  - user: john
    password: doe

# Spawn simplesftp
$ simplesftp -addr 127.0.0.1:2022 -key host_key -dir /path/to/directory -creds-file users.yaml

# Connect to simplesftp, use "doe" as password
$ sftp -P2022 john@127.0.0.1
```

## Users credentials YAML

The full format of the users YAML configuration file is:

```
# List all user/password couples. If multiple passwords are set for a given
user, only the last one is considered.
pass:
  - user: john
    password: doe

# List all user/public key couples. Multiple public keys can be set for one user.
pubkeys:
  # In this case, john can authenticate either with a password or a public key
  - user: john
    pubkey: |
      ssh-rsa ...	
  # In this case, robert can only authenticate with a public key
  - user: robert
    pubkey: |
      ssh-rsa ...
```


## Build & test

`simplesftp` requires at least go 1.26. To build it:

```
$ go build .
```

To run tests:

```
$ go test .
```
