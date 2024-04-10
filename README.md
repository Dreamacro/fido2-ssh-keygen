# FIDO SSH keygen

### Why

When export the FIDO2 ed25519sk keyhandle from OpenSSH, it would missing flag of `no-touch-required`. This crate is to generate the FIDO2 ed25519sk/ecdsa-sk keyhandle with the flags.

```shell
# generate the FIDO2 ed25519-sk is right
$ ssh-keygen -t ed25519-sk -O resident -O no-touch-required -O application=ssh:general -C "comment"

# but the export keyhandle is missing the flag of no-touch-required
# and it doesn't support custom comment
$ ssh-keygen -K
```

### Usage

```shell
$ fido2-ssh-keygen --help
```

### Example

```shell
$ fido2-ssh-keygen export -O no-touch-required -f ~/.ssh/id_ed25519_sk
```

```shell
$ fido2-ssh-keygen export -O no-touch-required -C "my comment"
```
