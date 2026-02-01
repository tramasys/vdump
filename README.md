# vdump

`vdump` decodes the current process's `vdso`, `vvar`, and `vvar_clock` mappings. No input binary or PID is needed. Requires linux and Rust 1.97 or newer.

```sh
cargo install --path .
vdump
vdump vdso
vdump --hex vvar
vdump --raw vdso > vdso.bin
vdump --list
```

Some kernels leave pages inside vvar mappings unreadable. In `--hex` they appear as `??`.
Raw output replaces them with zeroes and warns on stderr. Add `--strict` to reject an incomplete raw dump.
