Vendored copies of botan 1.13.6 and [Dadoum/Provision](https://github.com/Dadoum/Provision)
(`645d56d`). They are in-tree so the macOS CLI builds with LDC 1.41 without
hitting D 2.111 `delete` / protected-ctor / TLS associative-array issues in
the published dub packages.
