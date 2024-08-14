# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [1.2.6] - 2024-08-14

- mech_mx: fix incorrect evaluation of MX addresses (#26)

### [1.2.5] - 2024-04-17

- get_mx: filter out implicit MX records
- dep: eslint-plugin-haraka -> @haraka/eslint-config
- chore: lint: remove duplicate / stale rules from .eslintrc
- chore: populate [files] in package.json. Delete .npmignore.
- doc(CONTRIBUTORS): added
- doc(CHANGES): renamed CHANGELOG
- chore: prettier

### [1.2.4] - 2024-02-07

- doc(README): add ini code fences, improve docs
- dep(net-utils): bumped 1.5.0 -> 1.5.3

### [1.2.3] - 2023-07-14

- fix: Handle DNS TXT array result (#15)

### [1.2.2] - 2023-06-22

- fix: check for DNS results befor iterating, fixes #13
- es6(lib/spf): replace `self` with `this`

### [1.2.1] - 2023-06-19

- fix: call skip_hosts via 'this' instead of exports (#11)
- skip configuration was being ignored
- es6(index): replace `plugin` with `this`
- deps: bump versions to latest

### [1.2.0] - 2023-01-19

- Export SPF class (#8)

### [1.1.3] - 2022-12-23

- fix print log (#6)

### [1.1.2] - 2022-12-21

- dep: depend on net-utils 1.5.0
- refactor: convert loop to for...of

### [1.1.0] - 2022-12-17

- spf: use async/await dns
- replace many callbacks with async/await
- make check_host more linear
- ci(publish): only when package.json bumped
- index: safeguard cfg path with optional chaining, fixes #2
- dep(nopt): bump 6 -> 7

### [1.0.1] - 2022-07-23

- add bin/spf
- move spf.js to lib/spf.js

### 1.0.0 - 2022-07-23

- Import from Haraka

[1.0.0]: https://github.com/haraka/haraka-plugin-spf/releases/tag/v1.0.0
[1.0.1]: https://github.com/haraka/haraka-plugin-spf/releases/tag/1.0.1
[1.1.0]: https://github.com/haraka/haraka-plugin-spf/releases/tag/v1.1.0
[1.1.2]: https://github.com/haraka/haraka-plugin-spf/releases/tag/v1.1.2
[1.1.3]: https://github.com/haraka/haraka-plugin-spf/releases/tag/1.1.3
[1.1.4]: https://github.com/haraka/haraka-plugin-spf/releases/tag/1.1.4
[1.2.0]: https://github.com/haraka/haraka-plugin-spf/releases/tag/1.2.0
[1.2.1]: https://github.com/haraka/haraka-plugin-spf/releases/tag/1.2.1
[1.2.2]: https://github.com/haraka/haraka-plugin-spf/releases/tag/1.2.2
[1.2.3]: https://github.com/haraka/haraka-plugin-spf/releases/tag/1.2.3
[1.2.4]: https://github.com/haraka/haraka-plugin-spf/releases/tag/v1.2.4
[1.2.5]: https://github.com/haraka/haraka-plugin-spf/releases/tag/v1.2.5
[1.2.6]: https://github.com/haraka/haraka-plugin-spf/releases/tag/v1.2.6
