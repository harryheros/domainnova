# Third-party files

## public_suffix_list.dat

The [Public Suffix List](https://publicsuffix.org/), used by
`sources/scripts/_psl.py` to find the registrable name of a host
(`www.example.com.my` → `example.com.my`) and to recognise names that are
public suffixes (`com.my`) or are handed out under one (`x.sakura.ne.jp`).

- Source: https://publicsuffix.org/list/public_suffix_list.dat
- Version: commit `f7796455091118a5617cc7588523b083a8223301` of
  [publicsuffix/list](https://github.com/publicsuffix/list) (2026-11-19)
- License: [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/);
  the file is unmodified and keeps its license header.

To update, replace the file with the current one from the source above,
update the version line here, and run the unit tests.
