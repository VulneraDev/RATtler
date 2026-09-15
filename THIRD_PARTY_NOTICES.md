# Third-party notices

RATtler's portable macOS application bundles these unmodified runtime
dependencies:

- **cryptography 50.0.1** (**48.0.1** in the legacy Intel Mac build) —
  Copyright © individual contributors; available under Apache License 2.0 or
  BSD 3-Clause. RATtler uses the Argon2id and AES-GCM implementations for
  encrypted recovery exports. Version 48.0.1 is pinned on Intel because current
  releases no longer publish an Intel macOS wheel.
  Sources: <https://github.com/pyca/cryptography/tree/50.0.1> and
  <https://github.com/pyca/cryptography/tree/48.0.1>
- **YARA 4.5.4** — Copyright © 2007–2016 The YARA Authors; BSD 3-Clause.
  Source: <https://github.com/VirusTotal/yara/tree/v4.5.4>
- **yara-python 4.5.4** — Python bindings for YARA; Apache License 2.0.
  Source: <https://github.com/VirusTotal/yara-python/tree/v4.5.4>

The complete license texts are included in `licenses/`. RATtler's own source
and community rules remain MIT-licensed; bundling these dependencies does not
change that license.
