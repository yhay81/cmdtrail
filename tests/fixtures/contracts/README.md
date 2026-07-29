# Receipt compatibility corpus

`v0.1/portable.receipt.json` is the byte-for-byte compatibility artifact for
`cmdtrail.receipt.v1`. It contains all three v0.1 event variants and is sealed
with the documented RFC 8785 domain-separated digest algorithm.

`manifest.json` pins the accepted artifact digest and declares mutations that
the current reader or verifier must reject. `verify_golden.py` is an
independent, standard-library-only verifier for the v0.1 receipt data model; it
does not import or execute CmdTrail. `test_verify_golden.py` runs that verifier
against the same thirteen declared mutations used by the Rust compatibility
suite.

The corpus is immutable once published. Add a new version directory when a
future schema intentionally changes bytes or semantics.
