% tpm2_pcrextend(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_pcrextend**(1) - Extends a PCR.

# SYNOPSIS

**tpm2_pcrextend** [*OPTIONS*] _PCR\_DIGEST\_SPEC_

# DESCRIPTION

**tpm2_pcrextend**(1) - Extends the pcrs with values indicated by _PCR\_DIGEST\_SPEC_.

A _PCR\_DIGEST\_SPEC_ is defined as follows:

  * A numerical PCR identifier.
  * A colon followed by the algorithm hash specification.

The algorithm hash specification is as follows:
  * The algorithm friendly name or raw numerical.
  * An equals sign.
  * The hex hash value.

### Example Digest Specification

```
4:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15
```

**Note**: Multiple specifications of PCR and hash are allowed. Multiple
hashes cause the PCR to be extended with both hashes. Multiple same PCR values
cause the PCR to be extended multiple times. Extension is done in order from
left to right as specified. At most 5 hash extensions per PCR entry are
supported. This is to keep the parser simple.

# OPTIONS

This tool accepts no tool specific options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[PCR bank specifiers](common/pcr.md)

# EXAMPLES

## Extend PCR 4's SHA1 bank with a hash
```bash
tpm2_pcrextend 4:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15
```

## Extend PCR 4's SHA1 and SHA256 banks with hashes
```bash
tpm2_pcrextend 4:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15,sha256=b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c
```

## Extend PCR 4's SHA1 and PCR 7's SHA256 bank with hashes
```bash
tpm2_pcrextend 4:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15 7:sha256=b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c
```

[returns](common/returns.md)

[footer](common/footer.md)
