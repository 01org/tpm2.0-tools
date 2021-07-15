% tpm2_import(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_import**(1) - Imports an external key into the tpm as a TPM managed key
object.

# SYNOPSIS

**tpm2_import** [*OPTIONS*]

# DESCRIPTION

**tpm2_import**(1) - Imports an external generated key as TPM managed key object.
It requires that the parent key object be a RSA key. Can also import a TPM
managed key object created by the tpm2_duplicate tool.

# OPTIONS

These options control the key importation process:

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    The algorithm used by the key to be imported. Supports:
    * **aes** - AES 128, 192 or 256 key.
    * **rsa** - RSA 1024 or 2048 key.
    * **ecc** - ECC NIST P192, P224, P256, P384 or P521 public and private key.
	* **hmac** - HMAC key.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm for generating the objects name. This is optional
    and defaults to **sha256** when not specified. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * **-i**, **\--input**=_FILE_:

    Specifies the filename of the key to be imported. For AES keys,
    this file is the raw key bytes. For assymetric keys in PEM or DER
    format. A typical file is generated with `openssl genrsa`.

  * **-C**, **\--parent-context**=_OBJECT_:

    The parent key object.

  * **-U**, **\--parent-public**=_FILE_:

    Optional. Specifies the parent key public data file input. This can be read
    with **tpm2_readpublic**(1) tool. If not specified, the tool invokes a
    tpm2_readpublic on the parent object.

  * **-k**, **\--encryption-key**=_FILE_:

    Optional. Specifies the file containing the symmetric algorithm key that was
    used for the inner wrapper. If the file is specified the tool assumes the
    algorithm is AES 128 in CFB mode otherwise none.

  * **-r**, **\--private**=_FILE_:

    Specifies the file path required to save the encrypted private portion of
    the object imported as key.

    When importing a duplicated object this option specifies the file containing
    the private portion of the object to be imported.
    [protection details](common/protection-details.md)

  * **-u**, **\--public**=_FILE_:

    Specifies the file path required to save the public portion of the object
    imported as key

    When importing a duplicated object this option specifies the file containing
    the public portion of the object to be imported.

  * **-a**, **\--attributes**=_ATTRIBUTES_:

    The object attributes, optional.

  * **-P**, **\--parent-auth**=_AUTH_:

    The authorization value for using the parent key specified with **-C**.

  * **-p**, **\--key-auth**=_AUTH_:

    The authorization value for the imported key, optional.

  * **-L**, **\--policy**=_POLICY\_FILE_:

    The policy file.

  * **-s**, **\--seed**=_FILE_:

    Specifies the file containing the encrypted seed of the duplicated object.

  * **\--passin**=_OSSL\_PEM\_FILE\_PASSWORD_

    An optional password for an Open SSL (OSSL) provided input file. It mirrors
    the -passin option of OSSL and is known to support the pass, file, env, fd
    and plain password formats of openssl. (see *man(1) openssl*) for more.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[object attribute specifiers](common/obj-attrs.md) details the options for
specifying the object attributes _ATTRIBUTES_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## To import a key, one needs to have a parent key
```bash
tpm2_createprimary -Grsa2048:aes128cfb -C o -c parent.ctx
```

Create your key and and import it. If you already have a key, just use that
and skip creating it.

## Import an AES 128 key
```bash
dd if=/dev/urandom of=sym.key bs=1 count=16

tpm2_import -C parent.ctx -G aes -i sym.key -u key.pub -r key.priv
```

## Import an RSA key
```bash
openssl genrsa -out private.pem 2048

tpm2_import -C parent.ctx -G rsa -i private.pem -u key.pub -r key.priv
```

## Import an ECC key
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem

tpm2_import -C parent.ctx -G ecc -i private.ecc.pem -u key.pub -r key.priv
```

## Import a duplicated key
```bash
tpm2_import -C parent.ctx -i key.dup -u key.pub -r key.priv -L policy.dat
```

# LIMITATIONS
  * The TPM requires that the name algorithm of the child be smaller than the
    parent.

[returns](common/returns.md)

[footer](common/footer.md)
