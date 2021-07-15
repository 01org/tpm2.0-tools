# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f import_key.ctx import_key.name import_key.priv import_key.pub \
    parent.ctx plain.dec.ssl  plain.enc plain.txt sym.key import_rsa_key.pub \
    import_rsa_key.priv import_rsa_key.ctx import_rsa_key.name private.pem \
    public.pem plain.rsa.enc plain.rsa.dec public.pem data.in.raw \
    data.in.digest data.out.signed ticket.out ecc.pub ecc.priv ecc.name \
    ecc.ctx private.ecc.pem public.ecc.pem passfile aes.key policy.dat \
    aes.priv aes.pub sealdata seal.pub seal.priv seal.ctx unsealdata hmackey \
    hmac.pub hmac.priv hmac.ctx hmac-tpm2.out hmac-ossl.out

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

run_aes_import_test() {

    dd if=/dev/urandom of=sym.key bs=1 count=$3 2>/dev/null

    #Symmetric Key Import Test
    echo "tpm2 import -Q -G aes -g "$name_alg" -i sym.key -C $1 \
    -u import_key.pub -r import_key.priv"

    tpm2 import -Q -G aes -g "$name_alg" -i sym.key -C $1 -u import_key.pub \
    -r import_key.priv

    tpm2 load -Q -C $1 -u import_key.pub -r import_key.priv -n import_key.name \
    -c import_key.ctx

    echo "plaintext" > "plain.txt"

    if is_cmd_supported "EncryptDecrypt"; then
        tpm2 encryptdecrypt -c import_key.ctx -o plain.enc plain.txt

        openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -c 256 -p sym.key` \
        -iv 0 -$2

        diff plain.txt plain.dec.ssl
    else
        tpm2 readpublic -c import_key.ctx >out.pub
        alg=$(yaml_get_kv out.pub "sym-alg" "value")
        if [ "$alg" != "aes" ]; then
            echo "Algorithm parsed from tpm2 readpublic is '$alg' but should be \
                  'aes'"
            exit 1
        fi
        rm out.pub
    fi

    rm import_key.ctx
}

run_rsa_import_test() {

    #Asymmetric Key Import Test
    openssl genrsa -out private.pem $2
    openssl rsa -in private.pem -pubout > public.pem

    # Test an import without the parent public info data to force a readpublic
    tpm2 import -Q -G rsa -g "$name_alg" -i private.pem -C $1 \
    -u import_rsa_key.pub -r import_rsa_key.priv

    tpm2 load -Q -C $1 -u import_rsa_key.pub -r import_rsa_key.priv \
    -n import_rsa_key.name -c import_rsa_key.ctx

    openssl rsa -in private.pem -out public.pem -outform PEM -pubout
    openssl rsautl -encrypt -inkey public.pem -pubin -in plain.txt \
    -out plain.rsa.enc

    tpm2 rsadecrypt -c import_rsa_key.ctx -o plain.rsa.dec plain.rsa.enc

    diff plain.txt plain.rsa.dec

    # test verifying a sigature with the imported key, ie sign in tpm and
    # verify with openssl
    echo "data to sign" > data.in.raw

    shasum -a 256 data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > \
    data.in.digest

    tpm2 sign -Q -c import_rsa_key.ctx -g sha256 -d -f plain \
    -o data.out.signed data.in.digest

    openssl dgst -verify public.pem -keyform pem -sha256 -signature \
    data.out.signed data.in.raw

    # Sign with openssl and verify with TPM
    openssl dgst -sha256 -sign private.pem -out data.out.signed data.in.raw

    # Verify with the TPM
    tpm2 verifysignature -Q -c import_rsa_key.ctx -g sha256 -m data.in.raw \
    -f rsassa -s data.out.signed -t ticket.out

    rm import_rsa_key.ctx
}

run_ecc_import_test() {
    #
    # Test loading an OSSL PEM format ECC key, and verifying a signature
    # external to the TPM
    #

    #
    # Generate a Private and Public ECC pem file
    #
    openssl ecparam -name $2 -genkey -noout -out private.ecc.pem
    openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

    # Generate a hash to sign
    echo "data to sign" > data.in.raw
    shasum -a 256 data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > \
    data.in.digest

    tpm2 import -Q -G ecc -g "$name_alg" -i private.ecc.pem -C $1 -u ecc.pub \
    -r ecc.priv

    tpm2 load -Q -C $1 -u ecc.pub -r ecc.priv -n ecc.name -c ecc.ctx

    # Sign in the TPM and verify with OSSL
    tpm2 sign -Q -c ecc.ctx -g sha256 -d -f plain -o data.out.signed \
    data.in.digest
    openssl dgst -verify public.ecc.pem -keyform pem -sha256 \
    -signature data.out.signed data.in.raw

    # Sign with openssl and verify with TPM.
    openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw
    tpm2 verifysignature -Q -c ecc.ctx -g sha256 -m data.in.raw -f ecdsa \
    -s data.out.signed

    rm ecc.ctx
}

run_rsa_import_passin_test() {

    if [ "$3" != "stdin" ]; then
        tpm2 import -Q -G rsa -i "$2" -C "$1" \
            -u "import_rsa_key.pub" -r "import_rsa_key.priv" \
            --passin "$3"
    else
        tpm2 import -Q -G rsa -i "$2" -C "$1" \
            -u "import_rsa_key.pub" -r "import_rsa_key.priv" \
            --passin "$3" < "$4"
    fi;
}

run_aes_policy_import_test() {

	dd if=/dev/urandom of=aes.key bs=16 count=1
	dd if=/dev/urandom of=policy.dat bs=32 count=1

	tpm2 import -C "$1" -G aes -i aes.key -L policy.dat -u aes.pub -r aes.priv

	tpm2 load -C "$1" -u aes.priv -u aes.pub -r aes.priv -c aes.ctx

	trap - ERR
	echo 'foo' | tpm2 encryptdecrypt -c aes.ctx -o plain.rsa.dec plain.rsa.enc
	if [ $? -eq 0 ]; then
		echo "expected tpm2 encryptdecrypt to fail"
		exit 1
	fi
        trap onerror ERR
}

run_keyedhash_seal_import_test() {

    dd if=/dev/urandom of=sealdata bs=128 count=1
    tpm2 import -C "$1" -G hmac -i sealdata -a 'userwithauth' -u seal.pub -r seal.priv
    tpm2 load -C "$1" -u seal.pub -r seal.priv -c seal.ctx
    tpm2 unseal -c seal.ctx -o unsealdata
    cmp sealdata unsealdata
}

run_keyedhash_hmac_import_test() {

    dd if=/dev/urandom of=hmackey bs=73 count=1
    hexkey=$(xxd -p -c 256 < hmackey)
    tpm2 import -C "$1" -G hmac -i hmackey -u hmac.pub -r hmac.priv
    tpm2 load -C "$1" -u hmac.pub -r hmac.priv -c hmac.ctx
    echo -n "test data" | tpm2 hmac -g sha256 -c hmac.ctx -o hmac-tpm2.out
    echo -n "test data" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$hexkey" -binary -out hmac-ossl.out
    cmp hmac-tpm2.out hmac-ossl.out
}

run_test() {

    cleanup "no-shut-down"

    parent_alg=$1
    name_alg=$2

    tpm2 createprimary -Q -G "$parent_alg" -g "$name_alg" -C o -c parent.ctx

    # 128 bit AES is 16 bytes
    if is_alg_supported aes128; then
        run_aes_import_test parent.ctx aes-128-cfb 16
    fi
    # 256 bit AES is 32 bytes
    if is_alg_supported aes256; then
        run_aes_import_test parent.ctx aes-256-cfb 32
    fi

    run_rsa_import_test parent.ctx 1024
    run_rsa_import_test parent.ctx 2048

    run_ecc_import_test parent.ctx prime256v1

    run_keyedhash_seal_import_test parent.ctx
    run_keyedhash_hmac_import_test parent.ctx
}

#
# Run the tests against:
#   - RSA2048 with AES CFB 128 and 256 bit parents
#   - SHA256 object (not parent) name algorithms
#
parent_algs=("rsa2048:aes128cfb" "rsa2048:aes256cfb" "ecc256:aes128cfb")
halgs=`populate_hash_algs 'and alg != "sha1"'`
echo "halgs: $halgs"
for pa in "${parent_algs[@]}"; do
  for name in $halgs; do
    if is_alg_supported $pa; then
        echo "$pa - $name"
        run_test "$pa" "$name"
    fi
  done;
done;

#
# Test the passin options
#

tpm2 createprimary -Q -c parent.ctx

openssl genrsa -aes128 -passout "pass:mypassword" -out "private.pem" 1024

run_rsa_import_passin_test "parent.ctx" "private.pem" "pass:mypassword"

export envvar="mypassword"
run_rsa_import_passin_test "parent.ctx" "private.pem" "env:envvar"

echo -n "mypassword" > "passfile"
run_rsa_import_passin_test "parent.ctx" "private.pem" "file:passfile"

exec 42<> passfile
run_rsa_import_passin_test "parent.ctx" "private.pem" "fd:42"

run_rsa_import_passin_test "parent.ctx" "private.pem" "stdin" "passfile"

run_aes_policy_import_test "parent.ctx"

exit 0
