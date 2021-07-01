# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
    rm -f helpers.sh signing_key_private.pem signing_key_public.pem \
    signing_key.ctx signing_key.name authorized.policy policy.dat \
    primary.ctx key.prv key.pub key.ctx new_parent.prv new_parent.pub \
    new_parent.ctx new_parent.name key.name name.hash policy.namehash \
    policynamehash.signature policy.namehash verification.tkt dupprv.bin \
    dupseed.dat

    tpm2 flushcontext session.ctx 2>/dev/null || true
    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

generate_policycphash() {
    tpm2 startauthsession -S session.ctx -g sha256
    tpm2 policycphash -S session.ctx -L policy.cphash --cphash-input cp.hash
    tpm2 flushcontext session.ctx
    rm session.ctx
}

sign_and_verify_policycphash() {
    openssl dgst -sha256 -sign signing_key_private.pem \
    -out policycphash.signature policy.cphash

    tpm2 verifysignature -c signing_key.ctx -g sha256 -m policy.cphash \
    -s policycphash.signature -t verification.tkt -f rsassa
}

setup_authorized_policycphash() {
    tpm2 startauthsession -S session.ctx --policy-session -g sha256
    tpm2 policycphash -S session.ctx --cphash-input cp.hash
    tpm2 policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
    -t verification.tkt
}

setup_owner_policy() {
    tpm2 setprimarypolicy -C o -L policy.cphash -g sha256
    tpm2 startauthsession -S session.ctx --policy-session -g sha256
    tpm2 policycphash -S session.ctx --cphash-input cp.hash
}

start_policy_cphash() {
    tpm2 startauthsession -S session.ctx --policy-session -g sha256
    tpm2 policycphash -S session.ctx --cphash-input cp.hash
}

create_authorized_policy() {
  tpm2 clear
  # Define an authorized policy for an object
  openssl genrsa -out signing_key_private.pem 2048
  openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout
  tpm2 loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx \
  -n signing_key.name
  tpm2 startauthsession -S session.ctx -g sha256
  tpm2 policyauthorize -S session.ctx -L authorized.policy -n signing_key.name
  tpm2 flushcontext session.ctx
}

# Restrict the value that can be set through tpm2 nvsetbits.
create_authorized_policy
tpm2 nvdefine 1 -a "policywrite|authwrite|ownerread|nt=bits" -L authorized.policy
## Create policycphash
tpm2 nvsetbits 1 -i 1 --cphash cp.hash
generate_policycphash
## Sign and verify policycphash
sign_and_verify_policycphash
## Satisfy policycphash and execute nvsetbits
setup_authorized_policycphash
tpm2 nvsetbits 1 -i 1 -P "session:session.ctx"
tpm2 flushcontext session.ctx
## Attempt setting another bit which was not recorded in policycphash
setup_authorized_policycphash
trap - ERR
tpm2 nvsetbits 1 -i 2 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvsetbits must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 nvextend
create_authorized_policy
tpm2 nvdefine 1 -a "nt=extend|ownerread|policywrite" -L authorized.policy
echo "foo" | tpm2 nvextend -i- 1 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
echo "foo" | tpm2 nvextend -i- 1 -P "session:session.ctx"
tpm2 flushcontext session.ctx
## test the failing scenario
setup_authorized_policycphash
trap - ERR
echo "food" | tpm2 nvextend -i- 1 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvextend must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 nvincrement
create_authorized_policy
tpm2 nvdefine 1 -s 8 -a "nt=counter|ownerread|policywrite" -L authorized.policy
tpm2 nvincrement 1 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 nvincrement 1 -P "session:session.ctx"
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 nvread
create_authorized_policy
tpm2 nvdefine 1 -a "ownerwrite|policyread" -L authorized.policy
echo "foo" | tpm2 nvwrite 1 -i- -C o
tpm2 nvread 1 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 nvread 1 -P "session:session.ctx" | xxd -p
## test the failing scenario
setup_authorized_policycphash
trap - ERR
tpm2 nvread 1 -s 7 --offset 1 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvread must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 nvreadlock
create_authorized_policy
tpm2 nvdefine 1 -C o -s 32 -a "policyread|policywrite|read_stclear" \
-L authorized.policy
tpm2 nvreadlock 1 -C 0x01000001 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 nvreadlock 1 -C 0x01000001 -P "session:session.ctx"
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 nvwritelock
create_authorized_policy
tpm2 nvdefine 1 -C o -s 32 -a "policyread|policywrite|writedefine" \
-L authorized.policy
tpm2 nvwritelock 1 -C 0x01000001 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 nvwritelock 1 -C 0x01000001 -P "session:session.ctx"
tpm2 flushcontext session.ctx
tpm2 nvundefine 1
## attempt with globallock attribute set
tpm2 nvdefine 1 -C o -s 32 -a "ownerread|ownerwrite|globallock"
tpm2 nvwritelock --global -C o --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 nvwritelock --global -C o -P "session:session.ctx"
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 nvdefine
tpm2 nvdefine 1 -C o -s 32 -a "ownerread|ownerwrite" --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 nvdefine 1 -C o -s 32 -a "ownerread|ownerwrite" -P "session:session.ctx"
tpm2 flushcontext session.ctx
## attempt failing scenario
start_policy_cphash
trap - ERR
tpm2 nvdefine 2 -C o -s 32 -a "ownerread|ownerwrite" -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvdefine must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 nvundefine
tpm2 nvdefine 1
tpm2 nvundefine 1 --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 nvundefine 1 -P "session:session.ctx"
tpm2 flushcontext session.ctx
## attempt failing scenario
tpm2 nvdefine 2
start_policy_cphash
trap - ERR
tpm2 nvundefine 2 -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: nvundefine must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx
tpm2 nvundefine -C p 2

#Test tpm2 nvcertify
tpm2 createprimary -C o -c primary.ctx -Q
tpm2 create -G rsa -u signing_key.pub -r signing_key.priv -C primary.ctx \
-c signing_key.ctx -Q
tpm2 readpublic -c signing_key.ctx -f pem -o sslpub.pem -Q
tpm2 nvdefine -s 32 -C o -a "ownerread|ownerwrite|authread|authwrite" 1
dd if=/dev/urandom bs=1 count=32 status=none| tpm2 nvwrite 1 -i-
tpm2 nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1 -c o --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1 -c o -p "session:session.ctx"
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

#Test tpm2 policynv
tpm2 nvdefine -C o -a "ownerwrite|ownerread" -s 2 1
operandA=0x81
operandB=0x80
echo $operandA | xxd -r -p | tpm2 nvwrite -C o -i- 1
tpm2 startauthsession -S policy_session.ctx --policy-session -g sha256
echo $operandB | xxd -r -p | tpm2 policynv -i- -C o --cphash cp.hash 1 neq -S policy_session.ctx
generate_policycphash
setup_owner_policy
echo $operandB | xxd -r -p | tpm2 policynv -S policy_session.ctx -i- -C o -P "session:session.ctx" 1 neq
tpm2 flushcontext policy_session.ctx
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 policyauthorizenv
tpm2 nvdefine -C o 1 -a "ownerread|ownerwrite" -s 34
tpm2 startauthsession -S session.ctx
tpm2 policypassword -S session.ctx -L policy.pass
tpm2 flushcontext session.ctx
POLICYDIGESTALGORITHM=000b
echo $POLICYDIGESTALGORITHM | xxd -p -r | cat - policy.pass | \
tpm2 nvwrite -C o 1 -i-
tpm2 startauthsession -S policy_session.ctx --policy-session
tpm2 policyauthorizenv -S policy_session.ctx -C o 1 --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 policypassword -S policy_session.ctx
tpm2 policyauthorizenv -S policy_session.ctx -C o 1 -P "session:session.ctx"
tpm2 flushcontext policy_session.ctx
tpm2 flushcontext session.ctx
tpm2 nvundefine 1

# Test tpm2 policysecret
tpm2 startauthsession -S policy_session.ctx --policy-session -g sha256
tpm2 policysecret -S policy_session.ctx -c o --cphash cp.hash
tpm2 startauthsession -S session.ctx -g sha256
tpm2 policyauthvalue -S session.ctx -L policy.authval
tpm2 policycphash -S session.ctx --cphash cp.hash -L policy.authval_cphash
tpm2 flushcontext session.ctx
tpm2 setprimarypolicy -C o -L policy.authval_cphash -g sha256
tpm2 startauthsession -S session.ctx --policy-session -g sha256
tpm2 policyauthvalue -S session.ctx
tpm2 policycphash -S session.ctx --cphash cp.hash
## Changing the policysecret authhandle parameter fro "o" to "p" should fail
tpm2 policysecret -S policy_session.ctx -c o session:session.ctx
tpm2 flushcontext session.ctx
tpm2 flushcontext policy_session.ctx

# Test tpm2 create
create_authorized_policy
tpm2 createprimary -C o -c prim.ctx -G rsa -L authorized.policy
tpm2 create -C prim.ctx -G rsa --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 create -C prim.ctx -G rsa -P "session:session.ctx"
tpm2 flushcontext session.ctx
## Attempt creating a key type that was not recorded in policycphash
setup_authorized_policycphash
trap - ERR
tpm2 create -C prim.ctx -G aes -P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2 create must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx

# Test tpm2 load
create_authorized_policy
tpm2 createprimary -C o -c prim.ctx -G rsa -L authorized.policy
tpm2 create -C prim.ctx -G rsa -u key.pub -r key.priv
tpm2 create -C prim.ctx -G rsa -u key_2.pub -r key_2.priv
tpm2 load -C prim.ctx -u key.pub -r key.priv --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 load -C prim.ctx -u key.pub -r key.priv -c key.ctx -P "session:session.ctx"
tpm2 flushcontext session.ctx
## Attempt loading another key that was not recorded in policycphash
setup_authorized_policycphash
trap - ERR
tpm2 load -C prim.ctx -u key_2.pub -r key_2.priv -c key_2.ctx \
-P "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2 load must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx

# Test tpm2 activatecredential (using legacy option --cphash)
create_authorized_policy
tpm2 createprimary -C o -c prim.ctx -G rsa
tpm2 readpublic -c prim.ctx -o prim.pub
tpm2 create -C prim.ctx -u key.pub -r key.priv -c key.ctx -L authorized.policy
tpm2 readpublic -c key.ctx -n key.name
echo "plaintext" > plain.txt
tpm2 makecredential -u prim.pub  -s plain.txt -n `xxd -p -c 34 key.name` \
-o cred.secret
tpm2 activatecredential -c key.ctx -C prim.ctx -i cred.secret -o act_cred.secret \
--cphash cp.hash
tpm2 startauthsession -S session.ctx -g sha256
tpm2 policycphash -S session.ctx -L policy.cphash --cphash cp.hash
tpm2 policycommandcode -S session.ctx TPM2_CC_ActivateCredential -L policy.cphash
tpm2 flushcontext session.ctx
sign_and_verify_policycphash
tpm2 startauthsession -S session.ctx --policy-session -g sha256
tpm2 policycphash -S session.ctx --cphash cp.hash
tpm2 policycommandcode -S session.ctx TPM2_CC_ActivateCredential
tpm2 policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
tpm2 activatecredential -c key.ctx -C prim.ctx -i cred.secret -o act_cred.secret \
-p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 unseal
create_authorized_policy
tpm2 createprimary -C o -c prim.ctx
echo "plaintext" | \
tpm2 create -C prim.ctx -c key.ctx -u key.pub -r key.priv -L authorized.policy -i-
tpm2 unseal -c key.ctx --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 unseal -c key.ctx -p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 changeauth
tpm2 clear
tpm2 changeauth -c o ownerpassword --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 changeauth -c o ownerpassword -p session:session.ctx
tpm2 flushcontext session.ctx
## Negative test
tpm2 clear
tpm2 changeauth -c o ownerpassword --cphash cp.hash
generate_policycphash
setup_owner_policy
trap - ERR
tpm2 changeauth -c o wrongownerpassword -p session:session.ctx
if [ $? == 0 ];then
  echo "ERROR: tpm2 load must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx

#Test tpm2 duplicate
create_authorized_policy
tpm2 createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2 create -C primary.ctx -g sha256 -G rsa -r duplicable_key.prv \
-u duplicable_key.pub -a "sensitivedataorigin|sign|decrypt|encryptedduplication" \
-L authorized.policy
tpm2 load -C primary.ctx -r duplicable_key.prv -u duplicable_key.pub \
-c duplicable_key.ctx
tpm2 create -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub -a "decrypt|fixedparent|fixedtpm|restricted|\
sensitivedataorigin"
tpm2 loadexternal -C o -u new_parent.pub -c new_parent.ctx
dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none
tpm2 duplicate -C new_parent.ctx -c duplicable_key.ctx -G aes \
-i sym_key_in.bin -r dupprv.bin -s dupseed.dat --cphash cp.hash
tpm2 startauthsession -S session.ctx -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 policycommandcode -S session.ctx -L policy.cphash TPM2_CC_Duplicate
tpm2 flushcontext session.ctx
sign_and_verify_policycphash
tpm2 startauthsession --policy-session -S session.ctx -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 policycommandcode -S session.ctx TPM2_CC_Duplicate
tpm2 policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
tpm2 duplicate -C new_parent.ctx -c duplicable_key.ctx -G aes \
-i sym_key_in.bin -r dupprv.bin -s dupseed.dat -p "session:session.ctx"
tpm2 flushcontext session.ctx
## attempt failing scenario
dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none
tpm2 startauthsession --policy-session -S session.ctx -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 policycommandcode -S session.ctx TPM2_CC_Duplicate
tpm2 policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
trap - ERR
tpm2 duplicate -C new_parent.ctx -c duplicable_key.ctx -G aes \
-i sym_key_in.bin -r dupprv.bin -s dupseed.dat -p "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2 duplicate must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx

# Test tpm2 import
create_authorized_policy
tpm2 createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2 create -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
-u new_parent.pub -c new_parent.ctx -L authorized.policy \
-a "restricted|sensitivedataorigin|decrypt|userwithauth"
tpm2 startauthsession -S session.ctx
tpm2 policycommandcode -S session.ctx -L dpolicy.dat TPM2_CC_Duplicate
tpm2 flushcontext session.ctx
tpm2 create -C primary.ctx -g sha256 -G rsa -p foo -r dupkey.prv -u dupkey.pub \
-L dpolicy.dat -a "sensitivedataorigin|decrypt|userwithauth" -c dupkey.ctx
tpm2 startauthsession --policy-session -S session.ctx
tpm2 policycommandcode -S session.ctx TPM2_CC_Duplicate
tpm2 duplicate -C new_parent.ctx -c dupkey.ctx -G null -p "session:session.ctx" \
-r duplicated.prv -s dup.seed
tpm2 flushcontext session.ctx
tpm2 import -C new_parent.ctx -u dupkey.pub -i duplicated.prv -r imported_dup.prv \
-s dup.seed --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 import -C new_parent.ctx -u dupkey.pub -i duplicated.prv -r imported_dup.prv \
-s dup.seed -P "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 rsadecrypt
create_authorized_policy
tpm2 createprimary -C o -c prim.ctx
tpm2 create -C prim.ctx -c key.ctx -u key.pub -r key.priv -L authorized.policy \
-G rsa
echo "plaintext" > plain.txt
tpm2 rsaencrypt -c key.ctx -o enc.out plain.txt
tpm2 rsadecrypt -c key.ctx -s rsaes enc.out --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 rsadecrypt -c key.ctx -s rsaes enc.out -o dec.out -p "session:session.ctx"
tpm2 flushcontext session.ctx
# Attempt failing case
dd if=/dev/urandom of=rand.om bs=1 count=256 status=none
setup_authorized_policycphash
trap - ERR
tpm2 rsadecrypt -c key.ctx -s rsaes rand.om -o dec.out -p "session:session.ctx"
if [ $? == 0 ];then
  echo "ERROR: tpm2 rsadecrypt must fail!"
  exit 1
fi
trap onerror ERR
tpm2 flushcontext session.ctx

# Test tpm2 certify
create_authorized_policy
tpm2 createprimary -C o -G rsa -g sha256 -c prim.ctx -p primarypass
tpm2 create -C prim.ctx -c key.ctx -G rsa  -u key.pub -r key.priv \
-L authorized.policy -P primarypass
tpm2 certify -c prim.ctx -C key.ctx -g sha256 --cphash cp.hash
tpm2 startauthsession -S session.ctx -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 policycommandcode -S session.ctx -L policy.cphash TPM2_CC_Certify
tpm2 flushcontext session.ctx
sign_and_verify_policycphash
tpm2 startauthsession --policy-session -S session.ctx -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 policycommandcode -S session.ctx TPM2_CC_Certify
tpm2 policyauthorize -S session.ctx -i policy.cphash -n signing_key.name \
-t verification.tkt
tpm2 certify -c prim.ctx -C key.ctx -g sha256 -o attest.out -s sig.out \
-p "session:session.ctx" -P primarypass
tpm2 flushcontext session.ctx

# Test tpm2 certifycreation
create_authorized_policy
tpm2 createprimary -C o -c prim.ctx --creation-data create.dat \
-d create.dig -t create.ticket
tpm2 create -G rsa -u rsa.pub -r rsa.priv -C prim.ctx -c signingkey.ctx \
-L authorized.policy
tpm2 certifycreation -C signingkey.ctx -c prim.ctx -d create.dig \
-t create.ticket -g sha256 -f plain -s rsassa --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 certifycreation -C signingkey.ctx -c prim.ctx -d create.dig \
-t create.ticket -g sha256 -o sig.nature --attestation attestat.ion -f plain \
-s rsassa -P "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 quote
create_authorized_policy
tpm2 createprimary -C e -c primary.ctx
tpm2 create -C primary.ctx -u key.pub -r key.priv -c key.ctx \
-L authorized.policy
tpm2 quote -Q -c key.ctx -l 0x0004:16,17,18+0x000b:16,17,18 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 quote -Q -c key.ctx -l 0x0004:16,17,18+0x000b:16,17,18 \
-p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 gettime
create_authorized_policy
tpm2 createprimary -C e -c primary.ctx
tpm2 create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx \
-c rsa.ctx -L authorized.policy
tpm2 gettime -c rsa.ctx -q "cafebabe" --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 gettime -c rsa.ctx -q "cafebabe" -o attest.sig --attestation attest.data \
-p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 sign
create_authorized_policy
tpm2 createprimary -C e -c primary.ctx
tpm2 create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx -c rsa.ctx \
-L authorized.policy
echo "my message" > message.dat
tpm2 sign -c rsa.ctx -g sha256 message.dat --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 sign -c rsa.ctx -g sha256 message.dat -o signature.dat \
-p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 createprimary
tpm2 clear
tpm2 createprimary -C o -q "cafebabe" --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 createprimary -C o -q "cafebabe" -P "session:session.ctx" -c prim.ctx
tpm2 flushcontext session.ctx

# Test tpm2 hierarchycontrol
tpm2 clear
tpm2 hierarchycontrol -C p shEnable clear --cphash cp.hash
generate_policycphash
tpm2 setprimarypolicy -C p -L policy.cphash -g sha256
tpm2 startauthsession -S session.ctx --policy-session -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 hierarchycontrol -C p shEnable clear -P "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 setprimarypolicy
tpm2 startauthsession -S session.ctx
tpm2 policyauthvalue -S session.ctx -L policy.authvalue
tpm2 flushcontext session.ctx
create_authorized_policy
tpm2 setprimarypolicy -C o -L authorized.policy -g sha256
tpm2 setprimarypolicy -C o -L policy.authvalue -g sha256 --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 setprimarypolicy -C o -L policy.authvalue -g sha256 -P "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 clear
tpm2 clear
tpm2 clear -c l --cphash cp.hash
generate_policycphash
tpm2 setprimarypolicy -C l -L policy.cphash -g sha256
tpm2 startauthsession -S session.ctx --policy-session -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 clear -c l "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 clearcontrol
tpm2 clear
tpm2 clearcontrol -C l s --cphash cp.hash
generate_policycphash
tpm2 setprimarypolicy -C l -L policy.cphash -g sha256
tpm2 startauthsession -S session.ctx --policy-session -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 clearcontrol -C l s -P "session:session.ctx"
tpm2 flushcontext session.ctx

# Test tpm2 dictionarylockout
tpm2 clearcontrol -C p c
tpm2 clear
tpm2 dictionarylockout -s -n 5 -t 6 -l 7 --cphash cp.hash
generate_policycphash
tpm2 setprimarypolicy -C l -L policy.cphash -g sha256
tpm2 startauthsession -S session.ctx --policy-session -g sha256
tpm2 policycphash -S session.ctx --cphash-input cp.hash
tpm2 dictionarylockout -s -n 5 -t 6 -l 7 --cphash cp.hash -p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test evictcontrol
tpm2 clear
tpm2 createprimary -C o -c prim.ctx
tpm2 evictcontrol -C o -c prim.ctx 0x81010001 --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 evictcontrol -C o -c prim.ctx 0x81010001 -P "session:session.ctx"
tpm2 flushcontext session.ctx

# Test clockset
tpm2 clear
let clockset=`tpm2 readclock | grep clock | grep -v info | awk '{print $2}'`+100000
tpm2 setclock -c o $clockset --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 setclock -c o $clockset -p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test clockrateadjust
tpm2 clear
tpm2 clockrateadjust s --cphash cp.hash
generate_policycphash
setup_owner_policy
tpm2 clockrateadjust s -p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test nvwrite
 create_authorized_policy
 tpm2 nvdefine 1 -s 8 -a "ownerread|authwrite|policywrite" -L authorized.policy
 echo "foo" | tpm2 nvwrite 1 -i- --cphash cp.hash
 xxd -p cp.hash
 generate_policycphash
 sign_and_verify_policycphash
 setup_authorized_policycphash
 echo "foo" | tpm2 nvwrite 1 -i- -P "session:session.ctx"
 tpm2 flushcontext session.ctx

 # Test encryptdecrypt
create_authorized_policy
tpm2 createprimary -Q -C e -g sha1 -G rsa -c primary.ctx
tpm2 create -Q -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx \
-c decrypt.ctx -L authorized.policy

dd if=/dev/urandom of=iv.dat bs=16 count=1
echo "plaintext" > secret.dat
cat secret.dat | tpm2 encryptdecrypt -c decrypt.ctx --iv iv.dat --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
echo "plaintext" | tpm2 encryptdecrypt -c decrypt.ctx --iv iv.dat:iv2.dat \
-p "session:session.ctx" > secret2.dat

# Test tpm2 hmac
create_authorized_policy
tpm2 createprimary -Q -C o -c prim.ctx
tpm2 create -Q -C prim.ctx -c key.ctx -u key.pub -r key.priv -G hmac \
-L authorized.policy
echo "testdata" > plain.txt
tpm2 hmac -c key.ctx plain.txt --cphash cp.hash
generate_policycphash
sign_and_verify_policycphash
setup_authorized_policycphash
tpm2 hmac -c key.ctx plain.txt -o hmac.bin -p "session:session.ctx"
tpm2 flushcontext session.ctx

# Test if specifying the <halg>: in the cphash path has effect on cphash alg
TPM2_ALG_SHA256_SZ=34
TPM2_ALG_SHA1_SZ=22

## Default must be sha256
expected_hash_len=$TPM2_ALG_SHA256_SZ
tpm2 getrandom 8 --cphash cp.hash
file_size=`ls -l cp.hash | awk {'print $5'}`
test $file_size -eq $expected_hash_len

## Check if a specific hash can be enforced with <halg>:
expected_hash_len=$TPM2_ALG_SHA1_SZ
tpm2 getrandom 8 --cphash sha1:cp.hash
file_size=`ls -l cp.hash | awk {'print $5'}`
test $file_size -eq $expected_hash_len

exit 0
