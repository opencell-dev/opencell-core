#!/bin/bash
# tools/ca/oc-ca: a root, a certificate per role, the refusals; and the
# test PKI the TLS tests use (the ctest fixture "pki"): in OUT,
#   ca.crt                                 the root
#   core.key/.crt                          role core, localhost + 127.0.0.1
#   portal.key/.crt, portal.fpr            role portal (pinned by the tests)
#   other.key/.crt                         role portal, not pinned
#   expired.key/.crt, expired.fpr          role portal, expired in 2025
#   cell.key/.crt, cell.fpr                role cell (clientAuth, wrong role for the API)
#   rogue.key/.crt                         role portal from another root
#   core-client.fpr                        core.crt's fingerprint (serverAuth only)
#   db.key/.crt                            role db, oc-db-1 (serverAuth and clientAuth)
# usage: test_oc_ca.sh OC_CA OUT
set -euo pipefail
OC_CA=$1
OUT=$2
ARC=2.25.39025894690731581968303886031091540846
fails=0
ok() { echo "ok - $*"; }
bad() { echo "FAIL - $*"; fails=$((fails + 1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
refuse() { local what=$1; shift; if "$@" >/dev/null 2>&1; then bad "$what (was accepted)"; else ok "$what"; fi; }

rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"
key_csr() { # NAME [rsa]
    if [ "${2:-}" = rsa ]; then
        openssl req -new -newkey rsa:2048 -nodes -keyout "$1.key" -subj "/CN=$1" -out "$1.csr" 2>/dev/null
    else
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -subj "/CN=$1" \
            -out "$1.csr" 2>/dev/null
    fi
}

check "init makes a root" "$OC_CA" init ca
refuse "init refuses a second root in the same place" "$OC_CA" init ca
check "the root key is the owner's only" test "$(stat -c %a ca/ca.key)" = 600
cp ca/ca.crt ca.crt
check "the root is a CA with room for one intermediate" \
    bash -c "openssl x509 -in ca.crt -noout -text | grep -q 'CA:TRUE, pathlen:1'"

key_csr core
check "a core certificate" "$OC_CA" sign ca core core.csr core.crt localhost --dns localhost --ip 127.0.0.1
check "it chains to the root, for a server" openssl verify -CAfile ca.crt -purpose sslserver core.crt
check "it carries the core role" bash -c "openssl x509 -in core.crt -noout -text | grep -q '$ARC.1.1'"
check "its names" bash -c "openssl x509 -in core.crt -noout -ext subjectAltName | grep -q 'DNS:localhost, IP Address:127.0.0.1'"
check "valid 730 days" bash -c "openssl x509 -in core.crt -noout -checkend $((729 * 86400)) && ! openssl x509 -in core.crt -noout -checkend $((731 * 86400))"
refuse "a core certificate needs a name" "$OC_CA" sign ca core core.csr x.crt localhost

key_csr portal
out=$("$OC_CA" sign ca portal portal.csr portal.crt oc-portal)
check "a portal certificate" test -s portal.crt
check "it chains to the root, for a client" openssl verify -CAfile ca.crt -purpose sslclient portal.crt
refuse "...but not for a server" openssl verify -CAfile ca.crt -purpose sslserver portal.crt
check "it carries the portal role" bash -c "openssl x509 -in portal.crt -noout -text | grep -q '$ARC.1.2'"
check "valid a year" bash -c "openssl x509 -in portal.crt -noout -checkend $((364 * 86400)) && ! openssl x509 -in portal.crt -noout -checkend $((366 * 86400))"
check "its subject is the name given, not the CSR's" bash -c "openssl x509 -in portal.crt -noout -subject | grep -q 'CN=oc-portal'"
fpr=$("$OC_CA" fpr portal.crt)
check "sign prints the fingerprint fpr prints" test "$out" = "fingerprint $fpr"
check "a fingerprint is 64 lowercase hex digits" bash -c "[[ '$fpr' =~ ^[0-9a-f]{64}$ ]]"
echo "$fpr" > portal.fpr
check "a copy is kept under issued/" bash -c "ls ca/issued/portal-oc-portal-*.crt"
refuse "a portal certificate carries no names" "$OC_CA" sign ca portal portal.csr x.crt p --dns x

key_csr other
"$OC_CA" sign ca portal other.csr other.crt oc-portal-2 >/dev/null
# An expired portal certificate from our root (the TLS tests pin it: the
# chain check must refuse it anyway). oc-ca never backdates: openssl here.
key_csr expired
printf '[e]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth\ncertificatePolicies = %s.1.2\n' \
    "$ARC" > expired.ext
check "an expired portal certificate, for the TLS tests" openssl x509 -req -in expired.csr -CA ca/ca.crt -CAkey ca/ca.key \
    -sha256 -not_before 20250101000000Z -not_after 20250102000000Z -extfile expired.ext -extensions e -out expired.crt
"$OC_CA" fpr expired.crt > expired.fpr
key_csr cell
"$OC_CA" sign ca cell cell.csr cell.crt cell-7 >/dev/null
check "a cell certificate carries the cell role" bash -c "openssl x509 -in cell.crt -noout -text | grep -q '$ARC.1.3'"
"$OC_CA" fpr cell.crt > cell.fpr
"$OC_CA" fpr core.crt > core-client.fpr

key_csr db
check "a db certificate" "$OC_CA" sign ca db db.csr db.crt oc-db-1 --dns oc-db-1.wg.opencell.k4ozi.com --ip 10.99.0.4 --ip 10.0.0.62
check "it chains to the root, for a server" openssl verify -CAfile ca.crt -purpose sslserver db.crt
check "...and for a client (etcd peers, replication, pgBackRest)" openssl verify -CAfile ca.crt -purpose sslclient db.crt
check "it carries the db role" bash -c "openssl x509 -in db.crt -noout -text | grep -q '$ARC.1.4'"
check "its names, in order" bash -c "openssl x509 -in db.crt -noout -ext subjectAltName | grep -q 'DNS:oc-db-1.wg.opencell.k4ozi.com, IP Address:10.99.0.4, IP Address:10.0.0.62'"
check "its subject is the host (pg_ident maps the CN)" bash -c "openssl x509 -in db.crt -noout -subject | grep -q 'CN=oc-db-1\$'"
check "valid 730 days" bash -c "openssl x509 -in db.crt -noout -checkend $((729 * 86400)) && ! openssl x509 -in db.crt -noout -checkend $((731 * 86400))"
refuse "a db certificate needs a name" "$OC_CA" sign ca db db.csr x.crt oc-db-1

key_csr rsa rsa
refuse "an RSA key is refused" "$OC_CA" sign ca portal rsa.csr x.crt p
echo "not a csr" > junk.csr
refuse "a file that is not a CSR is refused" "$OC_CA" sign ca portal junk.csr x.crt p
refuse "an unknown role is refused" "$OC_CA" sign ca admin portal.csr x.crt p
refuse "a name with a slash is refused" "$OC_CA" sign ca portal portal.csr x.crt "a/b"

"$OC_CA" init rogue-ca >/dev/null
key_csr rogue
"$OC_CA" sign rogue-ca portal rogue.csr rogue.crt oc-portal >/dev/null
refuse "another root's certificate does not chain to ours" openssl verify -CAfile ca.crt rogue.crt

[ "$fails" -eq 0 ] || { echo "$fails failed"; exit 1; }
echo "all passed"
