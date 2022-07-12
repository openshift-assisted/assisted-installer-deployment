SCRIPT_DIR="$( dirname -- "${BASH_SOURCE[0]}"; )"

# making those actions optional as it's not always available via public internet
set +o errexit

# required in order to handle self-signed repository
curl -k -d op=download -d mimeType=application/x-x509-ca-cer \
    -d submit=Submit https://ca01.pki.prod.int.rdu2.redhat.com:8443/ca/ee/ca/getCAChain \
	| openssl pkcs7 -inform DER -print_certs \
	    -out /etc/pki/ca-trust/source/anchors/Red_Hat_CA_chain.pem

update-ca-trust

pip install -r ${SCRIPT_DIR}/requirements-rht.txt

set -o errexit
