#!/bin/sh
# Credits to https://github.com/derekparker/delve/blob/master/scripts/gencert.sh

# Check if the certificate is already present in the system keychain
security find-certificate -Z -p -c "org.radare.radare2" /Library/Keychains/System.keychain > /dev/null 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
	# Certificate has already been generated and installed
	exit 0
fi

CERT="org.radare.radare2"

# Create the certificate template
cat <<EOF >$CERT.tmpl
[ req ]
default_bits       = 2048        # RSA key size
encrypt_key        = no          # Protect private key
default_md         = sha512      # MD to use
prompt             = no          # Prompt for DN
distinguished_name = codesign_dn # DN template
[ codesign_dn ]
commonName         = "org.radare.radare2"
[ codesign_reqext ]
keyUsage           = critical,digitalSignature
extendedKeyUsage   = critical,codeSigning
EOF

# Generate a new certificate
openssl req -new -newkey rsa:2048 -x509 -days 3650 -nodes -config $CERT.tmpl -extensions codesign_reqext -batch -out $CERT.cer -keyout $CERT.key > /dev/null 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
	# Something went wrong when generating the certificate
	exit 1
fi

# Install the certificate in the system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT.cer > /dev/null 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
	# Something went wrong when installing the certificate
	exit 1
fi

# Install the key for the certificate in the system keychain
sudo security import $CERT.key -A -k /Library/Keychains/System.keychain > /dev/null 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
	# Something went wrong when installing the key
	exit 1
fi

# Kill task_for_pid access control daemon
sudo pkill -f /usr/libexec/taskgated > /dev/null 2>&1

# Remove generated files
rm $CERT.tmpl $CERT.cer $CERT.key > /dev/null 2>&1

# Exit indicating the certificate is now generated and installed
exit 0
