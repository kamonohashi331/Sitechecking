#!/bin/bash

# Generate self-signed SSL certificate for development

echo "Generating self-signed SSL certificate..."

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 -nodes \
    -out certs/cert.pem \
    -keyout certs/key.pem \
    -days 365 \
    -subj "/C=FR/ST=State/L=City/O=Development/CN=api.hosting.austerfortia.fr"

echo "✓ SSL certificate generated successfully!"
echo ""
echo "Certificate: server/certs/cert.pem"
echo "Private Key: server/certs/key.pem"
echo ""
echo "Note: This is a self-signed certificate for development only."
echo "Browsers will show a security warning - this is normal."
