
# SAML Single Sign On Workflow Demo

This is a demo project for showcasing SAML SSO workflow written in Go and HTMX.

## Generate Certificates with SANs

**WARNING!!! This is a demo project. The self signed certificates and keys are only to be used in localhost for demo purposes. Never push your certificates and keys into the repositories.**

### Dependencies

Install ca-certificates
```bash
sudo dnf install ca-certificates openssl
```

### One-Time CA Setup (System-wide)

Generate your own Certificate Authority (do this once) for development environment:

```bash
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=Local SAML Demo CA"
```

Files generated from this step:

```text
~/.saml-ca/
├── ca.key          # Keep this secure!
├── ca.crt          # Distribute this to trust store
└── ca.srl          # Serial number file for CA
```

### Trust CA in Browser

Copy CA certificate to system trust:

```bash
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract
```

Restart your browser to pick up the new CA. Manually install the CA certificate in browsers that do not use the system
trust store (e.g, Firefox).

### Host Configuration

Edit /etc/hosts file to add the following:

```text
127.0.0.1 idp.localhost
127.0.0.1 sp1.localhost
127.0.0.1 sp2.localhost
```

**Note**: In a real-world scenario, these hostnames would use actual domain names with proper top-level domains (e.g., `.com`, `.org`) instead of `.localhost`.

### SAN Configuration

For each component (`idp.localhost`, `sp1.localhost`, `sp2.localhost`), create a certificate with **Subject Alternative
Names** (SANs) to avoid browser warnings.

Example SANs for `idp.localhost`:

```text
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = idp.localhost

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
basicConstraints = CA:FALSE

[alt_names]
DNS.1 = idp.localhost
DNS.2 = localhost
IP.1 = 127.0.0.1
```

**Note**: Modify CN and DNS entries for `sp1.localhost` and `sp2.localhost` accordingly.

### Per Service Certificate Generation

Generate certificates for each service signed by the CA. For a production setup, it should be done by a trusted CA.

Example certificate generation for idp:

```bash
# Generate service private key
openssl genrsa -out idp.key 2048

# Create Certificate Signing Request (CSR) with SAN
openssl req -new -key idp.key -out idp.csr -config idp.conf

# Sign with your CA to create final certificate
openssl x509 -req -in idp.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out idp.crt -days 365 -extfile idp.conf -extensions v3_req
```

**Note**: Modify command parameters for sp1, sp2 accordingly.

Files generated from this step:

```text
idp/
├── idp.key         # idp's private key
├── idp.crt         # idp's certificate (signed by CA)
├── idp.csr         # idp's certificate signing request
└── idp.conf        # idp's CSR config

sp1/
├── sp1.key         # sp1's private key
├── sp1.crt         # sp1's certificate (signed by CA)
├── sp1.csr         # sp1's certificate signing request
└── sp1.conf        # sp1's CSR config

sp2/
├── sp2.key         # sp2's private key
├── sp2.crt         # sp2's certificate (signed by CA)
├── sp2.csr         # sp2's certificate signing request
└── sp2.conf        # sp2's CSR config
```

### Verify Certificate Trust

Check if the certificates are trusted

```bash
openssl verify -CAfile ca.crt idp.crt
openssl x509 -in idp.crt -text -noout | grep -A 10 "X509v3"
openssl verify -CAfile ca.crt sp1.crt
openssl x509 -in sp1.crt -text -noout | grep -A 10 "X509v3"
openssl verify -CAfile ca.crt sp2.crt
openssl x509 -in sp2.crt -text -noout | grep -A 10 "X509v3"
```

## SAML Metadata Generation

ToDo

## SAML Authorization Workflow

Detailed SAML SP-Initiated Workflow:

### Phase 1: Initial Access Attempt
- User visits SP1 (https://sp1.localhost:8001/resource)
- SP1 checks session - No valid session exists
- SP1 initiates SAML flow - Redirects to SP1's /login endpoint

### Phase 2: SAML Authentication Request
- SP1 generates AuthnRequest - Creates SAML authentication request XML
- SP1 redirects to IDP - Sends user to https://idp.localhost:8000/sso with the AuthnRequest

### Phase 3: IDP Authentication
- IDP receives AuthnRequest - Validates the request from SP1
- IDP checks user session - If no session, shows login form
- User authenticates - User logs in (or registers if first time) at IDP
- IDP creates SAML Response - Generates signed SAML assertion with user attributes

### Phase 4: Response and Session Creation
- IDP posts to SP1 - Sends SAML Response to SP1's /acs (Assertion Consumer Service)
- SP1 validates response - Verifies signature and extracts user info
- SP1 creates session - Creates local session for the user
- SP1 grants access - Redirects user to originally requested resource

### Phase 5: Accessing Protected Resources
- User accesses protected resource - Now has access to https://sp1.localhost:8001/resource
- Session management - SP1 maintains session for subsequent requests

## Schema Migration

We are using golang-migrate with `sqlite3` plugin to create and manage schema migrations.

Install the `golang-migrate` tool for sqlite3:
```bash
go install -tags 'sqlite3' github.com/golang-migrate/migrate/v4/cmd/migrate@lates
```

### Create a Migration

Create the up and down migration schemas with migrate tool. Example:

```bash
migrate create -ext sql -dir pkg/db/migrations -digits 4 -seq create_table_users
```

### Run Migrations

Run all migrations:

```bash
migrate -path pkg/db/migrations -database "sqlite3://idp.db" up
```

See `golang-migrate` documentations for all available commands.

## IDP Configurations

### Environment Variables

Create a `.env` file to set the required environment variables
```bash
#!/usr/bin/env bash
export SECRET=prettylittlebaby
export SQLITE_DB=idp.db
export TLS_CERT_PATH=etc/idp.crt
export TLS_KEY_PATH=etc/idp.key
```

You can set the variables with

```bash
source .env
```
