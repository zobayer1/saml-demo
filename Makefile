CA_KEY_FILE = pki/local/ca.key
CA_CERT_FILE = pki/local/ca.crt
IDP_SAN_FILE = idp/etc/conf/idp.san.conf
IDP_KEY_FILE = idp/etc/tls/idp.key
IDP_CSR_FILE = idp/etc/tls/idp.csr
IDP_CERT_FILE = idp/etc/tls/idp.crt
IDP_METADATA_FILE = idp/static/idp-metadata.xml
IDP_SP1_METADATA_FILE = idp/etc/saml/sp1-metadata.xml
IDP_SP2_METADATA_FILE = idp/etc/saml/sp2-metadata.xml
SP1_SAN_FILE = sp1/etc/conf/sp1.san.conf
SP1_KEY_FILE = sp1/etc/tls/sp1.key
SP1_CSR_FILE = sp1/etc/tls/sp1.csr
SP1_CERT_FILE = sp1/etc/tls/sp1.crt
SP1_METADATA_FILE = sp1/static/sp1-metadata.xml
SP1_IDP_METADATA_FILE = sp1/etc/saml/idp-metadata.xml
SP2_SAN_FILE = sp2/etc/conf/sp2.san.conf
SP2_KEY_FILE = sp2/etc/tls/sp2.key
SP2_CSR_FILE = sp2/etc/tls/sp2.csr
SP2_CERT_FILE = sp2/etc/tls/sp2.crt
SP2_METADATA_FILE = sp2/static/sp2-metadata.xml
SP2_IDP_METADATA_FILE = sp2/etc/saml/idp-metadata.xml

.PHONY: all format ca idp-cert sp1-cert sp2-cert metadata

all: format ca idp-cert sp1-cert sp2-cert metadata

format:
	@find . -name '*.go' -exec sh -c 'gofmt -w "$$1" && golines -m 120 -w "$$1"' _ {} \;
	@echo "Code formatted"

$(CA_KEY_FILE):
	@mkdir -p pki/local
	@openssl genrsa -out $(CA_KEY_FILE) 2048

$(CA_CERT_FILE): $(CA_KEY_FILE)
	@openssl req -x509 -new -nodes -key $(CA_KEY_FILE) -sha256 -days 1024 -out $(CA_CERT_FILE) -subj "/CN=Local SAML Demo CA"
	@echo "CA certificate generated at $(CA_CERT_FILE)"

ca: $(CA_CERT_FILE)

$(IDP_KEY_FILE):
	@mkdir -p idp/etc/tls
	@openssl genrsa -out $(IDP_KEY_FILE) 2048

$(IDP_CERT_FILE): $(CA_CERT_FILE) $(CA_KEY_FILE) $(IDP_KEY_FILE) $(IDP_SAN_FILE)
	@openssl req -new -key $(IDP_KEY_FILE) -out $(IDP_CSR_FILE) -config $(IDP_SAN_FILE)
	@openssl x509 -req -in $(IDP_CSR_FILE) -CA $(CA_CERT_FILE) -CAkey $(CA_KEY_FILE) -CAcreateserial -out $(IDP_CERT_FILE) -days 365 -extfile $(IDP_SAN_FILE) -extensions v3_req
	@echo "IdP certificate generated at $(IDP_CERT_FILE)"

idp-cert: $(IDP_CERT_FILE)

$(SP1_KEY_FILE):
	@mkdir -p sp1/etc/tls
	@openssl genrsa -out $(SP1_KEY_FILE) 2048

$(SP1_CERT_FILE): $(CA_CERT_FILE) $(CA_KEY_FILE) $(SP1_SAN_FILE)
	@openssl req -new -key $(SP1_KEY_FILE) -out $(SP1_CSR_FILE) -config $(SP1_SAN_FILE)
	@openssl x509 -req -in $(SP1_CSR_FILE) -CA $(CA_CERT_FILE) -CAkey $(CA_KEY_FILE) -CAcreateserial -out $(SP1_CERT_FILE) -days 365 -extfile $(SP1_SAN_FILE) -extensions v3_req
	@echo "SP1 certificate generated at $(SP1_CERT_FILE)"

sp1-cert: $(SP1_CERT_FILE)

$(SP2_KEY_FILE):
	@mkdir -p sp2/etc/tls
	@openssl genrsa -out $(SP2_KEY_FILE) 2048

$(SP2_CERT_FILE): $(CA_CERT_FILE) $(CA_KEY_FILE) $(SP2_SAN_FILE)
	@openssl req -new -key $(SP2_KEY_FILE) -out $(SP2_CSR_FILE) -config $(SP2_SAN_FILE)
	@openssl x509 -req -in $(SP2_CSR_FILE) -CA $(CA_CERT_FILE) -CAkey $(CA_KEY_FILE) -CAcreateserial -out $(SP2_CERT_FILE) -days 365 -extfile $(SP2_SAN_FILE) -extensions v3_req
	@echo "SP2 certificate generated at $(SP2_CERT_FILE)"

sp2-cert: $(SP2_CERT_FILE)

$(IDP_METADATA_FILE): cmd/main.go $(IDP_CERT_FILE)
	@mkdir -p idp/static
	@go run cmd/main.go idp
	@echo "IdP metadata generated"

$(SP1_METADATA_FILE): cmd/main.go $(SP1_CERT_FILE)
	@mkdir -p sp1/static
	@go run cmd/main.go sp1
	@echo "SP1 metadata generated"

$(SP2_METADATA_FILE): cmd/main.go $(SP2_CERT_FILE)
	@mkdir -p sp2/static
	@go run cmd/main.go sp2
	@echo "SP2 metadata generated"

$(SP1_IDP_METADATA_FILE): $(IDP_METADATA_FILE)
	@mkdir -p sp1/etc/saml
	@cp $< $@
	@echo "Copied IdP metadata to SP1"

$(SP2_IDP_METADATA_FILE): $(IDP_METADATA_FILE)
	@mkdir -p sp2/etc/saml
	@cp $< $@
	@echo "Copied IdP metadata to SP2"

$(IDP_SP1_METADATA_FILE): $(SP1_METADATA_FILE)
	@mkdir -p idp/etc/saml
	@cp $< $@
	@echo "Copied SP1 metadata to IdP"

$(IDP_SP2_METADATA_FILE): $(SP2_METADATA_FILE)
	@mkdir -p idp/etc/saml
	@cp $< $@
	@echo "Copied SP2 metadata to IdP"

metadata: $(SP1_IDP_METADATA_FILE) $(SP2_IDP_METADATA_FILE) $(IDP_SP1_METADATA_FILE) $(IDP_SP2_METADATA_FILE)
