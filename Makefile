all: ca idp-crt sp1-crt sp2-crt

ca:
	@echo "Generating CA certificate..."
	@openssl genrsa -out pki/local/ca.key 2048
	@openssl req -x509 -new -nodes -key pki/local/ca.key -sha256 -days 1024 -out pki/local/ca.crt -subj "/CN=Local SAML Demo CA"
	@echo "CA certificate generated at pki/local/ca.crt"

idp-crt: ca
	@echo "Generating IdP certificate..."
	@openssl genrsa -out idp/etc/idp.key 2048
	@openssl req -new -key idp/etc/idp.key -out idp/etc/idp.csr -config idp/etc/idp.conf
	@openssl x509 -req -in idp/etc/idp.csr -CA pki/local/ca.crt -CAkey pki/local/ca.key -CAcreateserial -out idp/etc/idp.crt -days 365 -extfile idp/etc/idp.conf -extensions v3_req
	@echo "IdP certificate generated at idp/etc/idp.crt"

sp1-crt: ca
	@echo "Generating SP1 certificate..."
	@openssl genrsa -out sp1/etc/sp1.key 2048
	@openssl req -new -key sp1/etc/sp1.key -out sp1/etc/sp1.csr -config sp1/etc/sp1.conf
	@openssl x509 -req -in sp1/etc/sp1.csr -CA pki/local/ca.crt -CAkey pki/local/ca.key -CAcreateserial -out sp1/etc/sp1.crt -days 365 -extfile sp1/etc/sp1.conf -extensions v3_req
	@echo "SP1 certificate generated at sp1/etc/sp1.crt"

sp2-crt: ca
	@echo "Generating SP2 certificate..."
	@openssl genrsa -out sp2/etc/sp2.key 2048
	@openssl req -new -key sp2/etc/sp2.key -out sp2/etc/sp2.csr -config sp2/etc/sp2.conf
	@openssl x509 -req -in sp2/etc/sp2.csr -CA pki/local/ca.crt -CAkey pki/local/ca.key -CAcreateserial -out sp2/etc/sp2.crt -days 365 -extfile sp2/etc/sp2.conf -extensions v3_req
	@echo "SP2 certificate generated at sp2/etc/sp2.crt"

.PHONY: all ca idp-crt sp1-crt sp2-crt
