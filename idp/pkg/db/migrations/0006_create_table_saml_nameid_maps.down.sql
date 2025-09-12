-- Description: Drop SAML NameID mapping table (rollback for 0005 up migration)
DROP TABLE IF EXISTS saml_nameid_maps;
