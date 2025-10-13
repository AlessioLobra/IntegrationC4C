## Se dovesse cambiare il client secret, aggiungere nell'xs-security.json 

{
  "xsappname": "cap-saml-converter",
  "tenant-mode": "dedicated",
  "description": "Security profile for CAP SAML converter",
  "oauth2-configuration": {
    "credential-types": [
      "binding-secret",
      "x509"
    ]
  }
}