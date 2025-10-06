service SamlConverterService @(path:{ value:'/saml-converter' }) {

  action GenerateAndExchange(
    email         : String,
    certPath      : String,
    keyPath       : String,
    issuer        : String,
    audience      : String,
    clientId      : String,
    clientSecret  : String,
    tokenEndpoint : String
  ) returns {
    assertionXml  : String;
    access_token  : String;
    token_type    : String;
    expires_in    : Integer;
  };

}
