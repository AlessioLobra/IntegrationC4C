service SamlConverterService @(path:{ value:'/saml-converter' }) {

  action GenerateAndExchange(
    email         : String,  // opzionale: se assente, usa SAML_SUBJECT_EMAIL env
    @optional issuer        : String,  // opzionale: default da XSUAA xsappname o env
    @optional audience      : String,  // opzionale: default da XSUAA url
    @optional tokenEndpoint : String,  // opzionale: default da XSUAA tokenurl
    @optional clientId      : String,  // opzionale: default da XSUAA clientid
    @optional clientSecret  : String   // opzionale: default da XSUAA clientsecret
  ) returns {
    assertionXml  : String;
    access_token  : String;
    token_type    : String;
    expires_in    : Integer;
    exipres       : Integer;
  };

}
