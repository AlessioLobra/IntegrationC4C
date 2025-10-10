service SamlConverterService @(path:{ value:'/saml-converter' }) {

  action GenerateAndExchange(
    email         : String,
    @optional issuer        : String,
    @optional audience      : String,
    @optional tokenEndpoint : String,
    @optional clientId      : String,
    @optional clientSecret  : String
  ) returns String;

}
