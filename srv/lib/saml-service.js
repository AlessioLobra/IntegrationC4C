// srv/saml-converter.js
const cds = require('@sap/cds');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const xsenv = require('@sap/xsenv');


// xml-crypto per la firma
const { SignedXml } = require('xml-crypto');


// Utility tempo
function isoNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}
function inMinutesFromNow(mins) {
  return new Date(Date.now() + mins * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}


// Costruzione Assertion SAML 2.0
function buildAssertionXml({ issuer, subjectEmail, audience, recipient }) {
  const id = '_' + crypto.randomUUID().replace(/-/g, '');
  const issueInstant = isoNow();
  const notBefore = new Date(Date.now() - 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const notOnOrAfter = inMinutesFromNow(5);
  const nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';


  return `
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${issueInstant}">
  <saml2:Issuer>${issuer}</saml2:Issuer>
  <saml2:Subject>
    <saml2:NameID Format="${nameIdFormat}">${subjectEmail}</saml2:NameID>
    <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml2:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}"${recipient ? ` Recipient="${recipient}"` : ''}/>
    </saml2:SubjectConfirmation>
  </saml2:Subject>
  <saml2:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
    <saml2:AudienceRestriction>
      <saml2:Audience>${audience}</saml2:Audience>
    </saml2:AudienceRestriction>
  </saml2:Conditions>
  <saml2:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${id}">
    <saml2:AuthnContext>
      <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
    </saml2:AuthnContext>
  </saml2:AuthnStatement>
</saml2:Assertion>
`.trim();
}


// Firma XML-DSIG enveloped su Assertion
function signAssertionXml(xml, keyPem, certPem) {
  const sig = new SignedXml({
    privateKey: keyPem,
    publicCert: certPem,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    idAttribute: 'ID'
  });


  sig.addReference({
    xpath: "//*[local-name(.)='Assertion' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256'
  });


  sig.keyInfoProvider = {
    getKeyInfo() {
      const b64 = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
      return `<X509Data><X509Certificate>${b64}</X509Certificate></X509Data>`;
    }
  };


  sig.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='Issuer']", action: 'after' }
  });


  return sig.getSignedXml();
}


// Lettura binding XSUAA (client, secret, urls)
function readXsuaa() {
  try {
    const services = xsenv.getServices({ uaa: { label: 'xsuaa' } });
    return services.uaa; // { clientid, clientsecret, url, tokenurl, ... }
  } catch {
    return null;
  }
}


// Lettura certificati da UPS o ENV
function readCerts() {
  // 1) User-Provided Service tag 'certs'
  try {
    const services = xsenv.getServices({ certs: { tag: 'certs' } });
    if (services?.certs) return services.certs; // { cert, key } o { certPath, keyPath }
  } catch (e) {
    // ignora e passa al fallback
  }


  // 2) ENV base64
  const certFromB64 = process.env.CERT_PEM_B64
    ? Buffer.from(process.env.CERT_PEM_B64, 'base64').toString('utf8')
    : null;
  const keyFromB64 = process.env.KEY_PEM_B64
    ? Buffer.from(process.env.KEY_PEM_B64, 'base64').toString('utf8')
    : null;


  // 3) ENV plain text (già PEM)
  const certPlain = process.env.CERT || null;
  const keyPlain = process.env.KEY || null;


  // 4) PATH su filesystem
  const certPath = process.env.CERT_PATH || null;
  const keyPath = process.env.KEY_PATH || null;


  // 5) Ritorna priorizzando: user-provided > base64 > plain > path
  return {
    cert: certFromB64 || certPlain || null,
    key: keyFromB64 || keyPlain || null,
    certPath,
    keyPath
  };
}


// Costruisce config a partire da env + override request
function getConfigFromEnv(req) {
  const xsuaa = readXsuaa();
  const certs = readCerts();


  const email = req.data.email || process.env.SAML_SUBJECT_EMAIL;


  const issuer = req.data.issuer
    || process.env.SAML_ISSUER
    || (xsuaa && xsuaa.xsappname)
    || 'customIDP';


  const audience = req.data.audience
    || process.env.SAML_AUDIENCE
    || (xsuaa && (xsuaa.url || xsuaa.uaa_domain))
    || '';


  const tokenEndpoint = req.data.tokenEndpoint
    || process.env.TOKEN_ENDPOINT
    || (xsuaa && (xsuaa.tokenurl || xsuaa.token_endpoint || (xsuaa.url && xsuaa.url.replace(/\/?$/, '/oauth/token'))));


  const clientId = req.data.clientId
    || process.env.CLIENT_ID
    || (xsuaa && (xsuaa.clientid || xsuaa.client_id));


  const clientSecret = req.data.clientSecret
    || process.env.CLIENT_SECRET
    || (xsuaa && (xsuaa.clientsecret || xsuaa.client_secret));


  // Cert PEM/KEY: preferisci contenuto inline poi path
  let certPem = certs && certs.cert ? certs.cert : null;
  let keyPem = certs && certs.key ? certs.key : null;


  if (!certPem && certs && certs.certPath) certPem = fs.readFileSync(certs.cert, 'utf8');
  if (!keyPem && certs && certs.keyPath) keyPem = fs.readFileSync(certs.key, 'utf8');


  return { email, issuer, audience, tokenEndpoint, clientId, clientSecret, certPem, keyPem };
}


module.exports = cds.service.impl(function () {
  this.on('GenerateAndExchange', async (req) => {
    try {
      const cfg = getConfigFromEnv(req);


      if (!cfg.email) return req.reject(400, 'Missing email (SAML Subject)');
      //if (!cfg.certPem || !cfg.keyPem) return req.reject(500, 'Missing signing certificate/key from environment');
      //if (!cfg.clientId || !cfg.clientSecret || !cfg.tokenEndpoint) return req.reject(500, 'Missing OAuth client or token endpoint from XSUAA binding');


      const recipient = cfg.tokenEndpoint;
      const unsigned = buildAssertionXml({
        issuer: cfg.issuer,
        subjectEmail: cfg.email,
        audience: cfg.audience,
        recipient
      });


      const signedXml = signAssertionXml(unsigned, cfg.keyPem, cfg.certPem);
      const samlAssertionB64 = Buffer.from(signedXml, 'utf8').toString('base64');


      const form = new URLSearchParams();
      form.set('grant_type', 'urn:ietf:params:oauth:grant-type:saml2-bearer');
      form.set('assertion', samlAssertionB64);
      form.set('client_id', cfg.clientId);
      form.set('client_secret', cfg.clientSecret);


      const resp = await axios.post(cfg.tokenEndpoint, form, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 20000,
        validateStatus: (s) => s >= 200 && s < 300
      });


      return {
        assertionXml: signedXml,
        access_token: resp.data.access_token,
        token_type: resp.data.token_type,
        expires_in: resp.data.expires_in
      };
    } catch (err) {
      const isAxios = !!(err && err.isAxiosError);
      const status = isAxios && err.response ? err.response.status : 500;
      const data = isAxios && err.response ? err.response.data : undefined;
      const details = [];


      if (isAxios) {
        details.push({
          code: 'TOKEN_ENDPOINT_ERROR',
          message: `Token endpoint returned status ${status}`,
          target: 'tokenEndpoint'
        });
        if (typeof data === 'object' && data) {
          const msg = data.error_description || data.error || JSON.stringify(data);
          details.push({
            code: 'OAUTH_RESPONSE',
            message: String(msg).slice(0, 500)
          });
        }
      } else if (err && err.message) {
        details.push({
          code: 'LOCAL_PROCESSING_ERROR',
          message: err.message
        });
      }


      if (err && /digestAlgorithm is required/i.test(err.message)) {
        details.push({
          code: 'SIGN_CONFIG',
          message: 'Imposta digestAlgorithm in addReference (http://www.w3.org/2001/04/xmlenc#sha256).'
        });
      }


      return req.reject({
        status,
        code: 'SAML_BEARER_EXCHANGE_FAILED',
        message: 'Scambio SAML Bearer fallito',
        target: 'GenerateAndExchange',
        details
      });
    }
  });
});