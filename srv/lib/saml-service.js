// srv/saml-converter.js
const cds = require('@sap/cds');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const xsenv = require('@sap/xsenv');
const { SignedXml } = require('xml-crypto');
// XML builder per l’output
const { create } = require('xmlbuilder2');

// Utility tempo
function isoNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}
function inMinutesFromNow(mins) {
  return new Date(Date.now() + mins * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// Costruzione Assertion SAML 2.0 — restituisce anche notOnOrAfter per calcolo epoch
function buildAssertionXml({ issuer, subjectEmail, audience, recipient }) {
  const id = '_' + crypto.randomUUID().replace(/-/g, '');
  const issueInstant = isoNow();
  const notBefore = new Date(Date.now() - 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const notOnOrAfter = inMinutesFromNow(5);
  const nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

  const xml = `
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

  return { xml, id, issueInstant, notBefore, notOnOrAfter };
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
      const b64 = certPem
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
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

// Lettura certificati da UPS o ENV (+ issuer/recipient opzionali)
function readCerts() {
  try {
    const services = xsenv.getServices({ certs: { tag: 'certs' } });
    if (services?.certs) {
      return {
        cert: services.certs.cert || null,
        key: services.certs.key || null,
        certPath: services.certs.certPath || null,
        keyPath: services.certs.keyPath || null,
        issuer: services.certs.issuer || null,
        recipient: services.certs.recipient || null
      };
    }
  } catch (e) {
    // ignore
  }

  const certFromB64 = process.env.CERT_PEM_B64
    ? Buffer.from(process.env.CERT_PEM_B64, 'base64').toString('utf8')
    : null;
  const keyFromB64 = process.env.KEY_PEM_B64
    ? Buffer.from(process.env.KEY_PEM_B64, 'base64').toString('utf8')
    : null;

  const certPlain = process.env.CERT || null;
  const keyPlain = process.env.KEY || null;

  const issuerEnv = process.env.SAML_ISSUER || null;
  const recipientEnv = process.env.RECIPIENT || process.env.TOKEN_ENDPOINT || null;

  const certPath = process.env.CERT_PATH || null;
  const keyPath = process.env.KEY_PATH || null;

  return {
    cert: certFromB64 || certPlain || null,
    key: keyFromB64 || keyPlain || null,
    certPath,
    keyPath,
    issuer: issuerEnv || null,
    recipient: recipientEnv || null
  };
}

// Costruisce config a partire da env + override request
function getConfigFromEnv(req) {
  const xsuaa = readXsuaa();
  const certs = readCerts();

  const email = req.data.email || process.env.SAML_SUBJECT_EMAIL;

  const issuer = req.data.issuer
    || process.env.SAML_ISSUER
    || (certs && certs.issuer)
    || 'customIDP';

  const audience = req.data.audience
    || process.env.SAML_AUDIENCE
    || (xsuaa && (xsuaa.url || xsuaa.uaa_domain))
    || '';

  const tokenEndpoint = req.data.tokenEndpoint
    || process.env.TOKEN_ENDPOINT
    || (certs && certs.recipient);

  const clientId = req.data.clientId
    || process.env.CLIENT_ID
    || (xsuaa && (xsuaa.clientid || xsuaa.client_id));

  const clientSecret = req.data.clientSecret
    || process.env.CLIENT_SECRET
    || (xsuaa && (xsuaa.clientsecret || xsuaa.client_secret));

  let certPem = certs && certs.cert ? certs.cert : null;
  let keyPem = certs && certs.key ? certs.key : null;

  if (!certPem && certs && certs.certPath) certPem = fs.readFileSync(certs.certPath, 'utf8');
  if (!keyPem && certs && certs.keyPath) keyPem = fs.readFileSync(certs.keyPath, 'utf8');

  return { email, issuer, audience, tokenEndpoint, clientId, clientSecret, certPem, keyPem };
}

// Servizio CDS
module.exports = cds.service.impl(function () {
  this.on('GenerateAndExchange', async (req) => {
    try {
      const cfg = getConfigFromEnv(req);

      if (!cfg.email) return req.reject(400, 'Missing email (SAML Subject)');

      const built = buildAssertionXml({
        issuer: cfg.issuer,
        subjectEmail: cfg.email,
        audience: cfg.audience,
        recipient: cfg.tokenEndpoint
      });

      const signedXml = signAssertionXml(built.xml, cfg.keyPem, cfg.certPem);

      // Epoch millis della scadenza SAML (NotOnOrAfter)
      const expires = new Date(built.notOnOrAfter).getTime();

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

      // Costruzione XML di risposta: 
      // <Token xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      //   <Token>
      //     <data>{expires}</data>
      //     <user_name>{email}</user_name>
      //     <Token>Bearer {access_token}</Token>
      //   </Token>
      // </Token>
      const xmlDoc = create({ version: '1.0' })
        .ele('Token', { 'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance' })
          .ele('Token')
            .ele('data').txt(String(expires)).up()
            .ele('user_name').txt(String(cfg.email || '')).up()
            .ele('Token').txt(`Bearer ${resp.data.access_token}`).up()
          .up()
        .up()
        .end({ prettyPrint: false });

      // Imposta Content-Type e invia l’XML
      const res = req.http?.res || req._?.res || req.res; // fallback difensivo
      if (res) {
        res.set('Content-Type', 'application/xml');
        res.send(xmlDoc);
        return; // evita doppie risposte
      }

      // Fallback (se per qualche motivo non c'è res HTTP)
      return xmlDoc;

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
