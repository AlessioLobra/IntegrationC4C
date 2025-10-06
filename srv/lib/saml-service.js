// srv/saml-converter.js
const cds = require('@sap/cds');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml, xpath } = require('xml-crypto');

function isoNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}
function inMinutesFromNow(mins) {
  return new Date(Date.now() + mins * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

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
  }); // digestAlgorithm obbligatorio [web:10]

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


module.exports = cds.service.impl(function () {
  this.on('GenerateAndExchange', async (req) => {
    const {
      email,
      certPath,
      keyPath,
      issuer,
      audience,
      clientId,
      clientSecret,
      tokenEndpoint
    } = req.data;

    const certPem = fs.readFileSync(certPath, 'utf8');
    const keyPem = fs.readFileSync(keyPath, 'utf8');

    const recipient = tokenEndpoint; // opzionale: usare ACS/token endpoint previsto dal server OAuth
    const unsigned = buildAssertionXml({
      issuer, subjectEmail: email, audience, recipient
    });

    const signedXml = signAssertionXml(unsigned, keyPem, certPem);

    const samlAssertionB64 = Buffer.from(signedXml, 'utf8').toString('base64');

    const form = new URLSearchParams();
    form.set('grant_type', 'urn:ietf:params:oauth:grant-type:saml2-bearer');
    form.set('assertion', samlAssertionB64);
    form.set('client_id', clientId);
    form.set('client_secret', clientSecret);

    const resp = await axios.post(tokenEndpoint, form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 20000
    });

    return {
      assertionXml: signedXml,
      access_token: resp.data.access_token,
      token_type: resp.data.token_type,
      expires_in: resp.data.expires_in
    };
  });
});
