const crypto = require('crypto');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');


const ts = new Date().toISOString();
console.log(ts);

// Load your private key and XML content
const privateKeyPem = fs.readFileSync('UAT_Document_Signer.pem', 'utf8');
const xmlContent = '<content>some content</content>';

// Load your X.509 certificate
const x509CertificatePem = fs.readFileSync('tjscertificate.crt', 'utf8');

// Remove "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" from the certificate
const cleanedX509CertificatePem = x509CertificatePem
  .replace(/-----BEGIN CERTIFICATE-----/g, '')
  .replace(/-----END CERTIFICATE-----/g, '')
  .replace(/\s/g, ''); // Remove all whitespace, including line breaks

// Parse the X.509 certificate to extract issuer name and serial number
const x509IssuerName = 'CN=esign, OU=esign, O=esign, L=India, C=91'; // Extract this from your CRT file
const x509SerialNumber = '56046136974634'; // Extract this from your CRT file

// Create a private key object
const privateKey = crypto.createPrivateKey(privateKeyPem);

// Calculate the message digest (SHA-256 hash) of the XML content
const md = crypto.createHash('sha256');
md.update(xmlContent, 'utf8');
const messageDigest = md.digest();

// Create the SignedInfo element with SHA-256 digest
const signedInfoPrefix = '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n';
const signedInfo =
  signedInfoPrefix +
  '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod>\n' +
  '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"></ds:SignatureMethod>\n' +
  '<ds:Reference URI="">\n' +
  '<ds:Transforms>\n' +
  '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>\n' +
  '<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"></ds:Transform>\n' +
  '</ds:Transforms>\n' +
  `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha256"></ds:DigestMethod>\n` +
  `<ds:DigestValue>${messageDigest.toString('base64')}</ds:DigestValue>\n` +
  '</ds:Reference>\n' +
  '</ds:SignedInfo>';

// Calculate the SHA-256 hash of the SignedInfo element
const md2 = crypto.createHash('sha256');
md2.update(signedInfo, 'utf8');
const signatureDigest = md2.digest();

// Sign the SHA-256 hash of the SignedInfo element with the private key
const signature = crypto.sign('sha256WithRSAEncryption', signatureDigest, {
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
});

// Encode the signature in base64
const base64Signature = signature.toString('base64');

// Create the Signature element
const signatureXml = `
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    ${signedInfo}
  </SignedInfo>
  <SignatureValue>${base64Signature}</SignatureValue>
  <KeyInfo>
    <X509Data>
      <X509Certificate>${cleanedX509CertificatePem}</X509Certificate>
      <X509IssuerSerial>
        <X509IssuerName>${x509IssuerName}</X509IssuerName>
        <X509SerialNumber>${x509SerialNumber}</X509SerialNumber>
      </X509IssuerSerial>
    </X509Data>
  </KeyInfo>
</Signature>`;

// Create the Esign element and embed the Signature
const esignXml = `
<Esign AuthMode="1" aspId="mQ3SY2lvVg9qUAauq9ztMACHMZwfDxym" ekycId="" ekycIdType="A" responseSigType="pkcs7" responseUrl="http://localhost:8080/esignAsp-0.0.1-SNAPSHOT/res/dummy@1@1" sc="Y" ts="2023-09-08T10:25:51" txn="94140c33-074b-4c2e-8e20-a167b17da234" ver="2.1">
  <Docs>
    <InputHash docInfo="Test" hashAlgorithm="SHA256" id="1">620952d725b5c065df94ac55ff34e4a9311b5541a26787e884db93719478a95f</InputHash>
  </Docs>
  ${signatureXml}
</Esign>`;

// Create the final XML document
const finalXml = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>${esignXml}`;

// Save the final XML document to a file or process it as needed
fs.writeFileSync('e.xml', finalXml);

console.log('XML with embedded signature and X.509 certificate saved to signed-esign-xml-with-certificate.xml');
