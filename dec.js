const crypto = require('crypto');
const fs = require('fs');

// Load your private key and XML content
const privateKeyPem = fs.readFileSync('UAT_Document_Signer.pem', 'utf8');
const xmlContent = '<content>some content</content>';

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
  '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>\n' +
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

console.log(base64Signature);
