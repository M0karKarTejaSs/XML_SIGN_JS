const fs = require('fs');
const forge = require('node-forge');
const { Application } = require('xmldsigjs');
const { DOMParser, XMLSerializer } = require('xmldom');

// Load .pfx and convert it to PEM
const pfxPath = 'tjstjs.pfx'; // Update with the correct file path
const pfxPassword = 'abc1234'; // Update with your password

try {
  const pfx = fs.readFileSync(pfxPath);
  const pfxDer = forge.util.decode64(pfx.toString('base64'));
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const certBag = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, pfxPassword);

  // Get private key
  const bags = certBag.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const bag = bags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  const privateKey = forge.pki.privateKeyToPem(bag.key);

  // Define the XML content without the signature (removed extra indentation)
  const xmlContent = `<Esign AuthMode="1" aspId="mQ3SY2lvVg9qUAauq9ztMACHMZwfDxym" ekycId="" ekycIdType="A" responseSigType="pkcs7"
responseUrl="http://localhost:3000/esignAsp-0.0.1-SNAPSHOT/res/dummy@1@1" sc="Y"
ts="2023-09-09T04:40:11.830Z" txn="9627e47a-d93a-46fe-9925-ff759ccefa81" ver="2.1"
xmlns="http://www.example.com">
  <Docs>
    <InputHash docInfo="Test" hashAlgorithm="SHA256" id="1">
      3df79d34abbca99308e79cb94461c1893582604d68329a41fd4bec1885e6adb4
    </InputHash>
  </Docs>
</Esign>`;

  // Load the XML content
  const doc = new DOMParser().parseFromString(xmlContent, 'application/xml');

  // Create an instance of xmldsigjs
  const signer = new Application();

  // Load the XML document
  signer.LoadXml(doc);

  // Create a reference to the <Docs> element
  const ref = signer.CreateReference('');
  ref.DigestMethod.Algorithm = 'http://www.w3.org/2001/04/xmlenc#sha256';

  // Add the reference to the signed info
  signer.AddReference(ref);

  // Sign the document
  signer.SigningKey = privateKey;
  signer.ComputeSignature();

  // Get the signed XML as a string
  const signedXml = signer.GetXml();

  // Log the signed XML
  console.log(new XMLSerializer().serializeToString(signedXml));
} catch (error) {
  console.error('Error:', error);
}
