const crypto = require('crypto');
module.exports = {
  generateCertificate: (privateKey, publicKey) => {

    const attrs = [
      {
        name: "commonName",
        value: "mhd.org",
      },
      {
        name: "countryName",
        value: "SY",
      },
      {
        shortName: "ST",
        value: "SYRIA",
      },
      {
        name: "localityName",
        value: "DAMASCUS",
      },
      {
        name: "organizationName",
        value: "FITE",
      },
      {
        shortName: "OU",
        value: "IT",
      },
    ]
    const forge = require("node-forge");
    const pki = forge.pki;

    const prKey = pki.privateKeyFromPem(privateKey);
    const pubKey = pki.publicKeyFromPem(publicKey);

    // create a new certificate
    const cert = pki.createCertificate();

    // fill the required fields
    cert.publicKey = pubKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );

    // here we set subject and issuer as the same one
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    


    // certificate signing
  
       cert.sign(prKey);
    
    // now convert the Forge certificate to PEM format
    return {
      certificateToPem:  pki.certificateToPem(cert),
      signcert : cert
    }
  },
};