module.exports = {
  generateCSR: (privateKey, publicKey) => {

    const forge = require("node-forge");
    const pki = forge.pki;

     privateKey = pki.privateKeyFromPem(privateKey);
     publicKey = pki.publicKeyFromPem(publicKey);

    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = publicKey;
    csr.setSubject([
      {
        name: "commonName",
        value: "mhd.org",
      },
      {
        name: "countryName",
        value: "SY" ,
      },
      {
        shortName: "ST",
        value: "Virginia",
      },
      {
        name: "localityName",
        value: "none",
      },
      {
        name: "organizationName",
        value: "iITE",
      },
      {
        shortName: "OU",
        value: "Test",
      },
    ]);
    

    // sign certification request
    csr.sign(privateKey);

    // verify certification request
    const verified = csr.verify();

    // convert certification request to PEM-format
    const pem = forge.pki.certificationRequestToPem(csr);

 
    
    return pem;
  },
};