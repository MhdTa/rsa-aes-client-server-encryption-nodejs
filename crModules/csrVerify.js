module.exports = {
    verifiyCSR: (csrPem) => {
      const forge = require("node-forge");
      const fs = require("fs");
  
      const csr = forge.pki.certificationRequestFromPem(csrPem);

      // Read CA cert and key
  
   
      const caKeyPem = fs.readFileSync("privatekey.pem", {
        encoding: "utf-8",
      });
      // const caCert = forge.pki.certificateFromPem(caCertPem);
      const caKey = forge.pki.privateKeyFromPem(caKeyPem);
  
      if (csr.verify()) {
        console.log("Certification request (CSR) verified.");
      } else {
        throw new Error("Signature not verified.");
      }
  
      console.log("Creating certificate...");
      const cert = forge.pki.createCertificate();
      cert.serialNumber = "02";
  
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(
        cert.validity.notBefore.getFullYear() + 1
      );
  
      // subject from CSR
      cert.setSubject(csr.subject.attributes);
      // issuer from CA
      // cert.setIssuer("CA");
  
      cert.setExtensions([
        {
          name: "basicConstraints",
          cA: true,
        },
        {
          name: "keyUsage",
          keyCertSign: true,
          digitalSignature: true,
          nonRepudiation: true,
          keyEncipherment: true,
          dataEncipherment: true,
        },
        {
          name: "subjectAltName",
          altNames: [
            {
              type: 6, // URI
              value: "http://ite.org/",
            },
          ],
        },
      ]);
  
      cert.publicKey = csr.publicKey;
  
      cert.sign(caKey);
      console.log("Certificate created.");
  
      console.log("\nWriting Certificate");

      return forge.pki.certificateToPem(cert);
    },
  };