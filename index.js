const express = require('express');
const crypto = require('crypto');
const app = express();
const  http = require('http').Server(app);
const io = require('socket.io')(http);
var fs = require('fs');
const rsaWrapper = require('./components/rsa-wrapper');
const aesWrapper = require('./components/aes-wrapper');
const csrGenerator = require("./crModules/csrGenerate");
const certificatesVerifier = require("./crModules/csrVerify");
const generatecr = require("./crModules/generatecr");

rsaWrapper.initLoadServerKeys(__dirname);
rsaWrapper.serverExampleEncrypt();
var crServer,crClient;

// middleware for static processing
app.use(express.static(__dirname + '/static'));
app.use('/', (req, res, next) => {
    res.send('Hello from SSL server')
  })

var newData = {
    "data":"" ,
    "type":""
};
var sessionKey;

// web socket connection event
io.on('connection', function(socket){

   //on connect
 
    // Test sending to client dummy RSA message
    let encrypted = rsaWrapper.encrypt(rsaWrapper.clientPub, 'Hello RSA message from client to server');
    socket.emit('rsa server encrypted message', encrypted);

    //get Decrypted with AES from client
    socket.on('get action from client with AES', function (data) {
        console.log('Encrypted fileName with AES:');
        console.log(data.fileName);
       var fileName = aesWrapper.decrypt(aesKey, data.fileName);
       console.log('Decrypted fileName with AES:');
       console.log(fileName);

       console.log('Encrypted action with AES:');
        console.log(data.action);
       var action = aesWrapper.decrypt(aesKey, data.action);
       console.log('Decrypted actiom with AES:');
       console.log(action);

       console.log('Encrypted newText with AES:');
        console.log(data.newText);
       var newText = aesWrapper.decrypt(aesKey, data.newText);
       console.log('Decrypted NewText with AES:');
       console.log(newText);


        if (fs.existsSync("static/text/"+fileName+".json"))   { 
        fs.readFile("static/text/"+fileName+".json", 'utf8', function (err, data) {
            if (err) {
              console.log(err)
          } else {
               file = JSON.parse(data);
         
              newData.type = "old";
               if(action=="edit"){
                newData.type = "edit";
                   file.txt = newText;
                    const json = JSON.stringify(file);
                fs.writeFile("static/text/"+fileName+".json", json, 'utf8', function(err){
                  if(err){ 
                        console.log(err); 
                  } else {
                  }});
               }
               //newData.data = file.txt;
                newData.data = aesWrapper.createAesMessage(aesKey,  file.txt);
                newData.type = aesWrapper.createAesMessage(aesKey,  newData.type);
               socket.emit('send AES text to client', newData);
              
          }
          });
        }
        else{
            var newText = newText;
        file = {"txt":newText};
        const json = JSON.stringify(file);
        fs.writeFile("static/text/"+fileName+".json", json, 'utf8', function(err){
            if(err){ 
                  console.log(err); 
            } else {
            }});
            //newData.data = file.txt;
            //newData.type = "new";
            newData.data = aesWrapper.createAesMessage(aesKey,  file.txt);
            newData.type = aesWrapper.createAesMessage(aesKey,"new");
            socket.emit('send AES text to client', newData);
        }
    });



   





    //////////////////////////////////////////////////////////////////////////////////////////

//get Decrypted with RSA from client
socket.on('get action from client with RSA', function (data) {
    sessionKey = rsaWrapper.serverPrivate;
    console.log('Encrypted fileName with RSA:');
    console.log(data.fileName);
   var fileName = rsaWrapper.decrypt(sessionKey, data.fileName);
   console.log('Decrypted fileName with RSA:');
   console.log(fileName);

   console.log('Encrypted action with RSA:');
    console.log(data.action);
   var action = rsaWrapper.decrypt(sessionKey, data.action);
   console.log('Decrypted actiom with RSA:');
   console.log(action);

   console.log('Encrypted newText with RSA:');
    console.log(data.newText);
   var newText = rsaWrapper.decrypt(sessionKey, data.newText);
   console.log('Decrypted NewText with RSA:');
   console.log(newText);


   sessionKey = rsaWrapper.clientPub;


    if (fs.existsSync("static/text/"+fileName+".json"))   { 
    fs.readFile("static/text/"+fileName+".json", 'utf8', function (err, data) {
        if (err) {
          console.log(err)
      } else {
           file = JSON.parse(data);
     
          newData.type = "old";
           if(action=="edit"){
            newData.type = "edit";
               file.txt = newText;
                const json = JSON.stringify(file);
            fs.writeFile("static/text/"+fileName+".json", json, 'utf8', function(err){
              if(err){ 
                    console.log(err); 
              } else {
              }});
           }
          
           //newData.data = file.txt;
           


            newData.data = rsaWrapper.encrypt(sessionKey,  file.txt);
            newData.type = rsaWrapper.encrypt(sessionKey,  newData.type);
           socket.emit('send RSA text to client', newData);
          
      }
      });
    }
    else{
       // var newText = newText;
    file = {"txt":newText};
    const json = JSON.stringify(file);
    fs.writeFile("static/text/"+fileName+".json", json, 'utf8', function(err){
        if(err){ 
              console.log(err); 
        } else {
        }});
       
        //newData.data = file.txt;
        //newData.type = "new";

        newData.data = rsaWrapper.encrypt(sessionKey,  file.txt);
        newData.type = rsaWrapper.encrypt(sessionKey,"new");
        socket.emit('send RSA text to client', newData);
    }
});

    /////////////////////////////////////////////////////////////////////////////////////////



    // Test AES key sending
    const aesKey = aesWrapper.generateKey();
    let encryptedAesKey = rsaWrapper.encrypt(rsaWrapper.clientPub, (aesKey.toString('base64')));
    socket.emit('send key from server to client', encryptedAesKey);


    //recive client public key
    socket.on('send public key to server', function (data) {
        fs.readFile("public_clients.json", 'utf8', function (err, data2) {
            if (err) {
              console.log(err)
          } else {
               file = JSON.parse(data2);
         
              file.clients.push({"public":data});
              const json = JSON.stringify(file);
              fs.writeFile("public_clients.json", json, 'utf8', function(err){
                if(err){ 
                      console.log(err); 
                } else {
    // send public key to client
    socket.emit('send public key to client', rsaWrapper.serverPub);
                }});
              
          }
          });
    });

    
      //recive session key from client
  socket.on('session key', function (data) {
      console.log('recive session key');
    sessionKey = rsaWrapper.decrypt(rsaWrapper.serverPrivate, data);
     // sessionKey =data;
    
var signature = crypto.sign("sha256", Buffer.from(verifiableData), {
	key: rsaWrapper.serverPrivate,
	padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
});

var obj = {
    data:verifiableData,
    signature:signature
};

    socket.emit('accepted session key', obj);
//send server certifcate to client
socket.emit('server certifcate', crServer);
});
 

//////////////////////////////////////////////////////////////////////////////////////////////////////
//step 4 signuatre
var verifiableData = "mhd";
var signature = crypto.sign("sha256", Buffer.from(verifiableData), {
	key: rsaWrapper.serverPrivate,
	padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
})
console.log('sign');
console.log(signature.toString("base64"));


const isVerified = crypto.verify(
	"sha256",
	Buffer.from(verifiableData),
	{
		key: rsaWrapper.serverPub,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
	},
	signature
)

// isVerified should be `true` if the signature is valid
console.log("signature verified: ", isVerified)


// get certificate from client to verfiy 
socket.on('get client certifcate', function (data) {

      //verfiy certificate
      if(data.signcert.publicKey ==rsaWrapper.clientPub){
        console.log("client certifcate accepted");
    }
    


  });




// //////////////////////////////////////////////
//step 5
//Request Certificate for server
const createCSR = (privateKey, publicKey,name) => {
    //generateCSR
    const CSR = csrGenerator.generateCSR(privateKey, publicKey);
  
    // verify csr
    const cert = certificatesVerifier.verifiyCSR(CSR);
   
    // Writting CSR  
    fs.writeFileSync(name+".pem", cert, { encoding: "utf-8" });
  };
  
  /////////////////////////////////////////////////////
  //  CA PART
  
  //create csr for server
  createCSR(rsaWrapper.serverPrivate, rsaWrapper.serverPub,"servercsr");



////// generate cr for server
 crServer = generatecr.generateCertificate(rsaWrapper.serverPrivate, rsaWrapper.serverPub);
 // Writing to file
 fs.writeFileSync("servercr.pem", crServer.certificateToPem, {
    encoding: "utf-8",
  });



// get request from client to generate csr
socket.on('csr', function (data) {
  //create csr for client
  createCSR(rsaWrapper.clientPrivate, rsaWrapper.clientPub,"clientcsr");
  ////// generate cr for client
  crClient = generatecr.generateCertificate(rsaWrapper.clientPrivate, rsaWrapper.clientPub);
// Writing to file
fs.writeFileSync("clientcr.pem", crClient.certificateToPem, {
   encoding: "utf-8",
 });
 //send client certifcate to client
socket.emit('client certifcate', crClient);
});


});





http.listen(3000, function(){
    console.log('listening on *:3000');
});
