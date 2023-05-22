/* global encodePrivateKey, encodePublicKey */
const extractable = true;

function wrap(text, len) {
  const length = len || 72;
  let result = "";
  for (let i = 0; i < text.length; i += length) {
    result += text.slice(i, i + length);
    result += "\n";
  }
  return result;
}

function rsaPrivateKey(key) {
  return `-----BEGIN RSA PRIVATE KEY-----\n${key}-----END RSA PRIVATE KEY-----`;
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function generateKeyPair(alg, size, name, passphrase) {
  return window.crypto.subtle
    .generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096, // can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-512" }, // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
      },
      extractable,
      ["sign", "verify"]
    )
    .then(key => {
      const privateKey = window.crypto.subtle
        .exportKey("jwk", key.privateKey)
        .then(encodePrivateKey)
        .then(wrap)
        .then(rsaPrivateKey);

      const publicKey = window.crypto.subtle.exportKey("jwk", key.publicKey).then(jwk => encodePublicKey(jwk, name));
      return Promise.all([privateKey, publicKey]);
    });
}

document.addEventListener("DOMContentLoaded", function (event) {
  const btnGenerateKey = document.getElementById('generate');
  btnGenerateKey.addEventListener('click', () => {
    const passphrase = document.getElementById('passphrase').value;
    const keyPair = generateKeyPair("RSASSA-PKCS1-v1_5", 4096, null, passphrase);
    keyPair.then(keys => {
      const privateKey = keys[0];
      const publicKey = keys[1];
      console.log(privateKey);
      console.log(publicKey);
      // Aquí puedes usar las llaves generadas
    }).catch(error => {
      console.error(error);
    });
  });
});

if (!window.crypto || !window.crypto.subtle) {
  alert("Tu navegador no admite la API Web Cryptography");
}
