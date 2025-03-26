"use strict";

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

const PBKDF2_ITERATIONS = 100000;
const PASSWORD_VERIFICATION_DUMMY_TEXT = "password_verification_test";

class Keychain {
  constructor(domainKey, encryptionKey, kvs, salt, passwordVerificationData) {
    this.data = {
 
    };
    this.secrets = {
      domainKey: domainKey,
      encryptionKey: encryptionKey,
      kvs: kvs,
      salt: salt,
      passwordVerificationData: passwordVerificationData
    };
  };

  static async init(password) {
    if (typeof password !== 'string') {
      throw new Error("Password must be a string");
    }

    const salt = await getRandomBytes(16);
    const keyMaterial = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    const domainKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("domain_key"));
    const domainKey = await subtle.importKey("raw", domainKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

    const encryptionKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("encryption_key"));
    const encryptionKey = await subtle.importKey("raw", encryptionKeyMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);

    const verificationIv = await getRandomBytes(12);
    const encryptedVerificationValueBuffer = await subtle.encrypt(
        { name: "AES-GCM", iv: verificationIv },
        encryptionKey,
        stringToBuffer(PASSWORD_VERIFICATION_DUMMY_TEXT)
    );
    const passwordVerificationData = encodeBuffer(verificationIv) + "." + encodeBuffer(encryptedVerificationValueBuffer);


    return new Keychain(domainKey, encryptionKey, {}, encodeBuffer(salt), passwordVerificationData);
  }


  static async load(password, repr, trustedDataCheck) {
    if (typeof password !== 'string') {
      throw new Error("Password must be a string");
    }
    if (typeof repr !== 'string') {
      throw new Error("Representation must be a string");
    }
    if (trustedDataCheck !== undefined && typeof trustedDataCheck !== 'string') {
      throw new Error("trustedDataCheck must be a string or undefined");
    }

    try {
      const data = JSON.parse(repr);
      if (!data.kvs || !data.salt || !data.passwordVerificationData) {
        throw new Error("Invalid keychain format: missing kvs, salt, or passwordVerificationData");
      }
      const saltBuffer = decodeBuffer(data.salt);
      const keyMaterial = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
      const masterKey = await subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: saltBuffer,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      );

      const domainKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("domain_key"));
      const domainKey = await subtle.importKey("raw", domainKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

      const encryptionKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("encryption_key"));
      const encryptionKey = await subtle.importKey("raw", encryptionKeyMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);


      if (trustedDataCheck !== undefined) {
        const calculatedChecksumBuffer = await subtle.digest("SHA-256", stringToBuffer(repr));
        const calculatedChecksum = encodeBuffer(calculatedChecksumBuffer);
        if (calculatedChecksum !== trustedDataCheck) {
          throw new Error("Checksum verification failed: database may be corrupted or tampered with.");
        }
      }

      const [verificationIvBase64, encryptedVerificationValueBase64] = data.passwordVerificationData.split('.');
      if (!verificationIvBase64 || !encryptedVerificationValueBase64) {
          throw new Error("Invalid password verification data format");
      }
      const verificationIv = decodeBuffer(verificationIvBase64);
      const encryptedVerificationValueBuffer = decodeBuffer(encryptedVerificationValueBase64);

      try {
          const decryptedVerificationValueBuffer = await subtle.decrypt(
              { name: "AES-GCM", iv: verificationIv },
              encryptionKey,
              encryptedVerificationValueBuffer
          );
          const decryptedVerificationText = bufferToString(decryptedVerificationValueBuffer);
          if (decryptedVerificationText !== PASSWORD_VERIFICATION_DUMMY_TEXT) {
              throw new Error("Incorrect password or invalid keychain data."); 
          }
      } catch (e) {
          throw new Error("Incorrect password or invalid keychain data."); 
      }


      return new Keychain(domainKey, encryptionKey, data.kvs, data.salt, data.passwordVerificationData);


    } catch (e) {
      if (e.message === "Checksum verification failed: database may be corrupted or tampered with." || e.message === "Invalid keychain format: missing kvs, salt, or passwordVerificationData" || e.message === "Invalid password verification data format") {
        throw e; 
      }
       else {
        throw new Error("Incorrect password or invalid keychain data."); 
      }
    }
  };

  async dump() {
    const dataToSerialize = {
        kvs: this.secrets.kvs,
        salt: this.secrets.salt,
        passwordVerificationData: this.secrets.passwordVerificationData 
    };
    const representation = JSON.stringify(dataToSerialize);
    const checksumBuffer = await subtle.digest("SHA-256", stringToBuffer(representation));
    const checksum = encodeBuffer(checksumBuffer);
    return [representation, checksum];
  };

  async get(name) {
    if (typeof name !== 'string') {
      throw new Error("Domain name must be a string");
    }

    const domainHashBuffer = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.domainKey, stringToBuffer(name));
    const domainHash = encodeBuffer(domainHashBuffer);
    const authData = this.secrets.kvs[domainHash];
    if (!authData) {
      return null;
    }

    const [ivBase64, encryptedValueBase64] = authData.split('.');
    if (!ivBase64 || !encryptedValueBase64) {
      throw new Error("Invalid auth data format"); 
    }

    const iv = decodeBuffer(ivBase64);
    const encryptedValueBuffer = decodeBuffer(encryptedValueBase64);

    try {
      const decryptedValueBuffer = await subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.encryptionKey,
        encryptedValueBuffer
      );
      return bufferToString(decryptedValueBuffer);
    } catch (e) {

      console.error("Decryption error:", e);
      return null; 
    }
  };

  async set(name, value) {
    if (typeof name !== 'string') {
      throw new Error("Domain name must be a string");
    }
    if (typeof value !== 'string') {
      throw new Error("Password value must be a string");
    }

    const domainHashBuffer = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.domainKey, stringToBuffer(name));
    const domainHash = encodeBuffer(domainHashBuffer);
    const encodedValueBuffer = stringToBuffer(value);
    const iv = await getRandomBytes(12); 
    const encryptedValueBuffer = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.encryptionKey,
      encodedValueBuffer
    );
    const authData = encodeBuffer(iv) + "." + encodeBuffer(encryptedValueBuffer); 
    this.secrets.kvs[domainHash] = authData;
  };


  async remove(name) {
    if (typeof name !== 'string') {
      throw new Error("Domain name must be a string");
    }

    const domainHashBuffer = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.domainKey, stringToBuffer(name));
    const domainHash = encodeBuffer(domainHashBuffer);
    if (this.secrets.kvs[domainHash]) {
      delete this.secrets.kvs[domainHash];
      return true;
    } else {
      return false;
    }
  };
};

module.exports = { Keychain }