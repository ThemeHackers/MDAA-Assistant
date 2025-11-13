export const CryptoHelper = {
    _textEncoder: new TextEncoder(),
    _textDecoder: new TextDecoder(),
    _getPbkdf2Key: async (password, salt) => {
      const baseKey = await crypto.subtle.importKey(
        "raw",
        CryptoHelper._textEncoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
    },
    encrypt: async (data, password) => {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await CryptoHelper._getPbkdf2Key(password, salt);
      const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        CryptoHelper._textEncoder.encode(data)
      );
      return {
        salt: Array.from(salt),
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encryptedContent)),
      };
    },
    decrypt: async (encryptedObject, password) => {
      try {
        const salt = new Uint8Array(encryptedObject.salt);
        const iv = new Uint8Array(encryptedObject.iv);
        const data = new Uint8Array(encryptedObject.data);
        const key = await CryptoHelper._getPbkdf2Key(password, salt);
        const decryptedContent = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          data
        );
        return CryptoHelper._textDecoder.decode(decryptedContent);
      } catch (e) {
        console.error("Decryption failed:", e);
        return null;
      }
    },
  };