// Main function to execute the flow
(async function main() {

    // Generate symmetric private key (AES-GCM)
    var symKey = await generatePrivateKey();

    // Export for sending over network
    const jwkSymKey = await crypto.subtle.exportKey("jwk", symKey);

    // Fetch server's public key
    const publicJWTKey = await fetchPublicKey();

    // Import the server's public key
    const publicCryptoKey = await crypto.subtle.importKey(
        "jwk",                          // JWK format
        publicJWTKey,                   // The actual public key
        {
            name: "RSA-OAEP",           // Encryption algorimth
            hash: { name: "SHA-256" },  // Hashing algorithm
        },
        true,                           // Extractable
        ["encrypt"]                     // Public (only for encryption)
    );

    // Encrypt the symmetric key and send to server
    const privateKey = jwkSymKey.k;
    const encryptedPrivateKey = await encryptRSA(publicCryptoKey, privateKey);

    // Fetch encrypted content from server
    const encryptedContent = await fetchEncryptedContent(encryptedPrivateKey);

    // Using the symmetric key, decrypt the message from the server
    var decryptedMessage = await decrypt(encryptedContent.v, encryptedContent.n, symKey, encryptedContent.t);

    // Hooray!
    document.getElementById('content-server').innerHTML = decryptedMessage;

    // Send some encrypted text to the server
    var encContent = await encryptAES('You killed my father. Prepare to die!', symKey);
    var deContent = await sendEncryptedContent(encContent.ciphertext, encContent.nonce);

    // What did the server say we said?
    document.getElementById('content-client').innerHTML = deContent.message;
})();

// Generate a AES-GCM key (256 bits)
async function generatePrivateKey() {
    const key = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );

    return key;
}

// Encrypt the data using RSA
async function encryptRSA(privateKey, plaintext) {
    const encodedData = new TextEncoder().encode(plaintext);
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        privateKey,
        encodedData
    );
    return btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
}

// Encrypt a message using AES-GCM
async function encryptAES(plaintext, key) {
    const encoder = new TextEncoder();

    const nonce = crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce
    const plaintextBytes = encoder.encode(plaintext);

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: nonce,
        },
        key,
        plaintextBytes
    );

    return {
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))), // Base64 encode ciphertext
        nonce: btoa(String.fromCharCode(...nonce)), // Base64 encode nonce
    };
}

// Decrypt the encrypted AES-GCM message
async function decrypt(b64Text, base64Nonce, privateKey, base64Tag) {
    const decoder = new TextDecoder();

    let ciphertext = Uint8Array.from(atob(b64Text), c => c.charCodeAt(0));
    if (base64Tag) {
        const tag = Uint8Array.from(atob(base64Tag), c => c.charCodeAt(0));
        ciphertext = new Uint8Array([...ciphertext, ...tag]);
    }

    const nonce = Uint8Array.from(atob(base64Nonce), c => c.charCodeAt(0));

    const plainText = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: nonce,
        },
        privateKey,
        ciphertext
    );

    return decoder.decode(plainText);
}

// Fetch the public key from the server
async function fetchPublicKey() {
    const response = await fetch("https://localhost:7287/api/crypto/public-key");
    if (!response.ok) throw new Error("Failed to fetch public key");
    return await response.json();
}

// Get encrypted content from server
async function fetchEncryptedContent(encryptedPrivateKey) {
    const data = {
        ciphertext: encryptedPrivateKey
    };
    const body = JSON.stringify(data);
    const response = await fetch("https://localhost:7287/api/crypto/encrypted-data", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', },
        body: body
    });
    return await response.json();
}

// Ask the server to decrypt our encrypted text
async function sendEncryptedContent(ciphertext, nonce) {
    const data = {
        ciphertext: ciphertext,
        nonce: nonce
    };
    const body = JSON.stringify(data);
    const response = await fetch("https://localhost:7287/api/crypto/decrypt-data", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', },
        body: body
    });
    return await response.json();
}