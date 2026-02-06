/**
 * Browser-based cryptographic operations for mTLS PKI Portal.
 * Uses WebCrypto API for key generation and node-forge for PKCS#12 bundling.
 */

/**
 * Generate a high-entropy random password.
 * @returns {string} 32-character password
 */
export function generateStrongPassword() {
    // Alphanumeric only to avoid encoding issues with some importers
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const array = new Uint32Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, x => charset[x % charset.length]).join('');
}

/**
 * Generate an RSA-4096 key pair using WebCrypto.
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export async function generateRSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true, // extractable
        ['sign', 'verify']
    );
    return keyPair;
}

/**
 * Generate an ECDSA P-384 key pair using WebCrypto.
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export async function generateECDSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-384',
        },
        true, // extractable
        ['sign', 'verify']
    );
    return keyPair;
}

/**
 * Export a CryptoKey to PEM format.
 * @param {CryptoKey} key - The key to export
 * @param {string} type - 'public' or 'private'
 * @returns {Promise<string>} PEM-encoded key
 */
export async function exportKeyToPEM(key, type) {
    const format = type === 'private' ? 'pkcs8' : 'spki';
    const exported = await crypto.subtle.exportKey(format, key);
    const base64 = arrayBufferToBase64(exported);
    const label = type === 'private' ? 'PRIVATE KEY' : 'PUBLIC KEY';
    return `-----BEGIN ${label}-----\n${formatPEM(base64)}\n-----END ${label}-----`;
}

/**
 * Generate a CSR using node-forge.
 * Note: The subject in this CSR is dummy data - the backend will override it.
 * @param {CryptoKey} privateKey - The private key
 * @param {CryptoKey} publicKey - The public key
 * @returns {Promise<string>} PEM-encoded CSR
 */
export async function generateCSR(privateKey, publicKey) {
    // Export keys to PKCS#8/SPKI format
    const privateKeyPKCS8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    const publicKeySPKI = await crypto.subtle.exportKey('spki', publicKey);

    // Convert to forge format
    const forge = window.forge;
    const forgePrivateKey = forge.pki.privateKeyFromAsn1(
        forge.asn1.fromDer(forge.util.createBuffer(new Uint8Array(privateKeyPKCS8)))
    );
    const forgePublicKey = forge.pki.publicKeyFromAsn1(
        forge.asn1.fromDer(forge.util.createBuffer(new Uint8Array(publicKeySPKI)))
    );

    // Create CSR with dummy subject (backend will override)
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = forgePublicKey;

    // Set dummy subject - backend ignores this entirely
    csr.setSubject([
        { name: 'commonName', value: 'Pending' }
    ]);

    // Sign the CSR
    csr.sign(forgePrivateKey, forge.md.sha256.create());

    // Export to PEM
    return forge.pki.certificationRequestToPem(csr);
}

/**
 * Create a PKCS#12 bundle containing the private key, certificate, and CA chain.
 * @param {CryptoKey} privateKey - The private key
 * @param {string} certificatePEM - PEM-encoded certificate
 * @param {string} chainPEM - PEM-encoded CA chain
 * @param {string} password - Password to encrypt the PKCS#12
 * @param {string} [friendlyName] - Friendly name for the certificate (optional)
 * @returns {Promise<Blob>} PKCS#12 file as Blob
 */
export async function createPKCS12(privateKey, certificatePEM, chainPEM, password, friendlyName) {
    const forge = window.forge;

    // Export private key to PKCS#8
    const privateKeyPKCS8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    const forgePrivateKey = forge.pki.privateKeyFromAsn1(
        forge.asn1.fromDer(forge.util.createBuffer(new Uint8Array(privateKeyPKCS8)))
    );

    // Parse certificate
    const certificate = forge.pki.certificateFromPem(certificatePEM);

    // Parse CA chain
    const chainCerts = [];
    const chainParts = chainPEM.split(/(?=-----BEGIN CERTIFICATE-----)/);
    for (const part of chainParts) {
        if (part.trim()) {
            chainCerts.push(forge.pki.certificateFromPem(part));
        }
    }

    // Create PKCS#12
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
        forgePrivateKey,
        [certificate, ...chainCerts],
        password,
        {
            algorithm: 'aes128', // AES-128 is more modern and commonly supported
            friendlyName: friendlyName || 'mTLS Identity',
        }
    );

    // Convert to DER
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

    // Create Blob
    const p12Array = new Uint8Array(p12Der.length);
    for (let i = 0; i < p12Der.length; i++) {
        p12Array[i] = p12Der.charCodeAt(i);
    }

    return new Blob([p12Array], { type: 'application/x-pkcs12' });
}

/**
 * Download a Blob as a file.
 * @param {Blob} blob - The file content
 * @param {string} filename - The filename
 */
export function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ============================================================================
// Helpers
// ============================================================================

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function formatPEM(base64) {
    const lines = [];
    for (let i = 0; i < base64.length; i += 64) {
        lines.push(base64.substring(i, i + 64));
    }
    return lines.join('\n');
}
