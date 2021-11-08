// For Ed25519 key generation
const nacl = require('tweetnacl-ts');
// For Secp256k1 key generation
const secp = require('secp256k1');

const bip39 = require('./bip39');
const wordlist = require('./wordlist/english');

describe('BIP39 implementation', () => {

    var initialEntropy,
        sha256Hash,
        checksum,
        checksummedEntropy,
        mnemonicIndices,
        mnemonicPhrase,
        seed;

    it('should randomly generate 256 bits', () => {
        initialEntropy = bip39.generate256RandomBits();
        expect(Buffer.isBuffer(initialEntropy)).toBeTruthy();
        expect(initialEntropy.length).toEqual(32);
    });

    it('should take the SHA256 hash', () => {
        sha256Hash = bip39.getSHA256hash(initialEntropy);
        expect(Buffer.isBuffer(initialEntropy)).toBeTruthy();
        expect(sha256Hash.length).toEqual(32);
    });

    it('should compute and append the checksum', () => {
        [checksum, checksummedEntropy] = bip39.appendChecksum(initialEntropy, sha256Hash);
        expect(Buffer.isBuffer(checksummedEntropy)).toBeTruthy();
        expect(checksummedEntropy.length).toEqual(33);
    });

    it('should generate mnemonic indices from checksummed entropy', () => {
        mnemonicIndices = bip39.generateMnemonicIndices(checksummedEntropy);
        expect(mnemonicIndices.length).toEqual(24);
        for (i = 0; i < 24; i++) {
            let currentIndex = mnemonicIndices[i];
            expect(Number.isInteger(currentIndex)).toBeTruthy();
            expect(currentIndex).toBeLessThanOrEqual(2047);
            expect(currentIndex).toBeGreaterThanOrEqual(0);
        }
    });

    it('should generate a mnemonic phrase from indices', () => {
        mnemonicPhrase = bip39.generateMnemonic(wordlist, mnemonicIndices);
        expect(Array.isArray(mnemonicPhrase)).toBeTruthy();
        for (i = 0; i < 24; i++) {
            let currentWord = mnemonicPhrase[i];
            expect(typeof currentWord === 'string').toBeTruthy();
            expect(currentWord.length).toBeLessThanOrEqual(8)
            expect(currentWord.length).toBeGreaterThanOrEqual(3);
        }
    });

    it('should convert the mnemonic to a 512-bit seed', () => {
        seed = bip39.convertMnemonicToSeed(mnemonicPhrase);
        expect(Buffer.isBuffer(seed)).toBeTruthy();
        expect(seed.length).toEqual(64);
    });

    it('should produce the same seed for the same mnemonic', () => {
        let newSeed = bip39.convertMnemonicToSeed(mnemonicPhrase);
        expect(newSeed).toEqual(seed);
    });

    it('should derive (deterministically) ED25519 keypair from seed', () => {
        let [from, to] = bip39.calculateSlice(checksum);
        let keypair = nacl.sign_keyPair_fromSeed(seed.slice(from, to));

        [from, to] = bip39.calculateSlice(checksum);
        let keypair2 = nacl.sign_keyPair_fromSeed(seed.slice(from, to));

        expect(keypair).toEqual(keypair2);
    });

    it('should derive (deterministically) SECP256k1 keypair from seed', () => {
        let secretKey;
        let [from, to] = bip39.calculateSlice(checksum);
        secretKey = bip39.hmacSHA512(checksum, seed).slice(from, to);
        if (!secp.privateKeyVerify(secretKey))
            throw new Error('Invalid SECP256k1 key');

        let secretKey2;
        [from, to] = bip39.calculateSlice(checksum);
        secretKey2 = bip39.hmacSHA512(checksum, seed).slice(from, to);
        if (!secp.privateKeyVerify(secretKey2))
            throw new Error('Invalid SECP256k1 key');

        expect(secretKey).toEqual(secretKey2);
    });

});
