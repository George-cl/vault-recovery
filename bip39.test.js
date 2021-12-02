const bip39 = require('./bip39');
const wordlist = require('./wordlist/english');

const { newMnemonic, recoverFromMnemonic } = require('./index');

describe('BIP39 implementation', () => {

    var initialEntropy,
        sha256Hash,
        checksum,
        checksummedEntropy,
        mnemonicIndices,
        mnemonicPhrase,
        seed;

    it('should randomly generate 256 bits', () => {
        initialEntropy = bip39.generateRandomBits(256);
        expect(Buffer.isBuffer(initialEntropy)).toBeTruthy();
        // 256 bits / 8 bits => 32 bytes
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

    it('should derive (deterministically) ED25519 keypair from phrase', () => {
        let keypair = bip39.keypairFromMnemonic(mnemonicPhrase, 'ed25519');
        let keypair2 = bip39.keypairFromMnemonic(mnemonicPhrase, 'ed25519');

        expect(keypair).toEqual(keypair2);
    });

    it('should derive (deterministically) SECP256k1 keypair from phrase', () => {
        let keypair = bip39.keypairFromMnemonic(mnemonicPhrase, 'secp256k1');
        let keypair2 = bip39.keypairFromMnemonic(mnemonicPhrase, 'secp256k1');

        expect(keypair).toEqual(keypair2);
    });

    it('should recover from mnemonic (ed25519) (Exported Method)', () => {
        let mnemonic = newMnemonic();
        let keypair1 = recoverFromMnemonic(mnemonic, 'ed25519');
        let keypair2 = recoverFromMnemonic(mnemonic, 'ed25519');

        expect(keypair1).toEqual(keypair2);
    });

    it('should recover from mnemonic (secp256k1) (Exported Method)', () => {
        let mnemonic = newMnemonic();
        let keypair1 = recoverFromMnemonic(mnemonic, 'secp256k1');
        let keypair2 = recoverFromMnemonic(mnemonic, 'secp256k1');

        expect(keypair1).toEqual(keypair2);
    });

});
