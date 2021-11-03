const bip39 = require('./index');
const wordlist = require('./wordlist/english');

describe('My BIP39 implementation', () => {

    var initialEntropy;
    var sha256Hash;
    var checksummedEntropy;
    var mnemonicIndices;
    var mnemonicPhrase;

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

    it('should append the checksum', () => {
        let checksum = sha256Hash[0];
        expect(checksum.length).toEqual(8);

        checksummedEntropy = initialEntropy.concat([initialEntropy, checksum]);
        expect(checksummedEntropy.length).toEqual(33);
    });

    it('should generate mnemonic indices from checksummed entropy', () => {
        mnemonicIndices = bip39.generateMnemonicIndices(checksummedEntropy);
        expect(mnemonicIndices.length).toEqual(11);
        for (i=0; i<11; i++) {
            let currentIndex = mnemonicIndices[i];
            expect(Number.isInteger(currentIndex)).toBeTruthy();
            expect(currentIndex).toBeLessThanOrEqual(2047);
            expect(currentIndex).toBeGreaterThanOrEqual(0);
        }
    });

    it('should generate a mnemonic phrase from indices', () => {
        mnemonicPhrase = bip39.generateMnemonic(wordlist, mnemonicIndices);
        expect(Array.isArray(mnemonicPhrase)).toBeTruthy();
        for (i=0; i<24; i++) {
            let currentWord = mnemonicPhrase[i];
            expect(currentWord instanceof String).toBeTruthy();
            expect(currentWord.length).toBeLessThanOrEqual(8)
            expect(currentWord.length).toBeGreaterThanOrEqual(3);
        }
    });

    it('should convert the mnemonic to a 512-bit seed', () => {
        let seed = bip39.convertMnemonicToSeed(mnemonicPhrase);
        expect(Buffer.isBuffer(seed)).toBeTruthy();
        expect(seed.length).toEqual(64);
    });
});