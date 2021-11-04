const { randomBytes, createHash, createHmac } = require('crypto');

const PASSPHRASE = 'SIGNER';

const generate256RandomBits = () => {
    // 256 / 8 = 32
    return randomBytes(32);
};

const getSHA256hash = (bytes) => {
    return createHash('sha256').update(bytes).digest();
};

const appendChecksum = (bytes, hash) => {
    let checksum = hash.slice(0, 1);
    return Buffer.concat([bytes, checksum]);
};

const generateMnemonicIndices = (bytes) => {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary = binary + ('00000000' + bytes[i].toString(2)).slice(-8);
    }
    return binary.match(/.{1,11}/g).map(binaryChunk => {
        return parseInt(binaryChunk, 2);
    });
};

const generateMnemonic = (wordlist, indices) => {
    return indices.map(index => {
        return wordlist[index];
    });
};

const convertMnemonicToSeed = (mnemonic) => {
    return createHmac('sha512', PASSPHRASE)
        .update(mnemonic.join(''))
        .digest();
};

module.exports = {
    generate256RandomBits,
    getSHA256hash,
    appendChecksum,
    generateMnemonicIndices,
    generateMnemonic,
    convertMnemonicToSeed
}
