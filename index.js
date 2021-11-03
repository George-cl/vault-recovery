const { randomBytes, createHash } = require('crypto');

const generate256RandomBits = () => {
    // 256 / 8 = 32
    return randomBytes(32);
};

const getSHA256hash = (bytes) => {
    return createHash('sha256').update(bytes).digest();
};

const appendChecksum = (bytes, hash) => {
    
};

const generateMnemonicIndices = (bytes) => {

};

const generateMnemonic = (wordlist, indices) => {

};

const convertMnemonicToSeed = (mnemonic) => {

};

module.exports = {
    generate256RandomBits,
    getSHA256hash,
    appendChecksum,
    generateMnemonicIndices,
    generateMnemonic,
    convertMnemonicToSeed
}
