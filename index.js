const bip39 = require('./bip39');
const wordlist = require('./wordlist/english');

const newMnemonic = () => {
    let entropy = bip39.generate256RandomBits();
    let hash = bip39.getSHA256hash(entropy);
    let [, checksummedEntropy] = bip39.appendChecksum(entropy, hash);
    let indices = bip39.generateMnemonicIndices(checksummedEntropy);
    let phrase = bip39.generateMnemonic(wordlist, indices);

    return phrase;
}

const recoverFromMnemonic = (mnemonic, algorithm) => {
    return bip39.keypairFromMnemonic(mnemonic, algorithm);
}

module.exports = {
    newMnemonic,
    recoverFromMnemonic
}