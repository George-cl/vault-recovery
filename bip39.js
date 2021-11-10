const { randomBytes, createHash, createHmac } = require('crypto');
const { Keys } = require('casper-js-sdk');

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
    return [checksum, Buffer.concat([bytes, checksum])];
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
    return hmacSHA512(
        Buffer.from(PASSPHRASE, 'utf8'),
        Buffer.from(mnemonic.join(), 'utf8')
    );
};

// key and data should be passed as Buffers
const hmacSHA512 = (key, data) => {
    if (typeof key === 'undefined')
        key = PASSPHRASE;
    return createHmac('sha512', key)
        .update(data)
        .digest();
}

const calculateSlice = (checksumBytes) => {
    let from = checksumBytes.readUIntBE(0, 1);
    while (from > 64) {
        from = from - 64;
        if (from < 0) {
            from = (from ** from) ** 0.5;
        }
    }
    if ((from + 32) > 64) {
        from = from - 32;
    }
    return [from, from + 32];
}

const keypairFromSecretKey = (secretKey, algorithm) => {
    switch (algorithm) {
        case 'ed25519': {
            let parsedSecretKey = Keys.Ed25519.parsePrivateKey(secretKey);
            let parsedPublicKey = Keys.Ed25519.privateToPublicKey(secretKey);
            return Keys.Ed25519.parseKeyPair(parsedPublicKey, parsedSecretKey);
        };
        case 'secp256k1': {
            let parsedSecretKey = Keys.Secp256K1.parsePrivateKey(secretKey, 'raw')
            let parsedPublicKey = Keys.Secp256K1.privateToPublicKey(secretKey);
            return Keys.Secp256K1.parseKeyPair(parsedPublicKey, parsedSecretKey, 'raw');
        };
        default: throw new Error('invalid algorithm provided');
    }
}

module.exports = {
    generate256RandomBits,
    getSHA256hash,
    appendChecksum,
    generateMnemonicIndices,
    generateMnemonic,
    convertMnemonicToSeed,
    hmacSHA512,
    calculateSlice,
    keypairFromSecretKey
}
