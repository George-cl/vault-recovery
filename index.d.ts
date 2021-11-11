import { Keys } from 'casper-js-sdk';

interface VaultRecovery {
    newMnemonic(): Array<string>;
    recoverFromMnemonic(mnemonic: Array<string>, algorithm: 'ed25519' | 'secp256k1'): Keys.AsymmetricKey;
}

declare module "vaultrecovery" {
    const vaultrecovery: VaultRecovery;

    export default vaultrecovery;
}