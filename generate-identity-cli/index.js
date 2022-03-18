#!/usr/bin/env node

const { utils, Wallet } = require('ethers');
const { encode } = require('base64url');
const { program } = require('commander');

program
    .requiredOption('-p, --private-key <key>', 'DID private key', validatePrivateKey)
    .requiredOption('-b, --block-number <block number>', 'block number', parseBlockNumber)
    .option('-v, --verbose', 'output messages for debugging')
    .parse(process.argv);

const options = program.opts();
const { privateKey, blockNumber, verbose = false } = options;

const signer = new Wallet(privateKey);

const header = {
    alg: 'ES256',
    typ: 'JWT'
};

(async () => {
    const did = `did:ethr:volta:${await signer.getAddress()}`;

    logger(`generating identityToken for ${did}`, verbose);

    const payload = {
        iss: did,
        claimData: { blockNumber }
    };

    logger(`token header: ${JSON.stringify(header)}`, verbose);
    logger(`token payload: ${JSON.stringify(payload)}`, verbose);

    const headerEncoded = encode(Buffer.from(JSON.stringify(header)));
    const payloadEncoded = encode(Buffer.from(JSON.stringify(payload)));

    const hash = utils.keccak256(Buffer.from(`${headerEncoded}.${payloadEncoded}`));

    logger(`hash: ${hash}`, verbose);

    const signatureEncoded = encode(Buffer.from(await signer.signMessage(utils.arrayify(hash))));

    logger(`signature: ${signatureEncoded}`, verbose);

    const identityToken = `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;

    console.log(identityToken);
})();

function logger(message, enabled = true) {
    if (enabled) console.error(message);
}

function parseBlockNumber(blockNumber) {
    const parsedValue = parseInt(blockNumber, 10);
    if (isNaN(parsedValue)) {
        throw new program.InvalidArgumentError('Not a number.');
    }
    return parsedValue;
}

function validatePrivateKey(privateKey) {
    try {
        w = new Wallet(privateKey);
    } catch (e) {
        throw new program.InvalidArgumentError('Invalid private key.');
    }

    return privateKey;
}
