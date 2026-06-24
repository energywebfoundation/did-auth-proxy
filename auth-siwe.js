#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Helper to print usage
function printUsage() {
  console.log(`
Usage: node auth-siwe.js -p <private_key> [options]

Options:
  -p, --private-key    Ethereum Private Key to sign SIWE message (Required)
  -u, --url            Base URL of the auth server (Default: http://localhost:3000)
  -c, --chain-id       Chain ID (Default: 246)
  -h, --help           Show this help message
`);
}

// Parse args
const args = process.argv.slice(2);
let privateKey = process.env.PRIVATE_KEY;
let baseUrl = 'http://localhost:3000';
let chainId = 246;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '-p' || args[i] === '--private-key') {
    privateKey = args[++i];
  } else if (args[i] === '-u' || args[i] === '--url') {
    baseUrl = args[++i];
  } else if (args[i] === '-c' || args[i] === '--chain-id') {
    chainId = parseInt(args[++i], 10);
  } else if (args[i] === '-h' || args[i] === '--help') {
    printUsage();
    process.exit(0);
  }
}

if (!privateKey) {
  console.error('Error: Private key is required. Pass it via -p or set PRIVATE_KEY env variable.');
  printUsage();
  process.exit(1);
}

// Resolve dependencies from authorization-server
const authServerNodeModules = path.join(__dirname, 'authorization-server', 'node_modules');
const ethersPath = path.join(authServerNodeModules, 'ethers');
const siwePath = path.join(authServerNodeModules, 'siwe');

if (!fs.existsSync(ethersPath) || !fs.existsSync(siwePath)) {
  console.error('Error: Please run "yarn" inside "authorization-server" folder first.');
  process.exit(1);
}

const { Wallet } = require(ethersPath);
const { SiweMessage } = require(siwePath);

(async () => {
  try {
    const wallet = new Wallet(privateKey);
    console.error(`Signer Address: ${wallet.address}`);
    console.error(`Auth Server URL: ${baseUrl}`);

    // Step 1: Initiate SIWE login to get a nonce
    console.error('Initiating SIWE login...');
    const initiateRes = await fetch(`${baseUrl}/auth/login/siwe/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    if (!initiateRes.ok) {
      const errText = await initiateRes.text();
      throw new Error(`Failed to initiate SIWE: ${initiateRes.statusText} - ${errText}`);
    }

    const { nonce } = await initiateRes.json();
    console.error(`Received Nonce: ${nonce}`);

    // Step 2: Prepare SIWE message
    const domain = new URL(baseUrl).host;
    const uri = `${baseUrl}/auth/login/siwe/verify`;
    const siweMessage = new SiweMessage({
      domain,
      address: wallet.address,
      statement: 'Sign in with Ethereum to the DID Auth Proxy.',
      uri,
      version: '1',
      chainId,
      nonce,
      issuedAt: new Date().toISOString(),
    });
    const message = siweMessage.prepareMessage();

    // Step 3: Sign message
    console.error('Signing SIWE message...');
    const signature = await wallet.signMessage(message);

    // Step 4: Verify SIWE login
    console.error('Verifying SIWE signature...');
    const verifyRes = await fetch(`${baseUrl}/auth/login/siwe/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, signature }),
    });

    if (!verifyRes.ok) {
      const errText = await verifyRes.text();
      throw new Error(`Failed to verify SIWE: ${verifyRes.statusText} - ${errText}`);
    }

    const tokens = await verifyRes.json();
    console.error('SIWE authentication successful!');
    
    // Output the tokens JSON to stdout so it can be parsed or saved
    console.log(JSON.stringify(tokens, null, 2));

  } catch (error) {
    console.error('Authentication Error:', error.message);
    process.exit(1);
  }
})();
