const fs = require('fs');
const { Wallet } = require('ethers');

const args = process.argv.slice(2);

if (args.length < 2) {
  console.error("Usage: node decryptKeystore.js <keystore-file> <password>");
  process.exit(1);
}

const keystorePath = args[0];
const password = args[1];

try {
  if (!fs.existsSync(keystorePath)) {
    throw new Error("Keystore file does not exist");
  }

  const keystore = fs.readFileSync(keystorePath, 'utf8');
  const wallet = Wallet.fromEncryptedJsonSync(keystore, password);
  console.log(wallet.privateKey);
} catch (error) {
  console.error("Failed to decrypt keystore:", error.message);
}
