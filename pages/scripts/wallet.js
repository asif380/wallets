document.getElementById('dcfooter').innerHTML = 'MIT 2022  - <b style=\'cursor:pointer\' onclick=\'openDonatePage()\'><a href="https://github.com/RebelStation/RebelLightWallet?">Rebel Light Wallet</a>';


// Wallet Import
importWallet = function (newWif = false, raw = false) {
  const strImportConfirm = "Do you really want to import a new address? If you haven't saved the last private key, the wallet will be LOST forever.";
  const walletConfirm = fWalletLoaded ? window.confirm(strImportConfirm) : true;
  if (walletConfirm) {
    if (raw) {
      const pkNetBytesLen = newWif.length + 2;
      const pkNetBytes = new Uint8Array(pkNetBytesLen);
      // Network Encoding
      pkNetBytes[0] = SECRET_KEY;          // Private key prefix (1 byte)
      writeToUint8(pkNetBytes, newWif, 1); // Private key bytes  (32 bytes)
      pkNetBytes[pkNetBytesLen - 1] = 1;   // Leading digit      (1 byte)
      // Double SHA-256 hash
      const shaObj = new jsSHA(0, 0, { "numRounds": 2 });
      shaObj.update(pkNetBytes);
      // WIF Checksum
      const checksum = shaObj.getHash(0).slice(0, 4);
      const keyWithChecksum = new Uint8Array(pkNetBytesLen + checksum.length);
      writeToUint8(keyWithChecksum, pkNetBytes, 0);
      writeToUint8(keyWithChecksum, checksum, pkNetBytesLen);
      newWif = to_b58(keyWithChecksum);
    }
    // Wallet Import Format to Private Key
    const privkeyWIF = newWif || domPrivKey.value;
    privateKeyForTransactions = privkeyWIF;
    if (!newWif) domPrivKey.value = "";
    const byteArryConvert = from_b58(privkeyWIF);
    const droplfour = byteArryConvert.slice(0, byteArryConvert.length - 4);
    const key = droplfour.slice(1, droplfour.length);
    const privkeyBytes = key.slice(0, key.length - 1);
    if (debug) {
      // WIF to Private Key
      console.log(Crypto.util.bytesToHex(privkeyWIF));
      console.log(Crypto.util.bytesToHex(byteArryConvert));
      console.log(Crypto.util.bytesToHex(droplfour));
      console.log(Crypto.util.bytesToHex(privkeyBytes));
    }
    // Public Key Derivation
    let nPubkey = '';
    let pubY;
    try {
      // Incase of an invalid/malformed/incompatible private key: catch and display a nice error!
      nPubkey = Crypto.util.bytesToHex(nSecp256k1.getPublicKey(privkeyBytes)).substr(2);
      pubY = Secp256k1.uint256(nPubkey.substr(64), 16);
    } catch (e) {
      console.error(e);
      createAlert('warning', '<b>Failed to import!</b> Invalid private key.' +
        '<br>Double-check where your key came from!',
        6000);
    }
    nPubkey = nPubkey.substr(0, 64);
    const publicKeyBytesCompressed = Crypto.util.hexToBytes(nPubkey);
    publicKeyBytesCompressed.unshift(pubY.isEven() ? 0x02 : 0x03);
    // First pubkey SHA-256 hash
    const pubKeyHashing = new jsSHA(0, 0, { "numRounds": 1 });
    pubKeyHashing.update(publicKeyBytesCompressed);
    // RIPEMD160 hash
    const pubKeyHashRipemd160 = ripemd160(pubKeyHashing.getHash(0));
    // Network Encoding
    const pubKeyHashNetwork = new Uint8Array(pubKeyHashNetworkLen);
    pubKeyHashNetwork[0] = PUBKEY_ADDRESS;
    writeToUint8(pubKeyHashNetwork, pubKeyHashRipemd160, 1);
    // Double SHA-256 hash
    const pubKeyHashingS = new jsSHA(0, 0, { "numRounds": 2 });
    pubKeyHashingS.update(pubKeyHashNetwork);
    const pubKeyHashingSF = pubKeyHashingS.getHash(0);
    // Checksum
    const checksumPubKey = pubKeyHashingSF.slice(0, 4);
    // Public key pre-base58
    const pubKeyPreBase = new Uint8Array(pubPrebaseLen);
    writeToUint8(pubKeyPreBase, pubKeyHashNetwork, 0);
    writeToUint8(pubKeyPreBase, checksumPubKey, pubKeyHashNetworkLen);
    // Encode as Base58 human-readable network address
    publicKeyForNetwork = to_b58(pubKeyPreBase);

    // Reaching here: the deserialisation was a full cryptographic success, so a wallet is now imported!
    fWalletLoaded = true;

    // Display Text
    domGuiAddress.innerHTML = publicKeyForNetwork;
    domGuiWallet.style.display = 'block';
    domPrivateTxt.value = privkeyWIF;
    domGuiAddress.innerHTML = publicKeyForNetwork;

    // QR Codes
    // Private Key
    const typeNumber = 4;
    const errorCorrectionLevel = 'L';
    const qrPriv = qrcode(typeNumber, errorCorrectionLevel);
    qrPriv.addData(privkeyWIF);
    qrPriv.make();
    domPrivateQr.innerHTML = qrPriv.createImgTag();
    domPrivateQr.firstChild.style.borderRadius = '8px';

    // Public Key
    const qrPub = qrcode(typeNumber, errorCorrectionLevel);
    qrPub.addData('rebel:' + publicKeyForNetwork);
    qrPub.make();
    domPublicQr.innerHTML = qrPub.createImgTag();
    domPublicQr.firstChild.style.borderRadius = '8px';
    // Pubkey Modal
    domModalQrLabel.innerHTML = 'rebel:' + publicKeyForNetwork;
    domModalQR.innerHTML = qrPub.createImgTag();
    domModalQR.firstChild.style.width = "100%";
    domModalQR.firstChild.style.height = "auto";
    domModalQR.firstChild.style.imageRendering = "crisp-edges";
    document.getElementById('clipboard').value = publicKeyForNetwork;

    // Set view key as public and refresh QR code
    viewPrivKey = true;
    toggleKeyView();

    // Update identicon
    domIdenticon.dataset.jdenticonValue = publicKeyForNetwork;
    jdenticon();

    if (!newWif) {
      // Hide the encryption warning
      domGenKeyWarning.style.display = 'block';
    }
    // Load UTXOs from explorer
    if (networkEnabled)
      getUnspentTransactions();

    // Hide all wallet starter options
    hideAllWalletOptions();
  }
}

// Wallet Generation
generateWallet = async function (noUI = false) {
  const strImportConfirm = "Do you really want to import a new address? If you haven't saved the last private key, the wallet will be LOST forever.";
  const walletConfirm = fWalletLoaded && !noUI ? window.confirm(strImportConfirm) : true;
  if (walletConfirm) {
    const pkBytes = getSafeRand();
    // Private Key Generation
    const pkNetBytesLen = pkBytes.length + 2;
    const pkNetBytes = new Uint8Array(pkNetBytesLen);
    // Network Encoding
    pkNetBytes[0] = SECRET_KEY;           // Private key prefix (1 byte)
    writeToUint8(pkNetBytes, pkBytes, 1); // Private key bytes  (32 bytes)
    pkNetBytes[pkNetBytesLen - 1] = 1;    // Leading digit      (1 byte)
    // Double SHA-256 hash
    const shaObj = new jsSHA(0, 0, { "numRounds": 2 });
    shaObj.update(pkNetBytes);
    // WIF Checksum
    const checksum = shaObj.getHash(0).slice(0, 4);
    const keyWithChecksum = new Uint8Array(pkNetBytesLen + checksum.length);
    writeToUint8(keyWithChecksum, pkNetBytes, 0);
    writeToUint8(keyWithChecksum, checksum, pkNetBytesLen);
    // Encode as Base58 human-readable WIF
    privateKeyForTransactions = to_b58(keyWithChecksum);

    // Public Key Derivation
    let nPubkey = Crypto.util.bytesToHex(nSecp256k1.getPublicKey(pkBytes)).substr(2);
    const pubY = Secp256k1.uint256(nPubkey.substr(64), 16);
    nPubkey = nPubkey.substr(0, 64);
    const publicKeyBytesCompressed = Crypto.util.hexToBytes(nPubkey);
    publicKeyBytesCompressed.unshift(pubY.isEven() ? 0x02 : 0x03);
    // First pubkey SHA-256 hash
    const pubKeyHashing = new jsSHA(0, 0, { "numRounds": 1 });
    pubKeyHashing.update(publicKeyBytesCompressed);
    // RIPEMD160 hash
    const pubKeyHashRipemd160 = ripemd160(pubKeyHashing.getHash(0));
    // Network Encoding
    const pubKeyHashNetwork = new Uint8Array(pubKeyHashNetworkLen);
    pubKeyHashNetwork[0] = PUBKEY_ADDRESS;
    writeToUint8(pubKeyHashNetwork, pubKeyHashRipemd160, 1);
    // Double SHA-256 hash
    const pubKeyHashingS = new jsSHA(0, 0, { "numRounds": 2 });
    pubKeyHashingS.update(pubKeyHashNetwork);
    const pubKeyHashingSF = pubKeyHashingS.getHash(0);
    // Checksum
    const checksumPubKey = pubKeyHashingSF.slice(0, 4);
    // Public key pre-base58
    const pubKeyPreBase = new Uint8Array(pubPrebaseLen);
    writeToUint8(pubKeyPreBase, pubKeyHashNetwork, 0);
    writeToUint8(pubKeyPreBase, checksumPubKey, pubKeyHashNetworkLen);
    // Encode as Base58 human-readable network address
    publicKeyForNetwork = to_b58(pubKeyPreBase);

    fWalletLoaded = true;

    // Debug Console
    if (debug) {
      console.log("Private Key")
      console.log(pkNetBytes)
      console.log("Private key plus Net Prefix and Leading Digits")
      console.log(Crypto.util.bytesToHex(pkNetBytes))
      console.log("Double SHA-256 Hash")
      console.log(shaObj.getHash(0))
      console.log('CheckSum')
      console.log(checksum)
      console.log('Key With CheckSum')
      console.log(keyWithChecksum)
      console.log('Private Key')
      console.log(privateKeyForTransactions)
      console.log('Public Key')
      console.log(publicKeyBytesCompressed)
      console.log('Public Key Extended')
      console.log(Crypto.util.bytesToHex(pubkeyExt))
      console.log('SHA256 Public Key')
      console.log(pubKeyHashing.getHash("HEX"))
      console.log('RIPEMD160 Public Key')
      console.log(pubKeyHashRipemd160)
      console.log('PubKeyHash w/NetworkBytes')
      console.log(pubKeyHashNetwork)
      console.log('2x SHA256 Public Key Secound Time')
      console.log(pubKeyHashingSF)
      console.log("CheckSum Public Key")
      console.log(checksumPubKey)
      console.log("Pub Key with Checksum")
      console.log(pubKeyPreBase)
      console.log('Public Key Base 64')
      console.log(publicKeyForNetwork)
    }
    if (!noUI) {
      // Display Text
      domGenKeyWarning.style.display = 'block';
      domPrivateTxt.value = privateKeyForTransactions;
      domGuiAddress.innerHTML = publicKeyForNetwork;
      // New address... so there definitely won't be a balance
      domGuiBalance.innerHTML = "0";
      domGuiBalanceBox.style.fontSize = "x-large";
      // QR Codes
      const typeNumber = 4;
      const errorCorrectionLevel = 'L';
      const qrPriv = qrcode(typeNumber, errorCorrectionLevel);
      qrPriv.addData(privateKeyForTransactions);
      qrPriv.make();
      domPrivateQr.innerHTML = qrPriv.createImgTag();
      domPrivateQr.firstChild.style.borderRadius = '8px';
      const qrPub = qrcode(typeNumber, errorCorrectionLevel);
      qrPub.addData('rebel:' + publicKeyForNetwork);
      qrPub.make();
      domPublicQr.innerHTML = qrPub.createImgTag();
      domPublicQr.style.display = 'block';
      domPublicQr.firstChild.style.borderRadius = '8px';
      domModalQrLabel.innerHTML = 'rebel:' + publicKeyForNetwork;
      domModalQR.innerHTML = qrPub.createImgTag();
      domModalQR.firstChild.style.width = "100%";
      domModalQR.firstChild.style.height = "auto";
      domModalQR.firstChild.style.imageRendering = "crisp-edges";
      document.getElementById('clipboard').value = publicKeyForNetwork;
      // Update identicon
      domIdenticon.dataset.jdenticonValue = publicKeyForNetwork;
      jdenticon();
      domGuiWallet.style.display = 'block';
      viewPrivKey = false;
      hideAllWalletOptions();
    }
    return { 'pubkey': publicKeyForNetwork, 'privkey': privateKeyForTransactions };
  }
}

async function benchmark(quantity) {
  let i = 0;
  const nStartTime = Date.now();
  while (i < quantity) {
    await generateWallet(true);
    i++;
  }
  const nEndTime = Date.now();
  console.log("Time taken to generate " + i + " addresses: " + (nEndTime - nStartTime).toFixed(2) + 'ms');
}

encryptWallet = async function (strPassword = '') {
  // Encrypt the wallet WIF with AES-GCM and a user-chosen password - suitable for browser storage
  let encWIF = await encrypt(privateKeyForTransactions, strPassword);
  if (typeof encWIF !== "string") return false;
  // Set the encrypted wallet in localStorage
  localStorage.setItem("encwif", encWIF);
  // Hide the encryption warning
  domGenKeyWarning.style.display = 'none';
}

decryptWallet = async function (strPassword = '') {
  // Check if there's any encrypted WIF available, if so, prompt to decrypt it
  let encWif = localStorage.getItem("encwif");
  if (!encWif || encWif.length < 1) {
    console.log("No local encrypted wallet found!");
    return false;
  }
  let decWif = await decrypt(encWif, strPassword);
  if (!decWif || decWif === "decryption failed!") {
    if (decWif === "decryption failed!")
      alert("Incorrect password!");
    return false;
  }
  importWallet(decWif);
  return true;
}

hasEncryptedWallet = function () {
  return localStorage.getItem("encwif") ? true : false;
}