'use strict';

function networkError() {
    if (disableNetwork()) {
        createAlert('warning',
                    '<b>Failed to synchronize!</b> Please try again later.' +
                    '<br>You can attempt re-connect via the Settings.');
    }
}

if (networkEnabled) {
  var getBlockCount = function() {
    var request = new XMLHttpRequest();
    request.open('GET', "https://zkbitcoin.com/api/v2/api", true);
    request.onerror = networkError;
    request.onload = function () {
      const data = JSON.parse(this.response);
      // If the block count has changed, refresh all of our data!
      domBalanceReload.className = domBalanceReload.className.replace(/ playAnim/g, "");
      domBalanceReloadStaking.className = domBalanceReloadStaking.className.replace(/ playAnim/g, "");
      if (data.backend.blocks > cachedBlockCount) {
        console.log("New block detected! " + cachedBlockCount + " --> " + data.backend.blocks);
        if (publicKeyForNetwork)
          getUnspentTransactions();
      }
      cachedBlockCount = data.backend.blocks;
    }
    request.send();
  }

  var getUnspentTransactions = function () {
    var request = new XMLHttpRequest()
    request.open('GET', "https://chainz.cryptoid.info/pivx/api.dws?q=unspent&active=" + publicKeyForNetwork + "&key=fb4fd0981734", true)
    request.onerror = networkError;
    request.onload = function () {
      const data = JSON.parse(this.response);
      cachedUTXOs = [];
      if (!data.unspent_outputs || data.unspent_outputs.length === 0) {
        console.log('No unspent Transactions');
        document.getElementById("errorNotice").innerHTML = '<div class="alert alert-danger" role="alert"><h4>Note:</h4><h5>You don\'t have any funds, get some coins first!</h5></div>';
      } else {
        document.getElementById("errorNotice").innerHTML = '';
        // Standardize the API UTXOs into a simplified MPW format
        data.unspent_outputs.map(cUTXO => cachedUTXOs.push({
          'id': cUTXO.tx_hash,
          'vout': cUTXO.tx_ouput_n,
          'sats': cUTXO.value,
          'script': cUTXO.script
        }));
        // Update the GUI with the newly cached UTXO set
        getBalance(true);
      }
    }
    request.send();
    // In parallel, fetch Cold Staking UTXOs
    getDelegatedUTXOs();
  }

  var arrUTXOsToSearch = [];
  var searchUTXO = function () {
    if (!arrUTXOsToSearch.length) return;
    var request = new XMLHttpRequest()
    request.open('GET', "https://zkbitcoin.com/api/v2/tx-specific/" + arrUTXOsToSearch[0].txid, true);
    request.onerror = networkError;
    request.onload = function () {
      const data = JSON.parse(this.response);
      // Check the UTXOs
      for (const cVout of data.vout) {
        if (cVout.spent) continue;
        if (cVout.scriptPubKey.type === 'coldstake' && cVout.scriptPubKey.addresses.includes(publicKeyForNetwork)) {
          if (!arrDelegatedUTXOs.find(a => a.id === data.txid && a.vout === cVout.n)) {
            arrDelegatedUTXOs.push({
              'id': data.txid,
              'vout': cVout.n,
              'sats': Number(cVout.value * COIN),
              'script': cVout.scriptPubKey.hex
            });
          }
        }
      }
      arrUTXOsToSearch.shift();
      getStakingBalance(true);
      if (arrUTXOsToSearch.length) searchUTXO();
    }
    request.send();
  }

  var getDelegatedUTXOs = function () {
    if (arrUTXOsToSearch.length) return;
    var request = new XMLHttpRequest()
    request.open('GET', "https://zkbitcoin.com/api/v2/utxo/" + publicKeyForNetwork, true);
    request.onerror = networkError;
    request.onload = function () {
      arrUTXOsToSearch = JSON.parse(this.response);
      arrDelegatedUTXOs = [];
      searchUTXO();
    }
    request.send();
  }

var sendTransaction = function (hex, msg = '') {
    var request = new XMLHttpRequest();
    request.open('GET', 'https://zkbitcoin.com/api/v2/sendtx/' + hex, true);
    request.onerror = networkError;
    request.onreadystatechange = function () {
        if (!this.response || (!this.status === 200 && !this.status === 400)) return;
        if (this.readyState !== 4) return;
        const data = JSON.parse(this.response);
        if (data.result && data.result.length === 64) {
            console.log('Transaction sent! ' + data.result);
            if (domAddress1s.value !== donationAddress)
                domTxOutput.innerHTML = ('<h4 style="color:green; font-family:mono !important;">' + data.result + '</h4>');
            else
                domTxOutput.innerHTML = ('<h4 style="color:green">Thank you for supporting MyREBELlightWallet! 💜💜💜<br><span style="font-family:mono !important">' + data.result + '</span></h4>');
            domSimpleTXs.style.display = 'none';
            domAddress1s.value = '';
            domValue1s.innerHTML = '';
            createAlert('success', msg || 'Transaction sent!', msg ? (1250 + (msg.length * 50)) : 1500);
        } else {
            console.log('Error sending transaction: ' + data.result);
            createAlert('warning', 'Transaction Failed!', 1250);
            // Attempt to parse and prettify JSON (if any), otherwise, display the raw output.
            let strError = data.error;
            try {
                strError = JSON.stringify(JSON.parse(data), null, 4);
                console.log('parsed');
            } catch(e){console.log('no parse!'); console.log(e);}
            domTxOutput.innerHTML = '<h4 style="color:red;font-family:mono !important;"><pre style="color: inherit;">' + strError + "</pre></h4>";
        }
    }
    request.send();
}

  var calculatefee = function (bytes) {
    // TEMPORARY: Hardcoded fee per-byte
    return (bytes * 50) / COIN; // 50 sat/byte
  }
}