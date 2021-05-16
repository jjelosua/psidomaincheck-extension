'use strict';
const urlInput =  document.querySelector("#url");

function setStorage() {
  console.log("inverted scalar saved to local storage");
}

function onError(error) {
  console.log(error)
}

function storeInvertedScalar(item) {
    browser.storage.local.set(item).then(setStorage, onError);
}

function showResults(blocked) {
    console.log("blocked", blocked);
}

function addAlert(message) {
    /*
    <div class="alert alert-success alert-dismissible fade show mx-2 popup-alert" role="alert">
        Alert message!
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>
    */

    var div = document.createElement('div');
    div.classList.add("alert", "alert-success", "alert-dismissible", "fade", "show", "mx-2", "popup-alert");
    div.setAttribute("role", "alert");

    var contentMessage = document.createTextNode(message);

    var closeBtn = document.createElement('button');
    closeBtn.classList.add("btn-close");
    closeBtn.setAttribute("type", "button");
    closeBtn.setAttribute("data-bs-dismiss", "alert");
    closeBtn.setAttribute("aria-label", "Close");

    div.appendChild(contentMessage);
    div.appendChild(closeBtn);

    footer.parentNode.insertBefore(div, footer);
}

function getHostname(tabs) {
    console.log("Getting hostname...")
    var domain = ""
    var tab = tabs[0];
    if (tab.url !== undefined) {
        var url = new URL(tab.url);
        if (url.protocol === "http:" || url.protocol === "https:")
            domain = url.hostname;
    }
    hostnameView.innerHTML = domain.bold();
    console.log("Get hostname done!")
}

function computeDomainCryptoInfo(background, url) {

    let sodium = background.sodium;
    // Get a random scalar from ristretto255
    let a = sodium.crypto_core_ristretto255_scalar_random();
    let a_hex = sodium.to_hex(a);
    console.log("scalar", a_hex);
    // Get the inverted scalar to be able to unblind later
    let a_inv = sodium.crypto_core_ristretto255_scalar_invert(a);
    let a_inv_hex = sodium.to_hex(a_inv);
    console.log("inv scalar", a_inv_hex);
    //Store inverted scalar in localstorage
    storeInvertedScalar({a_inv_hex});

    let hash = sodium.crypto_hash_sha512(url);
    let hash_hex = sodium.to_hex(hash);
    console.log("hash_in_hex", hash_hex);
    let hash_prefix = hash_hex.slice(0,4);
    console.log("hash prefix", hash_prefix);
    let mapped_hash = sodium.crypto_core_ristretto255_from_hash(hash);
    let blind_domain = sodium.crypto_scalarmult_ristretto255(a, mapped_hash);
    let blind_domain_hex = sodium.to_hex(blind_domain);
    console.log("blind_domain_hex", blind_domain_hex);
    console.log("valid point on curve", sodium.crypto_core_ristretto255_is_valid_point(blind_domain));

    background.kakoServerCheckDomain(hash_prefix, blind_domain_hex, showResults);
}

function addhttp(url) {
    if (!/^(?:f|ht)tps?\:\/\//.test(url)) {
        url = "http://" + url;
    }
    return url;
}

function isValidDomain(v) {
  if (!v) return false;
  var re = /^(?!:\/\/)([a-zA-Z0-9-]+\.){0,5}[a-zA-Z0-9-][a-zA-Z0-9-]+\.[a-zA-Z]{2,64}?$/gi;
  return re.test(v);
}

function checkdomain() {
    let url = urlInput.value;
    let normalized_url = addhttp(url)
    let testUrl = null
    try {
        testUrl = new URL(normalized_url);
    } catch (e) {
        if (e instanceof TypeError)
            console.log("no se reconoce una url valida");
        else
            throw e; //we want to only handle TypeError
    };
    let domain = testUrl.hostname;
    if (isValidDomain(domain)) {
        browser.runtime.getBackgroundPage().then(
            function(background) {return computeDomainCryptoInfo(background, domain);}, onError);
    }
    else {
        // TODO show error
        console.log("not a valid domain", domain)
    }
}

function protection() {
    let mode = activeProtectionBtn.getAttribute('aria-pressed');
    browser.storage.local.set({active: mode});
    if (mode == "true") {
        addAlert("Protection enabled!");
    } else {
        addAlert("Protection disabled");
    }
}

// Data view
let hostnameView = document.getElementById("hostname");
let statisticsView = document.getElementById("statistics");


let activeProtectionBtn = document.getElementById("active-protection");
let hostname = browser.tabs.query({ active: true, currentWindow: true });
hostname.then(getHostname, onError);



// Listeners
document.querySelector("#checkdomain").addEventListener('click', checkdomain);
activeProtectionBtn.addEventListener('click', protection);
