'use strict';
// sodium is loaded but not initialized yet
sodium.ready.then(sodiumInitialized).catch(sodiumNotInitialized);

function sodiumInitialized() {
    console.log("sodium initialized");
}

function sodiumNotInitialized(error) {
    console.log("sodium initialize error", error);
}

//global vars
var active = false;
var statistics = 0;

function onError(error) {
    console.log(error);
}


function kakoServerCheckDomain(prefix, p, callback) {
    let kakoUrl = new URL("http://127.0.0.1/api/checkdomain")
    const params = new URLSearchParams();
    params.set('hash_prefix', prefix);
    params.set('domain', p);
    kakoUrl.search = params.toString();
    console.log("kakoUrl", kakoUrl);
    let xhr = new XMLHttpRequest();
    xhr.open("GET", kakoUrl);
    xhr.send();
    let req = new XMLHttpRequest();
    req.open('GET', kakoUrl, true);
    req.onreadystatechange = function (aEvt) {
        if (req.readyState == 4) {
            if(req.status == 200) {
                let response = JSON.parse(req.responseText);
                validateDomain(response, callback)
            }
            else {
                console.log("Error communicating with kako server\n");
            }
        }
    };
    req.send(null);
}


async function callPSICheckDomain(data, callback) {
    let blocked = false;
    let kakoUrl = new URL("http://127.0.0.1/api/checkdomain")
    const params = new URLSearchParams();
    params.set('hash_prefix', data.hash_prefix);
    params.set('domain', data.blind_domain_hex);
    kakoUrl.search = params.toString();
    // ToDo add timeout since we are blocking the browser:
    // https://dmitripavlutin.com/timeout-fetch-request/
    let response = await fetch(kakoUrl);
    response = await response.json();
    blocked = validateDomain(response, data.a_inv_hex);
    return blocked;
}

function computeDomainCryptoInfo(domain) {

    // Get a random scalar from ristretto255
    let a = sodium.crypto_core_ristretto255_scalar_random();
    let a_hex = sodium.to_hex(a);
    //console.log("scalar", a_hex);
    // Get the inverted scalar to be able to unblind later
    let a_inv = sodium.crypto_core_ristretto255_scalar_invert(a);
    let a_inv_hex = sodium.to_hex(a_inv);

    let hash = sodium.crypto_hash_sha512(domain);
    let hash_hex = sodium.to_hex(hash);
    let hash_prefix = hash_hex.slice(0,4);
    let mapped_hash = sodium.crypto_core_ristretto255_from_hash(hash);
    let blind_domain = sodium.crypto_scalarmult_ristretto255(a, mapped_hash);
    let blind_domain_hex = sodium.to_hex(blind_domain);

    return {"hash_prefix" : hash_prefix, "blind_domain_hex" : blind_domain_hex, "a_inv_hex": a_inv_hex};
}

async function validateDomain(response, a_inv_hex) {
    let blocked = false;

    let double_blinded_domain_hex = response.double_blinded_domain;
    console.log("double_blinded_domain", double_blinded_domain_hex);
    let double_blinded_domain = sodium.from_hex(double_blinded_domain_hex);
    let a_inv = sodium.from_hex(a_inv_hex);
    let unblind_domain = sodium.crypto_scalarmult_ristretto255(a_inv, double_blinded_domain);
    let unblind_domain_hex = sodium.to_hex(unblind_domain);

    let malicious_domains = response.malicious_domains;

    if (malicious_domains.indexOf(unblind_domain_hex) > -1) blocked = true;
    return blocked;
}

async function checkBrowserDomain(requestDetails) {
    console.log("inicio checkBrowserDomain");
    let url = new URL(requestDetails.url);
    let domain = url.hostname;
    console.log("domain", domain);
    let data = computeDomainCryptoInfo(domain);
    let blocked = await callPSICheckDomain(data);
    if (blocked) {
        console.log("should be blocked!!")
        return {redirectUrl: browser.runtime.getURL("blocked/blocked.html")};
    } else {
        console.log("Nothing to do, let browser continue with its life");
    }
    console.log("final checkBrowserDomain");
}

async function checkManualDomain(domain, callback) {
    console.log("inicio checkManualDomain");
    console.log("domain", domain);
    let data = computeDomainCryptoInfo(domain);
    let blocked = await callPSICheckDomain(data);
    console.log("final checkManualDomain");
    callback(blocked);
}

function activeProtection() {
    if (active == "true") {
        browser.webRequest.onBeforeRequest.addListener(
            checkBrowserDomain,
            {urls: ["<all_urls>"], types: ["main_frame"]},
            ["blocking"]
        );
    } else {
        chrome.webRequest.onBeforeRequest.removeListener(checkBrowserDomain);
    }
}

function updateStatus() {
    if (active === false){
        browser.browserAction.setIcon({path: "img/vortex-off-48.png"});
    } else {
        browser.browserActsion.setIcon({path: "img/vortex-48.png"});
    }
}

// Listen for changes in storage
browser.storage.onChanged.addListener(changes => {
    console.log("Updating data...")
    let changedItems = Object.keys(changes);

    if (changedItems.includes("active")) {
        active = changes.active.newValue;
        activeProtection()
    }

    if (changedItems.includes("statistics")) {
        statistics = changes.statistics.newValue;
        //setBadgeData(statistics);
    }

    console.log("Updated data!")
});

browser.runtime.onInstalled.addListener(details => {
    browser.storage.local.set({
        active: false,
        statistics: statistics
    });
});
