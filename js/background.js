'use strict';
// sodium is loaded but not initialized yet check for errors
sodium.ready.catch(sodiumNotInitialized);

function sodiumNotInitialized(error) {
    console.log("sodium initialize error", error);
}

//global vars
var statistics = 0;

//local storage
function onError(error) {
    console.log(error);
}

function setStorage() {
  console.log("statistics saved to local storage");
}

function storeStatistics() {
    browser.storage.local.set({statistics}).catch(onError);
}

async function resetStatistics(callback) {
    statistics = 0;
    await storeStatistics();
    callback();
}

// Auxilizary domain functions
function normalizeDomain(domain) {
    // strip leading www and lowercase domain
    return domain.replace(/^www\./,'').toLowerCase();
}

// PSI Core functions
async function callPSICheckDomain(data, callback) {
    let blocked = false;
    let psicheckdomainUrl = new URL("https://psidomaincheck.es/api/checkdomain");
    const params = new URLSearchParams();
    params.set('hash_prefix', data.hash_prefix);
    params.set('domain', data.blind_domain_hex);
    psicheckdomainUrl.search = params.toString();
    // ToDo add timeout since we are blocking the browser:
    // https://dmitripavlutin.com/timeout-fetch-request/
    let response = await fetch(psicheckdomainUrl);
    response = await response.json();
    blocked = validateDomain(response, data.a_inv_hex);
    return blocked;
}

function computeDomainCryptoInfo(domain) {

    // Get a random scalar from ristretto255
    let a = sodium.crypto_core_ristretto255_scalar_random();
    let a_hex = sodium.to_hex(a);
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

// Active Protection functionality
// Switch Active Protection status
function activeProtection(active) {
    console.log("active", active);
    if (active) {
        browser.webRequest.onBeforeRequest.addListener(
            checkBrowserDomain,
            {urls: ["<all_urls>"], types: ["main_frame"]},
            ["blocking"]
        );
    } else {
        chrome.webRequest.onBeforeRequest.removeListener(checkBrowserDomain);
    }
}

async function checkBrowserDomain(requestDetails) {
    console.log("inicio checkBrowserDomain");
    let url = new URL(requestDetails.url);
    let domain = url.hostname;
    let norm_domain = normalizeDomain(domain);
    console.log("domain", norm_domain);

    let data = computeDomainCryptoInfo(norm_domain);
    let blocked = await callPSICheckDomain(data);
    if (blocked) {
        statistics += 1;
        storeStatistics();
        return {redirectUrl: browser.runtime.getURL("blocked.html")};
    }
}

// Manual Protection functionality
async function checkManualDomain(domain, callback) {
    console.log("inicio checkManualDomain");
    let norm_domain = normalizeDomain(domain);
    console.log("domain", norm_domain);
    let data = computeDomainCryptoInfo(norm_domain);
    let blocked = await callPSICheckDomain(data);
    callback(blocked, norm_domain);
}

// initialize statistics on local storage on installation
browser.runtime.onInstalled.addListener(details => {
    browser.storage.local.set({statistics}).catch(onError);
});
