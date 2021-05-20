'use strict';

function onError(error) {
  console.log(error)
}

function showResults(blocked) {
    console.log("blocked", blocked);
    if (blocked) {
        addAlert("Domain has been found as malicious in PSIDomainCheck intelligence feed.", "manual-alert-placeholder");
    } else {
        addAlert("Domain not found as malicious within PSIDomainCheck intelligence feed.", "manual-alert-placeholder");
    }
}

function addAlert(message, elid) {
    let position = document.getElementById(elid);
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

    position.parentNode.insertBefore(div, position);
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
    let urlInput =  document.getElementById("url");
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
            function(background) {return background.checkManualDomain(domain, showResults);}, onError);
    }
    else {
        // TODO show error
        console.log("not a valid domain", domain);
        addAlert("not a valid domain, try again", "manual-alert-placeholder");
    }
}

function protection() {
    let mode = activeProtectionBtn.getAttribute('aria-pressed');
    browser.storage.local.set({active: mode});
    if (mode == "true") {
        addAlert("Protection enabled!", "footer");
    } else {
        addAlert("Protection disabled", "footer");
    }
}

// Data view
let hostnameView = document.getElementById("hostname");
let statisticsView = document.getElementById("statistics");


let activeProtectionBtn = document.getElementById("active-protection");
let checkDomainBtn = document.getElementById("checkdomain");
let hostname = browser.tabs.query({ active: true, currentWindow: true });
hostname.then(getHostname, onError);



// Listeners
checkDomainBtn.addEventListener('click', checkdomain);
activeProtectionBtn.addEventListener('click', protection);
