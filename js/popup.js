'use strict';

function onError(error) {
  console.log(error)
}

function showResults(blocked, norm_domain) {
    console.log("blocked", blocked);
    if (blocked) {
        addAlert(norm_domain + " has been found as malicious in PSIDomainCheck intelligence feed.", "manual-alert-container", "alert-danger");
    } else {
        addAlert(norm_domain + " not found as malicious within PSIDomainCheck intelligence feed.", "manual-alert-container", "alert-info");
    }
}

function addAlert(message, elid, alert_type) {
    let container = document.getElementById(elid);

    var div = document.createElement('div');
    div.classList.add("alert", alert_type, "alert-dismissible", "fade", "show", "mx-2");
    div.setAttribute("role", "alert");

    var contentMessage = document.createTextNode(message);

    var closeBtn = document.createElement('button');
    closeBtn.classList.add("btn-close");
    closeBtn.setAttribute("type", "button");
    closeBtn.setAttribute("data-bs-dismiss", "alert");
    closeBtn.setAttribute("aria-label", "Close");

    div.appendChild(contentMessage);
    div.appendChild(closeBtn);

    if (container.children.length) {
        container.replaceChild(div, container.children[0]);
    }
    else {
        container.appendChild(div);
    }
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
    let url = urlView.value;
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
        document.getElementById("url").value = '';
        browser.runtime.getBackgroundPage().then(
            function(background) {return background.checkManualDomain(domain, showResults);}, onError);
    }
    else {
        // TODO show error
        console.log("not a valid domain", domain);
        addAlert("not a valid domain, try again", "manual-alert-container", "alert-warning");
    }
}

function protection() {
    let mode = activeProtectionBtn.getAttribute('aria-pressed');
    browser.storage.local.set({active: mode});
    if (mode == "true") {
        browser.browserAction.setIcon({path: "img/psidc-48@2x.png"});
        addAlert("Protection enabled!", "protection-alert-container", "alert-success");
    } else {
        browser.browserAction.setIcon({path: "img/psidc-off-48@2x.png"});
        addAlert("Protection disabled", "protection-alert-container", "alert-warning");
    }
}

// Data view
let hostnameView = document.getElementById("hostname");
let statisticsView = document.getElementById("statistics");
let urlView = document.getElementById("url");
let activeProtectionBtn = document.getElementById("active-protection");
let checkDomainBtn = document.getElementById("checkdomain");

let hostname = browser.tabs.query({ active: true, currentWindow: true });
hostname.then(getHostname, onError);



// Listeners
checkDomainBtn.addEventListener('click', checkdomain);
activeProtectionBtn.addEventListener('click', protection);

urlView.addEventListener("keyup", function(event) {
    if (event.key === "Enter") {
        checkdomain();
    }
});
