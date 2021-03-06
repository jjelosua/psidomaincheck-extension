'use strict';

function onError(error) {
  console.log(error)
}

function getDataFromLocalStorage() {
    browser.storage.local.get(["active","statistics"]).then(updateView, onError);
}

function updateView(items) {
    updateProtectionSwitch(items.active);
    updateStatistics(items.statistics);
}

function updateProtectionSwitch(item) {
    activeProtectionSwitch.checked = item;
}

function updateStatistics(item) {
    statisticsBadge.innerText = item;
}

function resetStatistics() {
    console.log("resetStatistics");
    browser.runtime.getBackgroundPage().then(
            function(background) {return background.resetStatistics(getDataFromLocalStorage);}, onError);
}

function showResults(blocked, norm_domain) {
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

function addhttp(url) {
    if (!/^(?:f|ht)tps?\:\/\//.test(url)) {
        url = "http://" + url;
    }
    return url;
}

function isValidDomain(v) {
  if (!v) return false;
  var re = /^(?!:\/\/)([a-zA-Z0-9-]+\.){0,5}[a-zA-Z0-9-]+\.[a-zA-Z]{2,64}?$/gi;
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
            console.log("could not parse data into a url, please try again");
        else
            throw e; //we want to only handle TypeError
    };
    let domain = testUrl.hostname;
    console.log("domain", domain);
    if (isValidDomain(domain)) {
        document.getElementById("url").value = '';
        browser.runtime.getBackgroundPage().then(
            function(background) {return background.checkManualDomain(domain, showResults);}, onError);
    }
    else {
        addAlert("not a valid domain, try again", "manual-alert-container", "alert-warning");
    }
}

function protection() {
    let active = this.checked;
    // Send to local storage to be able for the popup to be stateful
    browser.storage.local.set({active}).catch(onError);
    browser.runtime.getBackgroundPage().then(
            function(background) {background.activeProtection(active)}, onError);
    if (active) {
        browser.browserAction.setIcon({path: "img/psidc-48@2x.png"});
    } else {
        browser.browserAction.setIcon({path: "img/psidc-off-48@2x.png"});
    }
}

// Data view
let urlView = document.getElementById("url");
let activeProtectionSwitch = document.getElementById("activeprotection");
let checkDomainBtn = document.getElementById("checkdomain");
let statisticsBtn = document.getElementById("resetstatistics");
let statisticsBadge = document.getElementById("statisticsbadge");

// Listeners
checkDomainBtn.addEventListener('click', checkdomain);
activeProtectionSwitch.addEventListener('change', protection);
statisticsBtn.addEventListener('click', resetStatistics)


urlView.addEventListener("keyup", function(event) {
    if (event.key === "Enter") {
        checkdomain();
    }
});

getDataFromLocalStorage();
