
// console.log(window.browser.devtools.inspectedWindow.tabId);
function colour(pass) {
    console.log("Dadada", pass);
    if  (pass) {
        return "label-success";
    }
    return "label-danger";

}
var port = chrome.runtime.connect({name: "security"});
port.onMessage.addListener( (msg) => {
    console.log(msg);
    // Got the result back. [url, headers, scores].
    msg.result.forEach(element => {
        let d = document.getElementById('results');
        const text_div = document.createElement("div");
        const hsts = element[1].headerScores.hsts.result || 'not-present';
        const csp = element[1].headerScores.csp.result|| 'not-present';
        const xxssp = element[1].headerScores.xxssp.result|| 'not-present';
        const ct = element[1].headerScores['x-content-type-options'].result|| 'not-present';
        const xframe = element[1].headerScores.xframe.result|| 'not-present';

        // Let's only print the score for main page.
        if (element[0] === msg.tabLink) {
            text_div.innerHTML = `
                ${element[0]} -> ${element[2].grade} 
                <span class="label label-danger}">HSTS</span>
                <span class="label ${colour(element[1].headerScores.csp.pass)}">csp</span>
                <span class="label ${colour(element[1].headerScores.xxssp.pass)}">xxssp</span>
                <span class="label ${colour(element[1].headerScores.xframe.pass)}">x-frame</span>
                `;
            d.appendChild(text_div);
        }      
    });
});
const tabID = window.browser.devtools.inspectedWindow.tabId;
//window.browser.devtools.network.onRequestFinished.addListener( (request) => {
//    if (!request.connection) return;
//    const url = request.request.url;

    // Let's get score from the background.
port.postMessage({tabID});

//});

