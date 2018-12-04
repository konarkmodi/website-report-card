if(typeof('chrome') === 'undefined') {
  var chrome = browser;
}

const sriArray = Array.prototype.slice.call(document.querySelectorAll('[integrity]'));
const sri = {
  type: 'sri',
  status: false,
  urls: {}
}
if (sriArray.length > 0) {
  sri.status = true;
  sriArray.forEach(element => {
    const url = element.href || element.src;
    sri.urls[url] = true;
  });
}

console.log(sri);

chrome.runtime.sendMessage(sri);