function maskURL(url) {
  if (url.length > 40) {
    return `${url.substring(0,40)} ... ${url.substring(url.length - 10,url.length)}`;
  }
  return url;
}
function createSummary(message) {
  let tableContent = '';
  tableContent += `<tr><td>Host:</td><td colspan=3>${message.result[0]}</td></tr>`;
  tableContent += `<tr><td>Score:</td><td colspan=3>${message.result[2].score}</td></tr>`;
  tableContent += `<tr><td>IP:</td><td colspan=3>${message.result[4]}</td></tr>`;
  tableContent += `<tr><td colspand=4></td></tr>`;
  tableContent += `<tr><td><b>Test</b></td><td><b>Pass</b></td><td><b>Score</b></td><td><b>Explanation</b></td></tr>`;
  tableContent += `<tr><td>CSP:</td><td>${message.result[1].headerScores.csp.pass}</td><td>${message.result[1].headerScores.csp.score}</td><td>${message.result[1].headerScores.csp.result}</td></tr>`;
  tableContent += `<tr><td>HSTS:</td><td>${message.result[1].headerScores.hsts.pass}</td><td>${message.result[1].headerScores.hsts.score}</td><td>${message.result[1].headerScores.hsts.result}</td></tr>`;
  tableContent += `<tr><td>XXSSP:</td><td>${message.result[1].headerScores.xxssp.pass}</td><td>${message.result[1].headerScores.xxssp.score}</td><td>${message.result[1].headerScores.xxssp.result}</td></tr>`;
  tableContent += `<tr><td>X-Frame:</td><td>${message.result[1].headerScores.xframe.pass}</td><td>${message.result[1].headerScores.xframe.score}</td><td>${message.result[1].headerScores.xframe.result}</td></tr>`;
  tableContent += `<tr><td>X-Content-Type:</td><td>${message.result[1].headerScores['x-content-type-options'].pass}</td><td>${message.result[1].headerScores['x-content-type-options'].score}</td><td>${message.result[1].headerScores['x-content-type-options'].result}</td></tr>`;
  return tableContent;

}

function createAggSummary(message) {
  let tableContent = '';
  
  Object.keys(message.agg.grades).forEach( e => {
    tableContent += `<tr><td>${e}</td><td colspan=3>${message.agg.grades[e]}</td></tr>`;
  });
  tableContent += `<tr><td>Total:</td><td colspan=3>${message.agg.totalRequests}</td></tr>`;
  return tableContent;

}

function createGradeBox(message) {
  let divContent = '';
  let grade = message.result[2].grade;
  let plusGrade = grade.replace(grade.replace('+', '').replace('-', ''), '');
  divContent += `
  <span class="grade-container text-center grade-${grade.replace('+', '').replace('-', '').toLowerCase()} grade-with-modifier" id="scan-grade-container">
  <span class="grade-letter" id="scan-grade-letter">${grade.replace('+', '').replace('-', '')}</span>
  <sup class="grade-letter-modifier grade-with-modifier-wider" id="scan-grade-modifier">${plusGrade}</sup>
  </span>
  `;
  return divContent;

}

function createCompleteReport(message) {
  console.log(message);
  let tableContent = '<table class="table"><tbody><tr><td>URL</td><td>Grade</td><td>CSP</td><td>SRI</td><td>HSTS</td><td>XXSP</td><td>X-Frame</td><td>X-Content-Type-Options</td></tr>';
  Object.keys(message.result).forEach( e => {
    console.log(e);
    const row = message.result[e];
    console.log(row);
    tableContent += `<tr>
    <td title=${row[0]}>${maskURL(row[0])}</td>
    <td>${row[2].grade}</td>
    <td>${row[1].headerScores.csp.pass} : ${row[1].headerScores.csp.result}</td>
    <td>${message.sri ? message.sri[row[0]] : '-'}</td>
    <td>${row[1].headerScores.hsts.pass} : ${row[1].headerScores.hsts.result}</td>
    <td>${row[1].headerScores.xxssp.pass} : ${row[1].headerScores.xxssp.result}</td>
    <td>${row[1].headerScores.xframe.pass} : ${row[1].headerScores.xframe.result}</td>
    <td>${row[1].headerScores['x-content-type-options'].pass} : ${row[1].headerScores['x-content-type-options'].result}</td>
    </tr>`;
  });
  tableContent += '</tbody></table>';
  const div = document.getElementById('complete-report');
  div.innerHTML = tableContent;
  const div1 = document.getElementById('scan-summary');
  div1.innerHTML = '';
}
function responseBackground(message) {
  console.log(message);
  const summaryHTML = createSummary(message);
  const gradeHTML = createGradeBox(message);
  const aggHTML = createAggSummary(message);
  console.log(summaryHTML);
  const grade = document.getElementById('grade');
  grade.innerHTML = gradeHTML;
  const table = document.getElementById('results');
  table.innerHTML = summaryHTML;
  const aggTable = document.getElementById('results-summary');
  aggTable.innerHTML = aggHTML;
}

function handleError(error) {
	console.log("Error in popu>", error);
}

function getCurrentTab() {
  return new Promise( (resolve) => {
    chrome.tabs.query({active: true, lastFocusedWindow: true},(tabs) => {
      const tabLink = tabs[0].url;
      const tabID = tabs[0].id;
      resolve({tabLink, tabID});    
    });
  });
}


if (document.location.href.startsWith('moz-extension://') && document.location.href.indexOf('#') > -1) {
  const tabID = document.location.href.split('#')[1];
  console.log(">>>> ", tabID);
  const sending = browser.runtime.sendMessage({"id":tabID, "url": ''});
  sending.then(createCompleteReport, handleError);

} else {
  console.log(">>>>>> in else");
  getCurrentTab().then((h) => {
    console.log("DDD", h);
    const sending = browser.runtime.sendMessage({"id":h.tabID, "url": h.tabLink});
    sending.then(responseBackground, handleError);
  });
  
}



document.getElementById("detailedReport").addEventListener("click", function() {
  getCurrentTab().then((h) => { 
    chrome.tabs.create({
      url: `./popup.html#${h.tabID}`
    });
  });
});