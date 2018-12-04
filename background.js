/**
 * Porting analyzer from https://github.com/mozilla/http-observatory/blob/master/httpobs/scanner/analyzer/headers.py
 */

// We need to clean it at some point.
const tabSecurityScores = {};
const urls = {};
let sriURLs;
/**
 * Caluclate aggregate stats.
 *
 */
function aggregateStats(tabID) {
  const output = {
    totalRequests: 0,
    grades: {}
  }

  // Get object details.
  tabDetails = tabSecurityScores[tabID];
  output.totalRequests = Object.keys(tabDetails).length;
  Object.keys(tabDetails).forEach( (a) => {
    const results = tabDetails[a][2];
    if (!output.grades.hasOwnProperty(results.grade)) {
      output.grades[results.grade] = 0;
    }
    output.grades[results.grade] += 1;
  });

  return output;
}

/**
 * Convert response headers array to map.
 *
 */
function convertHeaders(responseHeaders) {
  const headers = new Map();
  for(let i=0;i<responseHeaders.length;i++) {
    headers.set(responseHeaders[i].name.toLowerCase(), responseHeaders[i].value);
  }
  return headers;
}

/**
 * param score: raw score based on all of the tests
 * return: the overall test score, grade and likelihood_indicator
 */
function get_grade_and_likelihood_for_score(_score) {
  const score = Math.max(_score, 0);  // can't have scores below 0.

  // If it's >100, just use the grade for 100, otherwise round down to the nearest multiple of 5
  const grade = GRADE_CHART[Math.min(score - score % 5, 100)];

  // If GRADE_CHART and LIKELIHOOD_INDICATOR_CHART are not synchronized during
  // manual code updates, then default to UNKNOWN

  let likelihood_indicator = null;
  if (Object.keys(LIKELIHOOD_INDICATOR_CHART).indexOf(grade[0]) > -1) {
    likelihood_indicator = grade[0];
  } else {
    likelihood_indicator = 'UNKNOWN';
  }
 

  return {
    score,
    grade,
    likelihood_indicator
  }

}

function clone(obj) {
  if (null == obj || "object" != typeof obj) return obj;
  var copy = obj.constructor();
  for (var attr in obj) {
      if (obj.hasOwnProperty(attr)) copy[attr] = clone(obj[attr]);
  }
  return copy;
}

function getDomain(url) {
	return url.split('://')[1].split('/')[0];
}

// Helper function
function intersect(arr1, arr2) {
  let a = new Set(arr1);
  let b = new Set(arr2);
  let intersection = new Set([...b].filter(x => a.has(x)));
  if ([...intersection].length > 0) {
    return true;
  } else {
    return false;
  }
}
// Test for space characters
function isSpace(aChar){
    myCharCode = aChar.charCodeAt(0);

    if(((myCharCode >  8) && (myCharCode < 14)) ||
        (myCharCode == 32))
    {
        return true;
    }

    return false;
}
// Ignore the CloudFlare __cfduid tracking cookies. They *are* actually bad, but it is out of a site's
// control.  See https://github.com/mozilla/http-observatory/issues/121 for additional details. Hopefully
// this will eventually be fixed on CloudFlare's end.

// Also ignore the Heroku sticky session cookie, see:
// https://github.com/mozilla/http-observatory/issues/282
const COOKIES_TO_DELETE = ['__cfduid', 'heroku-session-affinity'];

// CSP settings
const SHORTEST_DIRECTIVE = 'img-src';
const SHORTEST_DIRECTIVE_LENGTH = SHORTEST_DIRECTIVE.length - 1;  // the shortest policy accepted by the CSP test
/**
 *  Decompose the CSP; could probably do this in one step, but it's complicated enough
    Should look like:
    {
      'default-src': {'\'none\''},
      'object-src': {'\'none\''},
      'script-src': {'https://mozilla.org', '\'unsafe-inline\''},
      'style-src': {'\'self\', 'https://mozilla.org'},
      'upgrade-insecure-requests': {},
    }
 */
function parse_csp(csp_string) {
  // Clean out all the junk
  csp_string = csp_string.replace(/[\r\n]/g, '').trim();

  // So technically the shortest directive is img-src, so lets just assume that
  // anything super short is invalid
  if ((csp_string.length < SHORTEST_DIRECTIVE_LENGTH) || (isSpace(csp_string))) {
    throw new Error('CSP policy does not meet minimum length requirements');
  }

  // It's actually rather up in the air if CSP is case sensitive or not for directives, see:
  // https://github.com/w3c/webappsec-csp/issues/236
  // For now, we shall treat it as case-sensitive, since it's the safer thing to do, even though
  // Firefox, Safari, and Edge all treat them as case-insensitive.
  const csp = {}
  const entries = [];
  csp_string.split(';').forEach((directive) => {
    directive = directive.replace(/(^[ '\^\$\*#&]+)|([ '\^\$\*#&]+$)/g, '');
    if (directive.length > 0) {
      entries.push([directive.split(' ')]);
    }
  });

  
  entries.forEach((entry) => {
    let values = new Set();
    const directive = entry[0][0];
    // Technically the path part of any source is case-sensitive, but since we don't test
    // any paths, we can cheat a little bit here
    if (entry[0].length > 1) {
      entry[0].forEach( (source, idx) => {
        if (idx > 0) {
          values.add(source.toLowerCase());
        }
      });
    } else {
      values.add("'none'");
    };

    // While technically valid in that you just use the first entry, we are saying that repeated
    // directives are invalid so that people notice it
    if (Object.keys(csp).indexOf(directive) > -1) {
      throw new Error('Repeated policy directives are invalid');
    }
    else {
        csp[directive] = [...values];
    }
  });
  return csp;
}

/**
 *     :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        csp-implemented-with-no-unsafe: CSP implemented with no unsafe inline keywords [default]
        csp-implemented-with-unsafe-in-style-src-only: Allow the 'unsafe' keyword in style-src only
        csp-implemented-with-insecure-scheme-in-passive-content-only:
          CSP implemented with insecure schemes (http, ftp) in img/media-src
        csp-implemented-with-unsafe-inline: CSP implemented with unsafe-inline
        csp-implemented-with-unsafe-eval: CSP implemented with unsafe-eval
        csp-implemented-with-insecure-scheme: CSP implemented with having sources over http:
        csp-invalid-header: Invalid CSP header
        csp-not-implemented: CSP not implemented
    :return: dictionary with:
        data: the CSP lookup dictionary
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
 */
function content_security_policy(responseHeaders) {
  const output = {
    data: null,
    http: false,    // whether an HTTP header was available
    meta: false,    // whether an HTTP meta-equiv was available
    pass: false,
    policy: null,
    result: null,
    score: 0

  }
  // TODO: check for CSP meta tags
  // TODO: try to parse when there are multiple CSP headers

  // Obviously you can get around it with things like https://*.org, but you're only hurting yourself
  const DANGEROUSLY_BROAD = ['ftp:', 'http:', 'https:', '*', 'http://*', 'http://*.*', 'https://*', 'https://*.*'];
  const UNSAFE_INLINE = ['\'unsafe-inline\'', 'data:'];

  // Passive content check
  const PASSIVE_DIRECTIVES = ['img-src', 'media-src'];

  // What do nonces and hashes start with?
  const NONCES_HASHES = ['\'sha256-', '\'sha384-', '\'sha512-', '\'nonce-'];
  const headers = {};

  // TODO: Meta tags for CSP, currently we only check the HTTP header.
  try {
    headers.http = parse_csp(responseHeaders.get('content-security-policy')) || null;
  } catch (ee) {
    output.result = 'csp-header-invalid';
  }

  // If we have neither HTTP header nor meta, then there isn't any CSP
  if (Object.keys(headers).indexOf('http') === -1) {
    output.result = 'csp-not-implemented';
    output.score = SCORE_TABLE[output.result]['modifier'];
    return output;
  }

  // If we make it this far, we have a policy object
  output.policy = {
      antiClickjacking: false,
      defaultNone: false,
      insecureBaseUri: false,
      insecureFormAction: false,
      insecureSchemeActive: false,
      insecureSchemePassive: false,
      strictDynamic: false,
      unsafeEval: false,
      unsafeInline: false,
      unsafeInlineStyle: false,
      unsafeObjects: false,
  }

  // Store in our response object if we're using a header or meta
  output.http = true;
  const csp = headers.http;


  /* Since we only use http header now, the following snippet is commented.
    if headers['http'] and headers['meta']:
        # This is technically incorrect. It's very easy to see if a given resource will be allowed
        # given multiple policies, but it's extremely difficult to generate a singular policy to
        # represent this. For the purposes of the Observatory, we just create a union of the two
        # policies. This is incorrect, since if one policy had 'unsafe-inline' and the other one
        # did not, the policy would not allow 'unsafe-inline'. Nevertheless, we are going to flag
        # it, because the behavior is probably indicative of something bad and if the other policy
        # ever disappeared, then bad things could happen that had previously been prevented.
        csp = {}
        for k in set(list(headers['http'].keys()) + list(headers['meta'].keys())):
            csp[k] = headers['http'].get(k, set()).union(headers['meta'].get(k, set()))
    else:
        csp = headers['http'] or headers['meta']
  */

  // Get the various directives we look at

  const base_uri = csp['base-uri'] || `['*']`;
  const frame_ancestors = csp['frame-ancestors']|| `['*']`
  const form_action = csp['form-action'] || `['*']`;
  const object_src = new Set(csp['object-src'] || csp['default-src'] || `['*']`);
  const script_src = new Set(csp['script-src'] || csp['default-src'] || `['*']`);
  const style_src = new Set(csp['style-src'] || csp['default-src'] || `['*']`);

  // Now to make the piggies squeal

  // No 'unsafe-inline' or data: in script-src
  // Also don't allow overly broad schemes such as https: in either object-src or script-src
  // Likewise, if you don't have object-src or script-src defined, then all sources are allowed

  if (intersect(script_src, [].concat(DANGEROUSLY_BROAD, UNSAFE_INLINE))|| intersect(object_src, DANGEROUSLY_BROAD)) {
    if (output.result === null) {
      output['result'] = 'csp-implemented-with-unsafe-inline';
    }
    output['policy']['unsafeInline'] = true;
  }

  // Only if default-src is 'none' and 'none' alone, since additional uris override 'none'
  if (csp['default-src'] && csp['default-src'].indexOf(`'none'`) > -1){
    if (output.result === null) {
      output['result'] = 'csp-implemented-with-no-unsafe-default-src-none';
    }
    output['policy']['defaultNone'] = true;
  } else {
    if (output.result === null) {
      output['result'] = 'csp-implemented-with-no-unsafe';
    }
  }
  output.score = SCORE_TABLE[output.result]['modifier'];
  return output;
}

/** 
 *  :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        referrer-policy-private: Referrer-Policy header set to "no-referrer" or "same-origin", "strict-origin"
          or "strict-origin-when-origin"
        referrer-policy-no-referrer-when-downgrade: Referrer-Policy header set to "no-referrer-when-downgrade"
        referrer-policy-origin: Referrer-Policy header set to "origin"
        referrer-policy-origin-when-cross-origin: Referrer-Policy header set to "origin-when-cross-origin"
        referrer-policy-unsafe-url: Referrer-Policy header set to "unsafe-url"
        referrer-policy-not-implemented: Referrer-Policy header not implemented
        referrer-policy-header-invalid
    :return: dictionary with:
        data: the raw HTTP Referrer-Policy header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
 */
function referrer_policy(responseHeaders) {
  const output = {
    data: null,
    http: false,    // whether an HTTP header was available
    meta: false,    // whether an HTTP meta-equiv was available
    pass: false,
    result: null,
  } 
  const goodness = [
    'no-referrer',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin'
  ];

  const badness = [
    'origin',
    'origin-when-cross-origin',
    'unsafe-url'
  ];

  const valid = [
    'no-referrer',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'no-referrer-when-downgrade',
    'origin',
    'origin-when-cross-origin',
    'unsafe-url'
  ];

  // Meta not implemented yet.
  value = responseHeaders.get('referrer-policy') || null;
}

/**
 * 	expectation:
		hsts-implemented-max-age-at-least-six-months: HSTS implemented with a max age of at least six months (15768000)
		hsts-implemented-max-age-less-than-six-months: HSTS implemented with a max age of less than six months
		hsts-not-implemented-no-https: HSTS can't be implemented on http only sites
		hsts-not-implemented: HSTS not implemented
		hsts-header-invalid: HSTS header isn't parsable
		hsts-invalid-cert: Invalid certificate chain

  * return: object with:
		data: the raw HSTS header
		expectation: test expectation
		includesubdomains: whether the includeSubDomains directive is set
		pass: whether the site's configuration met its expectation
		preload: whether the preload flag is set
		result: short string describing the result of the test
 */
function strict_transport_security(secure, responseHeaders, domain) {
  const SIX_MONTHS = 15552000  // 15768000 is six months, but a lot of sites use 15552000, so a white lie is in order
  let value = null;
  const output = {
    data: null,
    includeSubDomains: false,
    'max-age': null,
    pass: false,
    preload: false,
    preloaded: false,
    result: 'hsts-not-implemented',
    score: 0
  }
  value = responseHeaders.get('strict-transport-security') || null;

  // If there's no HTTPS, we can't have HSTS.
  // TODO: Cert. valid or not.
  if (!secure) {
    output.result = 'hsts-not-implemented-no-https';
    output.score = SCORE_TABLE[output.result]['modifier'];
    return output;
  } else if (value === null) {
    output.result = 'hsts-not-implemented-no-https';
    output.score = SCORE_TABLE[output.result]['modifier'];
    return output;
  } else {
    output.data = value.substring(0,1024); // code against malicious headers

    try {
      if (output.data.indexOf(',') > -1) {
        throw new Error('value error');
      }
      const sts = output.data.split(';');
      sts.forEach(element => {
        const parameter = element.toLowerCase();
        if (parameter.startsWith('max-age=')) {
          output['max-age'] = parseInt(parameter.substring(8,128));
        } else if (parameter === 'includesubdomains') {
          output.includeSubDomains = true;
        } else if (parameter === 'preload') {
          output.preload = true;
        }
      });

      if (output['max-age']) {
        if (output['max-age'] < SIX_MONTHS) {
          output.result = 'hsts-implemented-max-age-less-than-six-months';
        } else {
          output.result = 'hsts-implemented-max-age-at-least-six-months';
        }
      } else {
        throw new Error('value error');
      }
      
    } catch (ee) {
      output.result = 'hsts-header-invalid';
    }
    
    // TODO: HSTS preload.
    if (HSTS_PRELOADED.indexOf(domain) > -1) {
      output.result = 'hsts-preloaded';
      output['preloaded'] = true;
    }
    // Check if the test passed.
    // Need to add the check for HSTS.
    if (output.result === 'hsts-implemented-max-age-at-least-six-months' || output.result === 'hsts-preloaded') {
      output.pass = true
    }
    output.score = SCORE_TABLE[output.result]['modifier'];
    return output;
  }
}

/**
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        x-content-type-options-nosniff: X-Content-Type-Options set to "nosniff" [default]
        x-content-type-options-not-implemented: X-Content-Type-Options header missing
        x-content-type-options-header-invalid
    :return: dictionary with:
        data: the raw X-Content-Type-Options header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
 */
function x_content_type_options(responseHeaders) {
  let value = null;
  const output = {
    data: null,
    pass: false,
    result: null,
  }
  
  value = responseHeaders.get('x-content-type-options') || null;


  if (value === null) {
    output.result = 'x-content-type-options-not-implemented';
  } else {
    output.data = value.substring(0,256); // code defensively
    if (output.data.toLowerCase().startsWith('nosniff')) {
      output.result = 'x-content-type-options-nosniff';
    } else {
      output.result = 'x-content-type-options-header-invalid';
    }
  }

  if (output.result === 'x-content-type-options-nosniff') {
    output.pass = true;
  }

  output.score = SCORE_TABLE[output.result]['modifier'];
  return output;
}

/**
 *     :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        x-xss-protection-enabled-mode-block: X-XSS-Protection set to "1; block" [default]
        x-xss-protection-enabled: X-XSS-Protection set to "1"
        x-xss-protection-not-needed-due-to-csp: no X-XSS-Protection header, but CSP blocks inline nonsense
        x-xss-protection-disabled: X-XSS-Protection set to "0" (disabled)
        x-xss-protection-not-implemented: X-XSS-Protection header missing
        x-xss-protection-header-invalid
    :return: dictionary with:
        data: the raw X-XSS-Protection header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
 */
function x_xss_protection(responseHeaders) {
  const VALID_DIRECTIVES = ['0', '1', 'mode', 'report'];
  const VALID_MODES = ['block'];
  let contentType = null;

  const output = {
    data: null,
    pass: false,
    result: null,
  }

  let enabled = false;  // XXSSP enabled or not
  let valid = true;     // XXSSP header valid or not
  let header = null;

  header = responseHeaders.get('x-xss-protection') || null;
  contentType = responseHeaders.get('content-type') || null;

  const xxssp = {}

  if (['text/css', 'image/png', 'image/x-icon'].indexOf(contentType) > -1) {
    output.score = 0;
    output.result = `xss-protection-not-needed-content-type-${contentType}`;
    return output;
  }
  
  if (header === null) {
    output.result = 'x-xss-protection-not-implemented'
  } else {
    output.data = header.trim().substring(0,256);

    try {
      if (['0', '1'].indexOf(header.trim().substring(0,1)) === -1) {
        throw new Error('value error');
      }

      if (header.substring(0,1) === '1') {
        enabled = true;
      }

      // Need to add checks for VALID_DIRECTIVES, VALID_MODES.
      header.toLowerCase().split(';').forEach( directive => {
        let k;
        let v;
        if (directive.indexOf('=') > -1) {
          k = directive.split('=')[0].trim();
          v = directive.split('=')[1].trim();
        } else {
          k = directive.trim();
          v = null;
        }

        // An invalid directive, like foo=bar
        if (VALID_DIRECTIVES.indexOf(k) === -1) {
          throw new Error('value error');
        }

        // An invalid mode, like mode=allow
        if (k === 'mode' && VALID_MODES.indexOf(v) === -1) {
          throw new Error('value error');
        }

        // A repeated directive, such as 1; mode=block; mode=block

        if (Object.keys(xxssp).indexOf(k) > -1) {
          throw new Error('value error');
        }

        xxssp[k] = v;
      });
    } catch(ee) {
      console.log("ERROR", ee);
      output.result = 'x-xss-protection-header-invalid';
      valid = false;
    }

    if (valid && enabled && xxssp['mode'] === 'block') {
      output.result = 'x-xss-protection-enabled-mode-block';
      output.pass = true;
    } else if (valid && enabled) {
      output.result = 'x-xss-protection-enabled';
      output.pass = true;
    } else if (valid && !enabled) {
      output.result = 'x-xss-protection-disabled'
    }
  }
  // Allow sites to skip out of having X-XSS-Protection if they implement a strong CSP policy
  // Note that having an invalid XXSSP setting will still trigger, even with a good CSP policy
  // TBD

  output.score = SCORE_TABLE[output.result]['modifier'];
  return output;
}

/**
    :param reqs: dictionary containing all the request and response objects
    :param expectation: test expectation
        x-frame-options-sameorigin-or-deny: X-Frame-Options set to "sameorigin" or "deny" [default]
        x-frame-options-allow-from-origin: X-Frame-Options set to ALLOW-FROM uri
        x-frame-options-implemented-via-csp: X-Frame-Options implemented via CSP frame-ancestors directive
        x-frame-options-not-implemented: X-Frame-Options header missing
        x-frame-options-header-invalid: Invalid X-Frame-Options header
    :return: dictionary with:
        data: the raw X-Frame-Options header
        expectation: test expectation
        pass: whether the site's configuration met its expectation
        result: short string describing the result of the test
 */
function x_frame_options(responseHeaders) {
  let value = null;
  const output = {
    data: null,
    pass: false,
    result: null,
  }

  value = responseHeaders.get('x-frame-options') || null;

  if (value === null) {
    output.result  = 'x-frame-options-not-implemented';
  } else {
    output.data = value.substring(0,1024);
    const xfo = output.data.toLowerCase();

    if (xfo === 'deny' || xfo === 'sameorigin') {
      output.result = 'x-frame-options-sameorigin-or-deny';
    } else if (xfo.startswith('allow-from ')) {
      output.result = 'x-frame-options-allow-from-origin';
    } else {
      output.result = 'x-frame-options-header-invalid';
    }

    // Need to integrate CSP here.
    if (output.result === 'x-frame-options-allow-from-origin' || 
      output.result === 'x-frame-options-sameorigin-or-deny') {
        output.pass = true;
      }
  }
  output.score = SCORE_TABLE[output.result]['modifier'];
  return output;
}

function parseHeaders(secure, responseHeaders, domain) {
  if (responseHeaders.length === 0) return undefined;
  const headerScores = {};
  let totalScore = 100; // It always needs to start with 100;

  headerScores.hsts = strict_transport_security(secure, responseHeaders, domain);
  headerScores.csp = content_security_policy(responseHeaders);
  headerScores['x-content-type-options'] = x_content_type_options(responseHeaders);
  headerScores.xxssp = x_xss_protection(responseHeaders);
  headerScores.xframe = x_frame_options(responseHeaders);
  Object.keys(headerScores).forEach( (key) => {
    totalScore += headerScores[key].score;
  });
  
	return {
    headerScores,
    totalScore
  }
}

// document.addEventListener("DOMContentLoaded", () => {
//	let content = document.getElementById("results");
  const domains = {};
  let headerResults;



function startParsing(request) {
  const currentDomain = getDomain(request.url);
  if (Object.keys(domains).indexOf(currentDomain) === -1) {
    // const text_div = document.createElement("div");
    let secure = false;
    if (request.url.startsWith('https://')) secure = true;
    const headers = convertHeaders(request.responseHeaders);
    headerResults = parseHeaders(secure, headers, currentDomain);
    
    // Add it to the dict of tabs.
    const tabID = request.tabId;
    const url = request.url;
    if (!tabSecurityScores.hasOwnProperty(tabID)) {
      tabSecurityScores[tabID] = {};
    }

    tabSecurityScores[tabID][url] = [
      url, 
      headerResults, 
      get_grade_and_likelihood_for_score(headerResults.totalScore),
      request.documentUrl,
      request.ip
    ];
  }
}


browser.webRequest.onHeadersReceived.addListener(
  startParsing,
  { urls : ["<all_urls>"] }, 
  ["responseHeaders"]
);

chrome.runtime.onConnect.addListener(function(port) {
  port.onMessage.addListener( (msg) => {
    chrome.tabs.query({active: true, lastFocusedWindow: true},(tabs) => {
      const tabLink = tabs[0].url;
      const tabID = msg.tabID;
      port.postMessage({tabLink, result: tabSecurityScores[tabID], agg: aggregateStats(msg.tabID)});
    });
  });
});


browser.runtime.onMessage.addListener((msg, sender, response) => {
  if (msg.type === 'sri') {
    console.log(msg);
    if (msg.status) {
      sriURLs = clone(msg.urls);
    }
  } else if (msg.url === '') {
    response({tabLink: msg.url, result: tabSecurityScores[msg.id], agg: aggregateStats(msg.id),  sri: sriURLs});
  } else {
    const result = tabSecurityScores[msg.id][msg.url] || tabSecurityScores[msg.id][msg.url.replace('www.', '')];
    response({tabLink: msg.url, result, agg: aggregateStats(msg.id)});
  }
});

function tabListener(tabId, changeInfo, tab) {
  try {
    if (changeInfo.status == 'complete' && tab.status == 'complete' && tab.url != undefined) {
        if (tab.url.startsWith('https://') || tab.url.startsWith('http://') || tab.url.startsWith('about:blank')) {
            // We should execute the content script, with runAt, instead of setting timeout in content script.
            chrome.tabs.executeScript(tabId, {file: './content.js', runAt: 'document_end', all_frames: true});
            // chrome.tabs.executeScript(tabId, {file: 'test.js', runAt: 'document_start'});
        }
    }
  } catch(ee){}
}

chrome.tabs.onUpdated.addListener(tabListener);