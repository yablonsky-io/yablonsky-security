(function(){
'use strict';
var nodes=document.querySelectorAll('[data-ysec-captcha-provider]');
if(!nodes.length){return;}
var provider=nodes[0].getAttribute('data-ysec-captcha-provider')||'';
var id=provider==='turnstile'?'ysec-turnstile-provider':'ysec-recaptcha-provider';
if(document.getElementById(id)){return;}
var src=provider==='turnstile'?'https://challenges.cloudflare.com/turnstile/v0/api.js':'https://www.google.com/recaptcha/api.js';
var script=document.createElement('script');
script.id=id;script.src=src;script.async=true;script.defer=true;script.referrerPolicy='strict-origin-when-cross-origin';
document.head.appendChild(script);
}());
