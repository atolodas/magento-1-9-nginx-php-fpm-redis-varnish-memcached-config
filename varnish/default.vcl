C{
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
static pthread_mutex_t lrand_mutex = PTHREAD_MUTEX_INITIALIZER;
void generate_uuid(char* buf) {
pthread_mutex_lock(&lrand_mutex);
long a = lrand48();
long b = lrand48();
long c = lrand48();
long d = lrand48();
pthread_mutex_unlock(&lrand_mutex);
sprintf(buf, "frontend=%08lx%04lx%04lx%04lx%04lx%08lx",
a,
b & 0xffff,
(b & ((long)0x0fff0000) >> 16) | 0x4000,
(c & 0x0fff) | 0x8000,
(c & (long)0xffff0000) >> 16,
d
);
return;
}
}C
import std;
backend default {
.host = "127.0.0.1";
.port = "8080";
.first_byte_timeout = 300s;
.between_bytes_timeout = 300s;
}
backend admin {
.host = "127.0.0.1";
.port = "8080";
.first_byte_timeout = 21600s;
.between_bytes_timeout = 21600s;
}
#alterado - remove acl crawler
#acl crawler_acl {
#"177.71.179.47";
#}
acl debug_acl {
}
/* -- REMOVED
sub generate_session {
if (req.url ~ ".*[&?]SID=([^&]+).*") {
set req.http.X-Varnish-Faked-Session = regsub(
req.url, ".*[&?]SID=([^&]+).*", "frontend=\1");
} else {
C{
char uuid_buf [50];
generate_uuid(uuid_buf);
VRT_SetHdr(sp, HDR_REQ,
"\030X-Varnish-Faked-Session:",
uuid_buf,
vrt_magic_string_end
);
}C
}
if (req.http.Cookie) {
std.collect(req.http.Cookie);
set req.http.Cookie = req.http.X-Varnish-Faked-Session +
"; " + req.http.Cookie;
} else {
set req.http.Cookie = req.http.X-Varnish-Faked-Session;
}
}
sub generate_session_expires {
C{
time_t now = time(NULL);
struct tm now_tm = *gmtime(&now);
now_tm.tm_sec += 86400;
mktime(&now_tm);
char date_buf [50];
strftime(date_buf, sizeof(date_buf)-1, "%a, %d-%b-%Y %H:%M:%S %Z", &now_tm);
VRT_SetHdr(sp, HDR_RESP,
"\031X-Varnish-Cookie-Expires:",
date_buf,
vrt_magic_string_end
);
}C
}
-- */
sub vcl_recv {

#adicionado soketweb
if (req.http.Upgrade ~ "(?i)websocket") {
         return (pipe);
}

#alterado - adicionei rules de segurana
include "/etc/varnish/seguro";
include "/etc/varnish/seguroag";

if (req.restarts == 0) {
if (req.http.X-Forwarded-For) {
	#alterado - tirei ip a  mais 
	set req.http.X-Forwarded-For = req.http.X-Forwarded-For; #+ ", " + client.ip;
} else {
	set req.http.X-Forwarded-For = client.ip;
}
}
if(false) {
set req.http.X-Varnish-Origin-Url = req.url;
}
if (req.http.Accept-Encoding) {
if (req.http.Accept-Encoding ~ "gzip") {
set req.http.Accept-Encoding = "gzip";
} else if (req.http.Accept-Encoding ~ "deflate") {
set req.http.Accept-Encoding = "deflate";
} else {
unset req.http.Accept-Encoding;
}
}
if (!true || req.http.Authorization ||
req.request !~ "^(GET|HEAD|OPTIONS)$" ||
req.http.Cookie ~ "varnish_bypass=1") {
if (req.url ~ "^(/media/|/skin/|/js/|/)(?:(?:index|litespeed)\.php/)?admin|blog_admin|api|oauth|soap|wsdl|itaushopline|atendimento-online-2/.*") {
set req.backend = admin;
}
return (pipe);
}
set req.url = regsuball(req.url, "([^:])//+", "\1/");
if (req.url ~ "^(/media/|/skin/|/js/|/)(?:(?:index|litespeed)\.php/)?") {
set req.http.X-Turpentine-Secret-Handshake = "1";
if (req.url ~ "^(/media/|/skin/|/js/|/)(?:(?:index|litespeed)\.php/)?admin") {
set req.backend = admin;
return (pipe);
}
if (req.http.Cookie ~ "\bcurrency=") {
set req.http.X-Varnish-Currency = regsub(
req.http.Cookie, ".*\bcurrency=([^;]*).*", "\1");
}
if (req.http.Cookie ~ "\bstore=") {
set req.http.X-Varnish-Store = regsub(
req.http.Cookie, ".*\bstore=([^;]*).*", "\1");
}
if (req.url ~ "/turpentine/esi/get(?:Block|FormKey)/") {
set req.http.X-Varnish-Esi-Method = regsub(
req.url, ".*/method/(\w+)/.*", "\1");
set req.http.X-Varnish-Esi-Access = regsub(
req.url, ".*/access/(\w+)/.*", "\1");
if (req.http.X-Varnish-Esi-Method == "esi" && req.esi_level == 0 &&
!(false || client.ip ~ debug_acl)) {
error 403 "External ESI requests are not allowed";
}
}
if (req.http.Cookie !~ "frontend=" && !req.http.X-Varnish-Esi-Method) {
#if (req.http.User-Agent ~ "^(?:ApacheBench/.*|.*Googlebot.*|.*bingbot.*|msnbot/.*|adidxbot/.*)$") {
if (req.http.User-Agent ~ "^(?:ApacheBench/.*|.*GTmetrix.*|.*Googlebot.*|.*JoeDog/.*Siege.*|magespeedtest\.com|Nexcessnet_Turpentine/.*|.*bingbot.*|msnbot/.*|adidxbot/.*)$") {
set req.http.Cookie = "frontend=crawler-session";
} else {
return (pipe);
}
}
#if (req.url ~ ".*\.(?:css|js|jpe?g|png|gif|ico|swf|woff)(?=\?|&|$)") {
if (req.url ~ "\.(css|js|png|gif|jp(e)?g|swf|ico|ttf|otf|wof|woff)(?=\?|&|$)") {
unset req.http.Cookie;
unset req.http.X-Varnish-Faked-Session;
return (pass);

}
if (req.url ~ "^(/media/|/skin/|/js/|/)(?:(?:index|litespeed)\.php/)?(?:admin|api|oauth|soap|wsdl|cron\.php|shipping/.*|checkout/.*|customer/.*|onestepcheckout/.*|pagseguro/.*|pseguro/.*|ajax/.*|downloadable/.*|newsletter/.*|oauth/.*|review/.*|sales/.*|downloader/.*|monkey/.*|atendimento-online-2/.*|adminhtml_optimizer/.*|itaushopline/.*|blog_admin/.*)" ||
req.url ~ "\?.*__from_store=") {
return (pipe);
}
if (true &&
req.url ~ "(?:[?&](?:__SID|XDEBUG_PROFILE)(?=[&=]|$))") {
return (pass);
}
if (true && req.url ~ "[?&](utm_source|utm_medium|utm_campaign|utm_content|utm_term|gclid|cx|ie|cof|siteurl)=") {
set req.url = regsuball(req.url, "(?:(\?)?|&)(?:utm_source|utm_medium|utm_campaign|utm_content|utm_term|gclid|cx|ie|cof|siteurl)=[^&]+", "\1");
set req.url = regsuball(req.url, "(?:(\?)&|\?$)", "\1");
}
if(false) {
set req.http.X-Varnish-Cache-Url = req.url;
set req.url = req.http.X-Varnish-Origin-Url;
unset req.http.X-Varnish-Origin-Url;
}
return (lookup);
}
}
sub vcl_pipe {

#adicionado suporte ao web soket
if (req.http.upgrade) {
   set bereq.http.upgrade = req.http.upgrade;
}

unset bereq.http.X-Turpentine-Secret-Handshake;
set bereq.http.Connection = "close";
}
sub vcl_hash {
if(false && req.http.X-Varnish-Cache-Url) {
hash_data(req.http.X-Varnish-Cache-Url);
} else {
hash_data(req.url);
}
if (req.http.Host) {
hash_data(req.http.Host);
} else {
hash_data(server.ip);
}
hash_data(req.http.Ssl-Offloaded);
if (req.http.X-Normalized-User-Agent) {
hash_data(req.http.X-Normalized-User-Agent);
}
if (req.http.Accept-Encoding) {
hash_data(req.http.Accept-Encoding);
}
if (req.http.X-Varnish-Store || req.http.X-Varnish-Currency) {
hash_data("s=" + req.http.X-Varnish-Store + "&c=" + req.http.X-Varnish-Currency);
}
if (req.http.X-Varnish-Esi-Access == "private" &&
req.http.Cookie ~ "frontend=") {
hash_data(regsub(req.http.Cookie, "^.*?frontend=([^;]*);*.*$", "\1"));
hash_data(req.http.User-Agent);
}
if (req.http.X-Varnish-Esi-Access == "customer_group" &&
req.http.Cookie ~ "customer_group=") {
hash_data(regsub(req.http.Cookie, "^.*?customer_group=([^;]*);*.*$", "\1"));
}
return (hash);
}
sub vcl_hit {
}
sub vcl_fetch {
set req.grace = 15s;
set beresp.http.X-Varnish-Host = req.http.host;
set beresp.http.X-Varnish-URL = req.url;
if (req.url ~ "^(/media/|/skin/|/js/|/)(?:(?:index|litespeed)\.php/)?") {
unset beresp.http.Vary;
set beresp.do_gzip = true;
if (beresp.status != 200 && beresp.status != 404) {
set beresp.ttl = 15s;
return (hit_for_pass);
} else {
if (beresp.http.Set-Cookie) {
set beresp.http.X-Varnish-Set-Cookie = beresp.http.Set-Cookie;
unset beresp.http.Set-Cookie;
}
unset beresp.http.Cache-Control;
unset beresp.http.Expires;
unset beresp.http.Pragma;
unset beresp.http.Cache;
unset beresp.http.Age;
if (beresp.http.X-Turpentine-Esi == "1") {
set beresp.do_esi = true;
}

if (beresp.http.X-Turpentine-Cache == "0") {
set beresp.ttl = 15s;
return (hit_for_pass);
} else {

if (req.url ~ "\.(css|js|png|gif|jp(e)?g|swf|ico|ttf|otf|wof|woff)(?=\?|&|$)") {
#if (bereq.url ~ ".*\.(?:css|js|jpe?g|png|gif|ico|swf)(?=\?|&|$)") {
set beresp.storage = "static";
set beresp.http.x-storage = "static";
set beresp.ttl = 2828000s;
set beresp.http.Cache-Control = "max-age=2828000";
set beresp.http.Expires = beresp.ttl;
set beresp.http.Programa = "Public";
unset beresp.http.Cookie;
unset beresp.http.set-cookie;
} elseif (req.http.X-Varnish-Esi-Method) {
if (req.http.X-Varnish-Esi-Access == "private" &&
req.http.Cookie ~ "frontend=") {
set beresp.http.X-Varnish-Session = regsub(req.http.Cookie,
"^.*?frontend=([^;]*);*.*$", "\1");

set beresp.storage = "default";
set beresp.http.x-storage = "default";

}
if (req.http.X-Varnish-Esi-Method == "ajax" &&
req.http.X-Varnish-Esi-Access == "public") {
set beresp.http.Cache-Control = "max-age=" + regsub(
req.url, ".*/ttl/(\d+)/.*", "\1");
set beresp.storage = "default";
set beresp.http.x-storage = "default";

}
set beresp.ttl = std.duration(
regsub(
req.url, ".*/ttl/(\d+)/.*", "\1s"),
300s);
if (beresp.ttl == 0s) {
set beresp.ttl = 15s;
return (hit_for_pass);
}
} else {
set beresp.ttl = 86400s;
}
}
}

if (bereq.url ~ "\.(css|js|png|gif|jp(e?)g)|swf|ico|wof") {
                #unset beresp.http.cookie;
                unset beresp.http.set-cookie;
                set beresp.storage = "static";
                set beresp.http.x-storage = "static";
                set beresp.ttl = 24h;
} else {
               set beresp.storage = "default";
               set beresp.http.x-storage = "default";
}



return (deliver);
}
}

sub vcl_deliver {
if (req.http.X-Varnish-Faked-Session) {
	set resp.http.Set-Cookie = req.http.X-Varnish-Faked-Session +"; expires=" + resp.http.X-Varnish-Cookie-Expires + "; path=/";
	if (req.http.Host) {
		if (req.http.User-Agent ~ "^(?:ApacheBench/.*|.*Googlebot.*|.*JoeDog/.*Siege.*|.*bingbot.*|msnbot/.*|adidxbot/.*)$") {
		#if (req.http.User-Agent ~ "^(?:ApacheBench/.*|.*GTmetrix.*|.*Googlebot.*|magespeedtest\.com|.*bingbot.*|msnbot/.*|adidxbot/.*)$") {
			set resp.http.Set-Cookie = resp.http.Set-Cookie +"; domain=" + regsub(req.http.Host, ":\d+$", "");
		} else {
		if(req.http.Host ~ "") {
			set resp.http.Set-Cookie = resp.http.Set-Cookie +"; domain=";
		} else {
			set resp.http.Set-Cookie = resp.http.Set-Cookie +"; domain=" + regsub(req.http.Host, ":\d+$", "");
		}
	}
}
set resp.http.Set-Cookie = resp.http.Set-Cookie + "; httponly";
unset resp.http.X-Varnish-Cookie-Expires;
}
if (req.http.X-Varnish-Esi-Method == "ajax" && req.http.X-Varnish-Esi-Access == "private") {
set resp.http.Cache-Control = "no-cache";
}
if (false || client.ip ~ debug_acl) {
#if (true) {
set resp.http.X-Varnish-Hits = obj.hits;
set resp.http.X-Varnish-Esi-Method = req.http.X-Varnish-Esi-Method;
set resp.http.X-Varnish-Esi-Access = req.http.X-Varnish-Esi-Access;
set resp.http.X-Varnish-Currency = req.http.X-Varnish-Currency;
set resp.http.X-Varnish-Store = req.http.X-Varnish-Store;
} else {
unset resp.http.X-Varnish;
unset resp.http.Via;
unset resp.http.X-Powered-By;
unset resp.http.Server;
unset resp.http.X-Turpentine-Cache;
unset resp.http.X-Turpentine-Esi;
unset resp.http.X-Turpentine-Flush-Events;
unset resp.http.X-Turpentine-Block;
unset resp.http.X-Varnish-Session;
unset resp.http.X-Varnish-Host;
unset resp.http.X-Varnish-URL;
unset resp.http.X-Varnish-Set-Cookie;
}
}
