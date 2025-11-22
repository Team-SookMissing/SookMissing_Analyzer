import re
import tldextract
from urllib.parse import urlparse
import ipaddress

SHORTENED_DOMAINS = [
    "bit.ly","kl.am","cli.gs","bc.vc","po.st","v.gd","bkite.com","shorl.com",
    "scrnch.me","to.ly","adf.ly","x.co","1url.com","ad.vu","migre.me","su.pr",
    "smallurl.co","cutt.us","filoops.info","shor7.com","yfrog.com","tinyurl.com",
    "u.to","ow.ly","ff.im","rubyurl.com","r2me.com","post.ly","twitthis.com",
    "buzurl.com","cur.lv","tr.im","bl.lnk","tiny.cc","lnkd.in","q.gs","is.gd",
    "hurl.ws","om.ly","prettylinkpro.com","qr.net","qr.ae","snipurl.com","ity.im",
    "t.co","db.tt","link.zip.net","doiop.com","url4.eu","poprl.com","tweez.me",
    "short.ie","me2.do","bit.do","shorte.st","go2l.ink","yourls.org","wp.me",
    "goo.gl","j.mp","twurl.nl","snipr.com","shortto.com","vzturl.com","u.bb",
    "shorturl.at","han.gl","wo.gl","wa.gl"
]

SUSPICIOUS_TLD= [
    "xyz","top","click","link","work","loan","online","shop","site","store","wiki", "mom","xyz", "top"
]


def extract_urls(text: str):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$\-@\.&+:/?=]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    urls = re.findall(url_pattern, text)
    return list(set(urls))


def analyze_url_pattern(url:str) -> dict:
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        extract = tldextract.extract(url)
        domain = f"{extract.domain}.{extract.suffix}"

        score = 0
        reasons=[]


        if url.startswith("http://"):
            score += 5
            reasons.append("보안 미적용 사이트")


        if domain.lower() in SHORTENED_DOMAINS:
            score += 5
            reasons.append("단축 URL 사용(사이트 숨김)")


        if extract.suffix in SUSPICIOUS_TLD:
            score += 15
            reasons.append(f"신뢰할 수 없는 도메인(.{extract.suffix})")


        try:
            ipaddress.ip_address(host)
            score += 20
            reasons.append("IP 주소로 직접 연결하는 비정상 경로")
        except: 
            pass

        if score > 30:
            score = 30

        return {
            "url" : url,
            "score": score,
            "reasons": reasons
        }
    except Exception as e:
        return {"url": url, "score": 0, "reasons": [f"URL 분석 오류: {str(e)}"]}

