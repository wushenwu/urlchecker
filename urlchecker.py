# -*- coding: utf-8 -*-
import sys
import re
import socket
import pickle
import logging

try: 
    # Python 2
    from urllib2 import urlopen, URLError
    from urlparse import scheme_chars
except ImportError:
    # Python 3
    from urllib.request import urlopen
    from urllib.error import URLError
    from urllib.parse import scheme_chars
    unicode = str
    
LOG = logging.getLogger("urlchecker")
    
SCHEME_RE = re.compile(r'^([' + scheme_chars + ']+:)?//')
IP_RE = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

TLD_CACHED_FILE = 'tld_cache.dat'
ALEX_TOP_CACHED_FILE = 'alex_top_1m.txt'

def isip(host):
    try:
        socket.inet_aton(host)
        return True
    except AttributeError:
        if IP_RE.match(host):
            return False
    except socket.error:
        return False
    
def gethostinfo(url):
    '''
    https://tools.ietf.org/html/rfc3986
    https://tools.ietf.org/html/rfc1808
    
    <scheme>://<net_loc>/<path>;<params>?<query>#<fragment>
    
    <scheme>://<user>:<password>@<host>:<port>/<url-path>
    
     foo://example.com:8042/over/there?name=ferret#nose
         \_/   \______________/\_________/ \_________/ \__/
          |           |            |            |        |
       scheme     authority       path        query   fragment
          |   _____________________|__
         / \ /                        \
         urn:example:animal:ferret:nose

    the authority component is precended by a double slash ("//")
        and is terminated by the next slash ("/"), question mark ("?"), or number sign ("#") character
    
    '''
    netloc = SCHEME_RE.sub("", url) \
            .partition("/")[0] \
            .partition("?")[0] \
            .partition("#")[0] \
          # / ? and # as the end anchor

    hostport = netloc.split("@")[-1] # remove user, password
    (host, sep, port)= hostport.partition(":")
    return (host, port, isip(host))

def removeScheme(url):
    '''
    http://www.360.cn/xx.html ==> www.360.cn/xx.html
    https://www.360.cn/xx.html ==> www.360.cn/xx.html
    '''
    return SCHEME_RE.sub("", url)

def getTLDSByFly():
    '''
    download suffix dat from web and save to local cache.

    hackpoint: here use _PublicSuffixListSource as a function ptr, make it a convenient way to call someone.
    '''
    tld_sources = (_PublicSuffixListSource,)
    tlds = frozenset(tld for tld_source in tld_sources for tld in tld_source())

    try:
        with open(TLD_CACHED_FILE, 'wb') as f:
            pickle.dump(tlds, f)
    except IOError as e:
        LOG.warn("unable to cache TLDs in file %s: %s", TLD_CACHED_FILE, e)
    return tlds

def getTLDSByCache():
    tlds = frozenset()
    with open(TLD_CACHED_FILE) as f:
        tlds = pickle.load(f)
    return tlds

def getTLDS(isForceUpdate = False):
    tlds = frozenset()
    tlds = getTLDSByCache()
    if not tlds or isForceUpdate:
        tlds = getTLDSByFly()
    
    return tlds

def getAlexTopByCache():
    '''
    http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
    
    alex_top_1m.txt is the white domain

    if A is in alex_top_1m.txt, then we also consider www.A is also 
    '''
    alextop = set()
    with open(ALEX_TOP_CACHED_FILE) as fr:
        for line in fr:
            alextop.add(line.strip())
            alextop.add('www.' + line.strip())
    return alextop

def _fetch_page(url):
    try:
        return unicode(urlopen(url).read(), 'utf-8')
    except URLError as e:
        return u''
  
def _PublicSuffixListSource():
    page = _fetch_page('http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1')
  
    tld_finder = re.compile(r'^(?P<tld>[.*!]*\w[\S]*)', re.UNICODE | re.MULTILINE)
    tlds = [m.group('tld') for m in tld_finder.finditer(page)]
    return tlds

class _PublicSuffixListTLDExtractor:
    '''
    the core part: use tlds you've gotten by fly or from cache to extract info from netloc
    '''
    def __init__(self, tlds):
        self.tlds = tlds

    def extract(self, netloc):
        '''
        make sure netloc is valid, not the url
        
        return tuple(registered_domain, tld)
        '''
        spl = netloc.split('.')
        lower_spl = tuple(el.lower() for el in spl)
        for i in range(len(spl)):
            maybe_tld = '.'.join(lower_spl[i:])
            
            '''
            // ck : https://en.wikipedia.org/wiki/.ck
            *.ck
            !www.ck
            
            so, 
            www.ck ==> ('www', 'ck')
            any.ck ==> ('', 'any.ck')
            '''
            exception_tld = '!' + maybe_tld
            if exception_tld in self.tlds:
                return '.'.join(spl[:i+1]), '.'.join(spl[i+1:])

            if maybe_tld in self.tlds:
                return '.'.join(spl[:i]), '.'.join(spl[i:])

            wildcard_tld = '*.' + '.'.join(lower_spl[i+1:])
            if wildcard_tld in self.tlds:
                return '.'.join(spl[:i]), '.'.join(spl[i:])

        return netloc, ''
    
class URLChecker:
    '''
    frequently used methods:
    '''
    def __init__(self):
        self.tlds = getTLDS()
        self.alex_top = getAlexTopByCache()
        self.tld_extractor = _PublicSuffixListTLDExtractor(self.tlds)
    
    def isDirectInAlexTop(self, domain, host):
        '''
        @param: make sure that is the host

        if 360.cn in alextop, then 360.cn and www.360.cn will both in
        '''
        return host in self.alex_top

    def isIndirectInAlexTop(self, domain, host):
        '''
        if blogspot.com in alextop, then xx.blogspot.com will 'subin' or indirect in 
        '''
        if domain != host and self.isDirectInAlexTop(domain, domain):
            return True
        return False
 
    def removeCDN(self, oriurl):
        '''
        1)find the last FQDN
        2)if no FQDN exist, find the last ip
        
        #10.102.3.20/update/files/31710000007F3D77/down.myapp.com/myapp/smart_ajax/com.tencent.android.qqdownloader/991310_22331408_1451062634607.apk
            => down.myapp.com
            
101     #10.236.6.15/downloadw.inner.bbk.com/sms/upapk/0/com.bbk.appstore/20151009151923/com.bbk.appstore.apk
            => download.inner.bbk.com
        '''
        url = removeScheme(oriurl)
        
        #this may be an host, but need more check
        items = [item for item in url.split('/') if item.find('.') != -1 and item.find('&') == -1 and item.find('?') == -1]
        LOG.info('splitting %s', ' '.join(items))

        lastip = None
        for item in items[::-1]:
            host, port, domain, tld, isip, isvalidDomain = self.getHostInfo(oriurl=item, needremovecdn=False)
            if isvalidDomain and not isip:
                #the last FQDN as the host
                return ''.join(url.rpartition(host)[1:])  
            
            if isip and not lastip:
                lastip = host
                
        #if only has ip, then select the lastip 
        if lastip:
            return ''.join(url.rpartition(lastip)[1:])
                      
        return url 
       
    def getHostInfo(self, oriurl, needremovecdn = True):
        '''
        @param oriurl: can be a anything, netloc, or a whole url
        
               needremovecdn: 
                    
        @return: (host, port, domain, tld, isip, isvalidDomain)
        
        @note: 
            host is FQDN, or you can call submain, like www.360.cn, blogs.360.cn
            domain, like 360.cn
        
        http://www.baidu.com:8090/xx.html
            =>(www.baidu.com, 8090, baidu.com, www.baidu.com, com, false)
        '''
        isvalidDomain = True
        url = oriurl
        
        if needremovecdn:
            url = self.removeCDN(oriurl)
            
        (host, port, isip) = gethostinfo(url)
        if isip:
            return (host, port, host, '', isip, isvalidDomain)
        
        #www.360.cn  ==> ('www.360', 'cn')
        registered_domain, tld = self.tld_extractor.extract(host)
        subdomain, _, domain = registered_domain.rpartition('.')
        domain = '%s.%s'%(domain, tld)
        
        '''
        // ck : https://en.wikipedia.org/wiki/.ck
        *.ck
        !www.ck
            
        so do.ck 's tld is '.do.ck', 
            
        221.220.221.1998  's domain will be '1998.'
        
        thz invalid domain starts or ends with '.'
        '''
        if domain[0] == '.' or domain[-1] == '.':
            isvalidDomain = False
        
        return (host, port, domain, tld, isip, isvalidDomain)
    
    def doStat(self, filename):
        '''
        do statistics about all the urls within filename,

        filename.txt
            ==> filename.txt_domain.txt             all domains within filename.txt
                filename.txt_domain_hosts.txt       domain and its hosts info within filename
                filename.txt_white_direct.txt       all urls whose host is directly in alex_top_1m, there are absolute safe
                filename.txt_white_indirect.txt     all urls whose host is indirectly in alex_top_1m, there are probably safe
                filename.txt_black.txt              all urls whose host is not in alex_top_1m, there are unknown, gray, or black
                                                        need to be checked
        '''
        fw_white_direct = open(filename + '_white_direct.txt', 'wb')
        fw_white_indirect = open(filename + '_white_indirect.txt', 'wb')
        fw_unknown = open(filename + '_unknown.txt', 'wb')

        d_domain_hosts = {} # {domain:[hosts, hosts,...]}
        with open(filename, 'rb') as fr:
            for line in fr:
                host, port, domain, tld, isip, isvalidDomain = self.getHostInfo(line.strip())
                d_domain_hosts.setdefault(domain, set()).add(host)

                if self.isDirectInAlexTop(domain, host):
                    fw_white_direct.write(line)
                elif self.isIndirectInAlexTop(domain, host):
                    fw_white_indirect.write(line)
                else:
                    fw_unknown.write(line)
        fw_white_direct.close()
        fw_white_indirect.close()
        fw_unknown.close()
            
        fw_domain = open(filename + '_domain.txt', 'wb')    
        fw_domain_hosts = open(filename + '_domain_hosts.txt', 'wb')
        for domain in d_domain_hosts:
            invalidHit = '\n'
            if domain[0] == '.' or domain[-1] == '.':
                invalidHit = '\t_invalid_\n' 
                                
            fw_domain.write('%s%s'%(domain, invalidHit))
            fw_domain_hosts.write('%s\t%d\t_domain_%s'%(domain, len(d_domain_hosts[domain]), invalidHit))
            
            for host in d_domain_hosts[domain]:
                fw_domain_hosts.write('\t%s\n'%host)
                
        fw_domain.close()
        fw_domain_hosts.close()
      
def main():
    objURLCheck = URLChecker()
    #print objURLCheck.getHostInfo(sys.argv[1])
    objURLCheck.doStat(sys.argv[1])
    #print objURLCheck.removeCDN(sys.argv[1])

if __name__ == "__main__":
    main()
