import requests
import json
import sublist3r
from provider import providers
import dns.resolver
import wappalyze as w
from utils import func as f

urls=[]
takeover_urls=[]
screenshot_urls=[]
alive_urls=[]
data={}
class subdomain:
    def alienvault(self,url):
        global urls
        search=f'https://otx.alienvault.com/api/v1/indicators/domain/{url}/passive_dns'
        response=requests.get(search)
        data=json.loads(response.text)
        for i in range(data["count"]):
            urls.append(data["passive_dns"][i]["hostname"])
        urls=list(set(urls))        
        print(urls)

    def crtsh(self,url):
        global urls
        search=f'https://crt.sh/?q={url}&output=json'
        response=requests.get(search)
        data=json.loads(response.text)
        res = [ sub['name_value'] for sub in data ]
        res=list(dict.fromkeys(res))
        for ele in res:
            ele1=ele.split("\n")
            for x in ele1:
                urls.append(x)
        urls=list(set(urls)) 
        print(urls)
    
    def sublister(self,url):
        global urls
        subdomains = sublist3r.main(url, 40 ,savefile=False, ports=None, silent=True, verbose= False, enable_bruteforce=False,engines=None)
        for x in subdomains:
            urls.append(x)
        urls=list(set(urls)) 

    def screenshot(self,urls):
        global screenshot_urls
        for url in urls:
            url='https://www.googleapis.com/pagespeedonline/v2/runPagespeed?screenshot=true&url=http://'+ url
            response=requests.get(url)
            data=json.loads(response.text)
            try:
                screenshot_urls.append(str(data.get("screenshot",None).get('data',None)))
                print(screenshot_urls)
            except:
                screenshot_urls.append("Error")
        print(screenshot_urls)

    def subtakeover(self,subdomains):
        global takeover_urls
        takeover_urls.clear()
        for subdomain in subdomains:
            try:
                answer=dns.resolver.query(subdomain, "CNAME")
                for i in answer:
                    cname=str(i)
            except:
               cname=''
            try:
                data=requests.get('http://'+subdomain,timeout=10).text
            except:
                data=''
            for k in providers.provider:
                c=False
                r=False
                p=False
                for cn in k['cname']:
                    if cn in cname:
                        c=True
                        print('cname match')
                for res in k['response']:
                    print
                    if res in data:
                        print('response match')
                        r=True
                if c or r:
                    p=True
                    if p:
                        print(subdomain+' may be vulnerable to takeover')
                        print("CName - "+cname)
                        takeover_urls.append(subdomain)
                else:
                    p=False
                    continue
                
        return takeover_urls
    
    def alive(self,urls):
        global alive_urls,data
        alive_urls.clear()
        data.clear()
        print(urls)
        c=0
        for url in urls:
            try:
                url='http://'+url
                response=requests.get(url)
                if response.status_code==200 or response.status_code==302:
                    c=c+1
                    alive_urls.append(url)
                    data[c]={}
                    data[c]["url"]=url
                    scripts=f.script_extractor(response.text)
                    js=f.js_extractor(response.text)
                    wap=w.wappalyzer(response,scripts,js)
                    waps=','.join(list(set(wap)))
                    data[c]["technologies"]=waps


            except:
                pass
        return alive_urls,data

    def all(self,url):
        global urls
        urls.clear()
        try:
            pass
 #           subdomain().sublister(url)
        except:
            print("sublist3r failed")
        
        try:
            subdomain().crtsh(url)
        except:
            print("crtsh failed")
        
        try:
            subdomain().alienvault(url)
        except:
            print("alienvault failed")
        
        return urls
    

