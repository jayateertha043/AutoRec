import requests
import json
import sublist3r
from provider import providers
import dns.resolver
import wappalyze as w
from utils import func as f
from report_const import html_start,html_end
import os.path
from slack import sendfiletoslack,sendmessage

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
    

    def report(self,url):
        report_urls=self.all(url)
        print("url:completed")
        print(report_urls)
        report_alive_urls,report_alive=self.alive(report_urls)
        print(report_alive_urls)
        report_takeover=self.subtakeover(report_urls)
        print("takeover:complete")
        print(report_takeover)

        html_subdomains='<p class="dahead">Subdomains:</p><br><table>'
        for u in report_urls:
            html_subdomains=html_subdomains+f'''<tr>
            <td>
           <a class="ahead" href="http://{u}">{u}</a></td>
            </tr>'''
        html_subdomains=html_subdomains+'</table>'
        html_alive=f'<p class="dahead">Alive:{len(report_alive)}/{len(report_urls)}</p></br>'
        html_alive=html_alive+'<table class="text-center" align="center" style="margin: 0px auto;width:80%;border: 1px solid black;background-color: cornflowerblue"><tr><th>SNO</th><th>HOST</th><th>Technologies Used</th></tr>'
        
        for key,value in report_alive.items():
            html_alive=html_alive+f'''
        <tr>
            <td class="ahead">{key}</td>
            <td>
           <a class="ahead" href="http://{value["url"]}">{value["url"]}</a></td>
           
           <td class="ahead">{value["technologies"]}</td>
            </tr>'''
        html_alive=html_alive+'</table><br>'

        html_takeover='<p class="dahead">Possible Subdomain Takeovers:</p><table></br>'

        for t in report_takeover:
            html_takeover=html_takeover+f'''<tr>
            <td>
           <a class="ahead" href="http://{t}"></a></td>
            </tr>'''
        html_takeover=html_takeover+'</table>'

        html_final=html_start+html_subdomains+html_alive+html_takeover+html_end
        print("writing to file")
        filename=f"{url}.html"
        directory = './reports/'
        if not os.path.isdir(directory):
            os.mkdir(directory)
        file_path = os.path.join(directory, filename)
        with open(file_path,'w') as html_file:  
            html_file.write(html_final)
        print("write success")
        try:
            if(sendfiletoslack(filename,file_path)):
                print("file sent removing now")
                remove_file='./reports/'+filename
                print(remove_file)
                try:
                    os.remove(remove_file)
                except:
                    print("file not present or file creation failed")
            try:
                os.remove(file_path)
            except:
                print("file not present or file creation failed")
            
        except:
            sendmessage()
            print("something Wrong either coulnt remove local file or slack error")
            




            
        
