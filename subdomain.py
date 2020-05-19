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
import time
import pydf
from sys import platform
try:
    from configs import APIKEY
except:
    from config import APIKEY

urls=[]
takeover_urls=[]
screenshot_urls=[]
alive_urls=[]
data={}
report_alive={}
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
        global report_alive
        c=1
        for url in urls:
            temp=url
            url=f'https://www2png.com/api/capture/{APIKEY}?url=https://'+ url           
            response=requests.get(url)
            if 'error' in response.text:
                url=f'https://www2png.com/api/capture/{APIKEY}?url=http://'+ temp
                response=requests.get(url)
            r=json.loads(response.text)
            if r["image_url"]:
                surl=r["image_url"]
            else:
                surl='error'
            print(surl)
            print(report_alive)
            report_alive[c]["image"]=surl
            c=c+1


    def subtakeover(self,subdomains):
        global takeover_urls,alive_urls,data
        alive_urls.clear()
        data.clear()
        c=0
        takeover_urls.clear()
        text=''
        for subdomain in subdomains:
            try:
                answer=dns.resolver.query(subdomain, "CNAME")
                for i in answer:
                    cname=str(i)
            except:
               cname=''
            try:
                try:
                    response=requests.get('http://'+subdomain)
                    text=response.text
                except:
                    response=requests.get('https://'+subdomain)
                    text=response.text
                if response.status_code==200 or response.status_code==302 or response.status_code==301:
                    c=c+1
                    alive_urls.append(subdomain)
                    data[c]={}
                    data[c]["url"]=subdomain
                    scripts=f.script_extractor(text)
                    js=f.js_extractor(text)
                    wap=w.wappalyzer(response,scripts,js)
                    waps=','.join(list(set(wap)))
                    data[c]["technologies"]=waps
                    data[c]["image"]=''
#                    data[c]["cname"]=cname
            except:
                text=''
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
                    if res in text:
                        print('response match')
                        r=True
                if c or r:
                    p=True
                    if p:
                        print(subdomain+'may be vulnerable to takeover')
                        print("CName - "+cname)
                        takeover_urls.append(subdomain)
                else:
                    p=False
                    continue
                
        return alive_urls,data,takeover_urls
    

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
        global report_alive
        start=time.time()
        report_urls=self.all(url)
        print("url:completed")
        print("total:"+str(len(report_urls)))
        report_alive_urls,report_alive,report_takeover=self.subtakeover(report_urls)
        self.screenshot(report_alive_urls)
        print("Completed alive and takeover")


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
           <td class="ahead"><a href="{value["image"]}"><img src={value["image"]} height=212px width=50px/></a></td>
            </tr>'''
        html_alive=html_alive+'</table><br>'

        html_takeover='<p class="dahead">Possible Subdomain Takeovers:</p><table></br>'

        for t in report_takeover:
            html_takeover=html_takeover+f'''<tr>
            <td>
           <a class="ahead" href="http://{t}">{t}</a></td>
            </tr>'''
        html_takeover=html_takeover+'</table>'
        end=time.time()
        total_time=(end-start)/60
        html_time=f'<p style="color:white">Report Generated in:{total_time} mins</p><br>'
        html_final=html_start+html_time+html_subdomains+html_alive+html_takeover+html_end
        print("writing to file")
        filename=f"{url}.html"
        pdffilename=f"{url}.pdf"
        directory = './reports/'
        if not os.path.isdir(directory):
            os.mkdir(directory)
        file_path = os.path.join(directory, filename)
        pdffile_path=os.path.join(directory, pdffilename)
        pdfremove_file='./reports/'+pdffilename
        with open(file_path,'w') as html_file:  
            html_file.write(html_final)
            print("html write success")
        if platform == "linux" or platform == "linux2":
            print("writing pdf")
            pdf = pydf.generate_pdf(html_final)
            with open(pdffile_path, 'wb') as f:
                f.write(pdf)
                sendfiletoslack(pdffilename,pdffile_path)
            os.remove(pdfremove_file)

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
            msg="something Wrong either coudn't remove local file or slack error"
            sendmessage(msg)
            print("something Wrong either coulnt remove local file or slack error")
            




            
        
