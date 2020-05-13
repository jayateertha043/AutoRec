from flask import Flask, request, render_template ,url_for,redirect
from subdomain import subdomain as s
app = Flask(__name__)
urls=[]
subtakeover_urls=[]
alive_urls=[]
@app.route('/',methods=['GET'])
def myHome():
    if request.method == 'GET':
        return render_template('index.html')
    else :
        return 'wrong method'
@app.route('/output',methods=['GET','POST'])
def output():
    global urls
    if request.method=='POST':
        url=''
        if request.form['search']:
            url=request.form['search']
            try:
                urls=s().all(url)
                return render_template('output.html',urls=urls,loaded=True)
            except:
                return render_template('index.html')
    else:
        return 'wrong method'

@app.route('/subdomains',methods=['GET'])
def subdomains():
    global urls
    return render_template('subdomains.html',urls=urls,loaded=False)

@app.route('/takeovers',methods=['GET'])
def takeovers():
    global urls,subtakeover_urls
    subtakeover_urls.clear()
    subtakeover_urls=s().subtakeover(urls)
    return render_template('takeovers.html',urls=urls,loaded=False)

@app.route('/alive',methods=['GET'])
def alive():
    global urls,alive_urls
    alive_urls.clear()
    alive_urls,data=s().alive(urls)
    print (data)
    return render_template('alive.html',data=data,urls=urls,loaded=False)