import requests
from configs import token,channel

def sendfiletoslack(filename,filepath):
    
    url = "https://slack.com/api/files.upload"

    querystring = {"token":token}


    target = {
    "channels":channel
    }

    file_upload = {
    "file":(filename, open(filepath, 'rb'),)
    }


    response = requests.post(url, data=target, params=querystring, files=file_upload)
    print(response.text)
    if response.status_code==200 and "ok:true" in response.text:
        return True
    return False

def sendmessage(msg):
    print("inside send message")
    data = {
    'token': token,
    'channel': channel,    
    'as_user': True,
    'text': msg
    }
    response=requests.post(url='https://slack.com/api/chat.postMessage',
              data=data)
    print(response.text)