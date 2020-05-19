import requests
try:
    from configs import token,channel
except:
    from config import token,channel

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
    if response.status_code==200 and "ok:true" in response.text:
        print("SENT REPORT TO SLACK")
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
