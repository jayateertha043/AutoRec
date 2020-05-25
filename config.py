import os

if isHeroku in os.environ:
    token=os.environ.get("token")
    channel=os.environ.get("channel")
    APIKEY=os.environ.get("APIKEY")
    print("token:" + str(token))
else:
    token='' #Enter Your Bot Token Here
    channel='' #Enter Your Channel Id here

#Note:Your Bot must be added to channel before it can send the files or send message to that channel

#www2png.com api for screenshot free
    APIKEY=''