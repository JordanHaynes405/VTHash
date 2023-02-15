import requests
import hashlib
import datetime
import os
import json

api_Key = 'YourAPIKeyHere'

CurrentUser = os.environ.get("USERNAME")

DownloadsPath = rf'C:\Users\{CurrentUser}\Downloads'

TodaysDate = datetime.datetime.now()

for file in os.listdir(DownloadsPath):
    fileWithPath = f"{DownloadsPath}\\{file}"
    fileDateModified = os.path.getmtime(fileWithPath)
    fileDateModified = datetime.datetime.fromtimestamp(fileDateModified)
    TimeDelta = TodaysDate - fileDateModified


    if TimeDelta.days < 1:
        with open(fileWithPath, 'rb') as f:
            data = f.read()
            Hash = hashlib.sha256(data).hexdigest()

            url = f"https://www.virustotal.com/api/v3/files/{Hash}"

            headers = {
                "accept": "application/json",
                "x-apikey": api_Key
            }

            response = requests.get(url, headers=headers)

            response = response.json()

            Reputation = TimesSubmitted = response["data"]["attributes"]["reputation"]
            TimesSubmitted = response["data"]["attributes"]["times_submitted"]
            TotalVotesHarmless = response["data"]["attributes"]["total_votes"]["harmless"]
            TotalVotesMalicious = response["data"]["attributes"]["total_votes"]["malicious"]


            print(f"{file} - hash: {Hash} appears to have a reputation of {Reputation}, was submitted {TimesSubmitted} times and has a harmless to malicious ratio of {TotalVotesHarmless}/{TotalVotesMalicious}.")


