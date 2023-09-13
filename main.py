import requests
import pyotp
import hashlib
import os
import boto3
import traceback
from datetime import datetime
from urllib.parse import parse_qs
from boto3.dynamodb.conditions import Key

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TABLE = "Trading"

dynamodb = boto3.resource(
    "dynamodb",
    region_name="ap-south-1",
)
tradingTable = dynamodb.Table(TABLE)


# Get all users from db
def getAllUsers():
    response = tradingTable.query(
        KeyConditionExpression=Key("pk").eq("client") & Key("sk").begins_with("ZERODHA")
    )
    return response["Items"]


# Save access token to dynamodb
def saveAccessToken(user, accessToken):
    date = datetime.now().isoformat()
    tradingTable.update_item(
        Key={"pk": user["pk"], "sk": user["sk"]},
        UpdateExpression="set accessToken = :accessToken, updatedAt = :updatedAt",
        ExpressionAttributeValues={":accessToken": accessToken, ":updatedAt": date},
        ReturnValues="UPDATED_NEW",
    )


# Send message on telegram
def sendTelegramMsg(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}

    requests.post(url, json=data).json()


# Login into kite and return access token
def login(user):
    session = requests.Session()
    name = user["name"]
    userId = user["clientId"]
    password = user["password"]
    apiKey = user["apiKey"]
    apiSecret = user["apiSecret"]
    totpKey = user["totpKey"]

    res1 = session.post(
        "https://kite.zerodha.com/api/login",
        data={"user_id": userId, "password": password},
    ).json()

    if res1["status"] != "success":
        print(f"Login failed at step1 for {name}", res1)
        raise Exception(f"Login failed at step1 for {name}")

    requestId = res1["data"]["request_id"]
    totpToken = pyotp.TOTP(totpKey).now()

    # # Two factor authentication
    res2 = session.post(
        "https://kite.zerodha.com/api/twofa",
        data={
            "request_id": requestId,
            "user_id": userId,
            "twofa_value": totpToken,
        },
    ).json()

    if res2["status"] != "success":
        print(f"Login failed at step2 for {name}", res2)
        raise Exception(f"Login failed at step2 for {name}")

    res3 = session.post(
        f"https://kite.trade/connect/login?v=3&api_key={apiKey}", allow_redirects=True
    )

    print("res3 url", res3.url)

    requestToken = parse_qs(res3.url)["request_token"][0]

    # Get access token
    h = hashlib.sha256(
        apiKey.encode("utf-8")
        + requestToken.encode("utf-8")
        + apiSecret.encode("utf-8")
    )
    checksum = h.hexdigest()

    res4 = session.post(
        "https://api.kite.trade/session/token",
        data={"api_key": apiKey, "request_token": requestToken, "checksum": checksum},
    ).json()

    if res4["status"] != "success":
        print(f"Login failed at step4 for {name}", res4)
        raise Exception(f"Login failed at step4 for {name}")

    return res4["data"]["access_token"]


def handler(event, context):
    users = getAllUsers()

    for user in users:
        try:
            name = user["name"]
            accessToken = login(user=user)
            saveAccessToken(user=user, accessToken=accessToken)
            sendTelegramMsg(f"{name}'s login to kite was successful")
        except Exception as e:
            name = user["name"]
            print("Something went wrong", e)
            traceback.print_exc()
            sendTelegramMsg(f"{name}'s login to kite failed, Something went wrong")

    return "success"
