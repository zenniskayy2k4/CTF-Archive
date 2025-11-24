from flask import Flask, request, render_template, session, redirect, url_for
import threading
import time
import random
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

items = [{
    "highest_bid": 0,
    "highest_bidder": None,
    "highest_bidder_uuid": None,
    "prize": "1.5m lunchcoins",
    "value": "1.5m lunchcoins"
}, {
    "highest_bid": 0,
    "highest_bidder": None,
    "highest_bidder_uuid": None,
    "prize": "10k moonies",
    "value": "1.5m lunchcoins"
}, {
    "highest_bid": 0,
    "highest_bidder": None,
    "highest_bidder_uuid": None,
    "prize": "flag",
    "value": "LITCTF{[redacted]}"
}]

class bot:
    def __init__(self, value, target, index):
        self.value = value
        self.target = target
        self.index = index
        self.name = "bot " + str(index)
        self.uuid = str(uuid.uuid4())
        self.inventory = []
    def bid(self, currentbid):
        if currentbid < self.value:
            return min(self.value, currentbid + 1)
        else:
            return None

bots = [bot(100, 0, 0), bot(100, 1, 1), bot(1000, 2, 2)]

class user:
    def __init__(self, value, index):
        self.value = value
        self.index = index
        self.name = "user " + str(index)
        self.inventory = []


time_limit = 100
auction_active = True

users = {}
userindex = 0
for i in bots:
    users[i.uuid] = i

def end_auction():
    time.sleep(time_limit)
    global auction_active
    auction_active = False
    time.sleep(1) #wating for all transactions to finish
    for i in items:
        if i["highest_bidder_uuid"] != None:
            users[i["highest_bidder_uuid"]].inventory.append(i["value"])



@app.route("/register")
def register():
    user_id = str(uuid.uuid4())
    session["user_id"] = user_id
    global userindex
    users[user_id] = user(200, userindex)
    userindex += 1
    username = users[user_id].name
    return render_template("register.html", username=username)

@app.route("/inventory")
def inventory():
    user_id = session.get("user_id")
    if not user_id or user_id not in users:
        return redirect("/register")
    return render_template("inventory.html", inventory=users[user_id].inventory)

@app.route("/bid", methods=["POST"])
def place_bid():
    if not auction_active:
        return redirect("/")

    user_id = session.get("user_id")
    if not user_id or user_id not in users:
        return redirect("/register")

    data = request.form
    try:
        item_id = int(data.get("item_id"))
        bid = float(data.get("bid"))
    except:
        return redirect("/")

    if item_id != None and item_id < len(items) and item_id >= 0:
        item = items[item_id]
    else:
        return render_template("error.html", message="Invalid item ID")

    if bid is None or bid <= item["highest_bid"]:
        return render_template("error.html", message="Bid too low or invalid")
    if bid > users[user_id].value:
        return render_template("error.html", message="Insufficient funds")
    users[user_id].value -= bid
    if item["highest_bidder_uuid"] != None:
        users[item["highest_bidder_uuid"]].value += item["highest_bid"]
        print(users[item["highest_bidder_uuid"]].name)
    item["highest_bid"] = bid
    item["highest_bidder"] = users[user_id].name
    item["highest_bidder_uuid"] = user_id

    for i in bots:
        botbid = i.bid(items[i.target]["highest_bid"])
        if (items[i.target]["highest_bidder_uuid"] == i.uuid):
            continue
        if botbid != None and botbid > items[i.target]["highest_bid"]:
            if items[i.target]["highest_bidder_uuid"] != None:
                users[items[i.target]["highest_bidder_uuid"]].value += item["highest_bid"]
            items[i.target]["highest_bid"] = botbid
            items[i.target]["highest_bidder"] = i.name
            items[i.target]["highest_bidder_uuid"] = i.uuid
            i.value -= botbid
    return redirect("/")

@app.route("/", methods=["GET"])
def status():
    user_id = session.get("user_id")
    if not user_id or user_id not in users:
        return redirect("/register")
    return render_template("status.html", items=items, balance=users[user_id].value, active=auction_active)

threading.Thread(target=end_auction, daemon=True).start()

if __name__ == "__main__":
    app.run(debug=False)
