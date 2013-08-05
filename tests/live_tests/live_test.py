# Copyright (C) 2013  Rob Boyle / Legit Inc
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses

import random
import string
import threading
import urllib
import oauth2 as oauth
import time

PII_FIELDS = ("name", "address", "ssn", "phone", "email", "facebook_id",
              "twitter_id", "linkedin_id")

PII_LEN = 8

def random_string(length):
    return ''.join(random.choice(string.ascii_lowercase) for x in range(length))

def generate_user(user_id):
    data = {}
    data["user_id"] = user_id
    for i in range(random.randint(1,len(PII_FIELDS))):
        data[random.choice([f for f in PII_FIELDS if f not in data])] = random_string(PII_LEN)
        
    return data
    
def generate_rep():
    data = {}
    data["date_joined"] = "2010-02-17"
    data["transaction_count"] = random.randint(0, 10)
    data["review_count"] = random.randint(0, 10)
    data["positive_review_percentage"] = random.randint(0, 100)
    
    return data

def add_users(key, secret, start_at, count, errors, success):
    url = "https://APP_URL/api/submit/user"
    consumer = oauth.Consumer(key=key, secret=secret)
    client = oauth.Client(consumer)
    
    for i in range(start_at, start_at+count):
        user_id = i+1
        user_data = generate_user(user_id)
        rep_data = generate_rep()
        
        user_data.update(rep_data)
        
        resp, content = client.request(url, "POST", urllib.urlencode(user_data))    

        if resp.status != 200:
            errors.append(content)
        else:
            success.append(content)
        
THREAD_COUNT = 8
TOTAL_USERS = 64

def live_test(consumer_key, consumer_secret):
    start_time = time.time()
    per_thread = TOTAL_USERS / THREAD_COUNT
    threads = []
    errors = []
    success = []
    for i in range(THREAD_COUNT):
        start_at = i * per_thread
        t = threading.Thread(target=add_users, 
                             args=(consumer_key, consumer_secret, 
                                   start_at, per_thread, errors, success))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
       
    end_time = time.time()
    print "ELAPSED TIME: %.2f seconds" % (end_time - start_time)
    print "USERS ADDED: %d" % len(success)
    print "ERRORS: %s" % len(errors)
    print "*** ERROR CONTENT ***"
    for e in errors:
        print e
        
    
if __name__ == "__main__":
    live_test("QXYQQNfX3jn49ecTyfI18ueQLZnOfRAZ", 
              "sebw4Nxhp7F3EuYzlpal1o0IjQkcNm9u")
              
              
              
              
              
              
              
              
              
              