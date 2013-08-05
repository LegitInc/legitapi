import oauth2 as oauth
from nose import with_setup
from nose.tools import eq_
from urllib import urlencode
import datetime
import hmac
import hashlib

import models
import cryptography
from local_tests import testapp, setup_datastore, teardown_datastore,\
                        create_request, create_GET_url, grant_submit,\
                        grant_query, grant_component

def check_intakeuser(intake_user, user_data, developer_key, org_key, 
                     pre_hashed=False):
    non_pii = ("date_joined", "date_banned", "reason_banned", "review_count", 
               "transaction_count", "positive_review_percentage")
    
    eq_(intake_user.developer, developer_key)
    eq_(intake_user.org, org_key)
        
    # Test that hashing went correctly
    for key, value in user_data.items():
        if key.startswith("date"):
            value = datetime.datetime.strptime(value, "%Y-%m-%d").date()
        
        # print "Key: %s" % key 
        # print "Intake: %s" % getattr(intake_user, key)
        # print "Test Data: %s" % value
                
        if key not in non_pii:
            # print "Intake Encrypted: %s" % getattr(intake_user, key+"_enc")
            # print "Intake Decrypt: %s" % cryptography.decrypt_value(getattr(intake_user, key+"_enc"))
            if pre_hashed:
                eq_(getattr(intake_user, key+"_enc"), None)
            else:
                eq_(cryptography.decrypt_value(getattr(intake_user, key+"_enc")), value)
            value = cryptography.hash_value(value, pre_hashed=pre_hashed)
        
        eq_(getattr(intake_user, key), value)

def test_hashing():    
    for test_value in ("This is a test value to hash", u"Now a uni\u0107ode string", 1231, datetime.date.today()):
        if isinstance(test_value, unicode):
            test_value = test_value.encode("utf-8")
        else:
            test_value = str(test_value)            
        public_hash = hmac.new(cryptography._get_public_salt(), msg=test_value, digestmod=hashlib.sha256).hexdigest()
        internal_hash = hmac.new(cryptography._get_salt(), msg=public_hash, digestmod=hashlib.sha256).hexdigest()
        
        assert internal_hash == cryptography.hash_value(test_value, pre_hashed=False)

        internal_hash = hmac.new(cryptography._get_salt(), msg=test_value, digestmod=hashlib.sha256).hexdigest()
        
        assert internal_hash == cryptography.hash_value(test_value, pre_hashed=True)
        
test_data = {"user_id": "1",
             "ssn": "123121234",
             "facebook_id": "132452356",
             "name": "Rob Boyle",
             "email": "rboyle@gmail.com",
             "date_joined": "1983-04-15",
             "date_banned": "1983-10-30",
             "review_count": 235,
             "transaction_count": 942,
             "positive_review_percentage": 74.23 }

@with_setup(setup_datastore, teardown_datastore)
def test_oauth():
    response = testapp.post("/api/v1/bad/method", status=404)
    assert response.status_int == 404
    
    response = testapp.post("/api/v1/submit/user", status=400)
    assert response.status_int == 400    
    assert response.body == "Invalid OAuth Request - Error: No OAuth credentials provided."
    
    consumer = oauth.Consumer(key="invalid key", secret="invalid secret")   
    req = create_request(consumer, "http://localhost/api/v1/submit/user", "POST", urlencode(test_data))    
    response = testapp.post("/api/v1/submit/user", req.to_postdata(), status=400)
    assert response.status_int == 400
    assert response.body == "Invalid OAuth Request - Error: Could not find OAuth consumer corresponding to key: invalid key"

    consumer = oauth.Consumer(key="valid_key1", secret="valid_secret1")
    req = create_request(consumer, "http://localhost/api/v1/submit/user", "POST", urlencode(test_data))    
    response = testapp.post("/api/v1/submit/user", req.to_postdata(), status=403)
    assert response.status_int == 403
    assert response.body == "Insufficent permissions to access this resource"
    
    test_dev = models.Developer.query(models.Developer.consumer_key==consumer.key).get()
    test_dev.permissions = ["submit"]
    test_dev.put()
    response = testapp.post("/api/v1/submit/user", req.to_postdata())
    assert response.status_int == 200
    assert response.json["user_id"] == u"1"
    assert response.json["is_new"]
    
@with_setup(setup_datastore, teardown_datastore)
def test_submit():
    grant_submit()
    
    # Submit through developer 1
    dev1 = models.Developer.query(models.Developer.consumer_key == "valid_key1").get()
    consumer1 = oauth.Consumer(key=dev1.consumer_key, secret=dev1.consumer_secret)
    req = create_request(consumer1, "http://localhost/api/v1/submit/user", "POST", urlencode(test_data))    
    
    response = testapp.post("/api/v1/submit/user", req.to_postdata())    
    assert response.status_int == 200
    assert response.json["user_id"] == u"1"
    assert response.json["is_new"]
    
    assert models.IntakeUser.query().count() == 1
    intake_user = models.IntakeUser.query().get()
    
    check_intakeuser(intake_user, test_data, dev1.key, dev1.org)
    
    # Submit through developer 2
    dev2 = models.Developer.query(models.Developer.consumer_key == "valid_key2").get()    
    consumer2 = oauth.Consumer(key=dev2.consumer_key, secret=dev2.consumer_secret)
    req = create_request(consumer2, "http://localhost/api/v1/submit/user", "POST", urlencode(test_data))
    
    response = testapp.post("/api/v1/submit/user", req.to_postdata())    
    assert response.status_int == 200
    assert response.json["user_id"] == u"1"
    assert response.json["is_new"]
    
    assert models.IntakeUser.query().count() == 2
    
    intake_user = models.IntakeUser.query(models.IntakeUser.org == dev2.org).get()
    
    check_intakeuser(intake_user, test_data, dev2.key, dev2.org)
    
    # Submit an update through developer 1
    test_data2 = {}
    test_data2.update(test_data)
    test_data2["transaction_count"] = 1056
    test_data2["twitter_id"] = "1234567"
    
    req = create_request(consumer1, "http://localhost/api/v1/submit/user", "POST", urlencode(test_data2))    

    response = testapp.post("/api/v1/submit/user", req.to_postdata())    
    assert response.status_int == 200
    assert response.json["user_id"] == u"1"
    assert not response.json["is_new"]
    
    intake_user = models.IntakeUser.query(models.IntakeUser.org == dev1.org).get()
    
    check_intakeuser(intake_user, test_data2, dev1.key, dev1.org)
    
    # Submit a second through developer 2
    test_data3 = {}
    test_data3.update(test_data)
    test_data3["user_id"] = u"2"
    
    req = create_request(consumer2, "http://localhost/api/v1/submit/user", "POST", urlencode(test_data3))    

    response = testapp.post("/api/v1/submit/user", req.to_postdata())    
    assert response.status_int == 200
    assert response.json["user_id"] == u"2"
    assert response.json["is_new"]
    
    intake_user = models.IntakeUser.query(models.IntakeUser.user_id == cryptography.hash_value(test_data3["user_id"]),
                                          models.IntakeUser.developer == dev2.key).get()                                          

    check_intakeuser(intake_user, test_data3, dev2.key, dev2.org)
        
@with_setup(setup_datastore, teardown_datastore)
def test_submit_emptyuser():
    grant_submit()
    empty_user_data = {"user_id": "1",
                       "ssn": "123121234",
                       "facebook_id": "132452356",
                       "name": "Rob Boyle",
                       "email": "rboyle@gmail.com",
                       "date_joined": "1983-04-15",
                       "date_banned": "1983-10-30",
                       "review_count": 0,
                       "transaction_count": 0,
                       "positive_review_percentage": 0 }
    
    dev = models.Developer.query(models.Developer.consumer_key == "valid_key1").get()
    consumer = oauth.Consumer(key=dev.consumer_key, secret=dev.consumer_secret)
    req = create_request(consumer, "http://localhost/api/v1/submit/user", 
                         "POST", urlencode(empty_user_data))    
    
    response = testapp.post("/api/v1/submit/user", req.to_postdata())
    
    assert models.IntakeUser.query().count() == 1
    intake_user = models.IntakeUser.query().get()
    
    check_intakeuser(intake_user, empty_user_data, dev.key, dev.org)    
    
@with_setup(setup_datastore, teardown_datastore)
def test_pre_hashing():
    grant_submit()
    
    pre_hashed_data = {}
    for k,v in test_data.items():
        if k in models.PII_FIELDS:
            v = hmac.new(cryptography._get_public_salt(), msg=cryptography._string_or_bust(v), digestmod=hashlib.sha256).hexdigest()
        pre_hashed_data[k] = v
    
    submission_data = {}
    submission_data.update(pre_hashed_data)
    submission_data["pre_hashed"] = True
    
    # Submit through developer 1
    dev1 = models.Developer.query(models.Developer.consumer_key == "valid_key1").get()
    consumer1 = oauth.Consumer(key=dev1.consumer_key, secret=dev1.consumer_secret)
    req = create_request(consumer1, "http://localhost/api/v1/submit/user", "POST", urlencode(submission_data))    
    
    response = testapp.post("/api/v1/submit/user", req.to_postdata())    
    assert response.status_int == 200
    assert response.json["user_id"] == u"1"
    assert response.json["is_new"]
    
    assert models.IntakeUser.query().count() == 1
    intake_user = models.IntakeUser.query().get()
        
    check_intakeuser(intake_user, pre_hashed_data, dev1.key, dev1.org, 
                     pre_hashed=True)
    

@with_setup(setup_datastore, teardown_datastore)
def test_validation():
    grant_submit()

    # Submit through developer 1
    correct_data = {
        "user_id": "1",
        "address": "123 High St, San Francisco CA, 94117",
        "name": "Rob Boyle",
        "ssn": "123121234",
        "phone": "+14151112222",
        "email": "rob@email.com",
        "facebook_id": "123456",
        "twitter_id": "123456",
        "linkedin_id": "123456",
        "date_joined": "1983-04-15",
        "date_banned": "1983-10-30",
        "review_count": 235,
        "transaction_count": 942,
        "positive_review_percentage": 74.23
    }
    
    dev1 = models.Developer.query(models.Developer.consumer_key == "valid_key1").get()
    consumer1 = oauth.Consumer(key=dev1.consumer_key, secret=dev1.consumer_secret)
    req = create_request(consumer1, "http://localhost/api/v1/submit/user", "POST", urlencode(correct_data))    
    response = testapp.post("/api/v1/submit/user", req.to_postdata())    

    intake_user = models.IntakeUser.query().get()    
    
    assert response.status_int == 200
    check_intakeuser(intake_user, correct_data, dev1.key, dev1.org, 
                     pre_hashed=False)
                     
    bad_data = {
        "user_id": "1",
        "address": "123 High St, San Francisco CA, 94117",
        "name": "Rob Boyle",
        "ssn": "123-12-1234",
        "phone": "(415)-123-1234",
        "email": "rob@email",
        "facebook_id": "facebook_rob",
        "twitter_id": "twitter_rob",
        "linkedin_id": "linkedin_rob",
        "date_joined": "1983-04-15",
        "date_banned": "1983-10-30",
        "review_count": 235,
        "transaction_count": 942,
        "positive_review_percentage": 74.23
    }
   
    req = create_request(consumer1, "http://localhost/api/v1/submit/user", "POST", urlencode(bad_data))    
    response = testapp.post("/api/v1/submit/user", req.to_postdata(), status=400)    

    intake_user = models.IntakeUser.query().get()    
    
    eq_(response.body,"""Request data validation failed with the following errors: 
phone - Invalid phone number: (415)-123-1234
ssn - Non-numeric SSN Number: 123-12-1234
linkedin_id - Invalid linkedin id: linkedin_rob
twitter_id - Invalid twitter id: twitter_rob
facebook_id - Invalid facebook id: facebook_rob""")
    eq_(response.status_int, 400)
  

@with_setup(setup_datastore, teardown_datastore)
def test_sandboxing():
    """
    Tests the ability for orgs to use the sandbox API.
    """
    grant_submit()
    grant_query()
    
    test_data = {"user_id": "1",
                 "ssn": "123121234",
                 "facebook_id": "132452356",
                 "name": "Rob Boyle",
                 "email": "rboyle@gmail.com",
                 "date_joined": "1983-04-15",
                 "date_banned": "1983-10-30",
                 "reason_banned": "Too awesome.",
                 "review_count": 235,
                 "transaction_count": 942,
                 "positive_review_percentage": 74.23 }
    
    # Setup developer 1
    dev1 = models.Developer.query(models.Developer.consumer_key == "valid_key1").get()
    consumer1 = oauth.Consumer(key=dev1.consumer_key, secret=dev1.consumer_secret)
    grant_component(dev1, "blacklist")
    
    # Setup developer 2
    dev2 = models.Developer.query(models.Developer.consumer_key == "valid_key2").get()    
    consumer2 = oauth.Consumer(key=dev2.consumer_key, secret=dev2.consumer_secret)
    grant_component(dev2, "blacklist")    
    
    # Submit a user to the dev1 sandbox
    req = create_request(consumer1, "http://localhost/sandbox/v1/submit/user", "POST", urlencode(test_data))        
    response = testapp.post("/sandbox/v1/submit/user", req.to_postdata())    
    assert response.status_int == 200
    assert response.json["user_id"] == u"1"
    assert response.json["is_new"]

    assert models.IntakeUser.query(models.IntakeUser.api_type=="api").count() == 0
    assert models.IntakeUser.query(models.IntakeUser.org==dev1.org, models.IntakeUser.api_type=="sandbox").count() == 1
    intake_user = models.IntakeUser.query(models.IntakeUser.api_type=="sandbox", models.IntakeUser.org==dev1.org).get()
    
    check_intakeuser(intake_user, test_data, dev1.key, dev1.org)
    
    # Query for the user using the sandbox blacklist query method
    url = create_GET_url({"email":"rboyle@gmail.com", "components":"blacklist"}, 
                         "/sandbox/v1/query/report", consumer1)
    response = testapp.get(url)    
    
    blacklist_data = response.json["blacklist"]
    
    eq_(blacklist_data["blacklisting_count"], 1)
    eq_(len(blacklist_data["blacklistings"]), 1)
    eq_(blacklist_data["blacklistings"][0]["date_banned"], "1983-10-30")
    eq_(blacklist_data["blacklistings"][0]["reason_banned"], "Too awesome.")
    eq_(blacklist_data["blacklistings"][0]["marketplace_type"], "testing")
    
    # Query for the user using the production API, make sure they don't show up
    url = create_GET_url({"email":"rboyle@gmail.com", "components":"blacklist"}, 
                         "/api/v1/query/report", consumer1)
    response = testapp.get(url)    
    blacklist_data = response.json["blacklist"]
    
    eq_(len(blacklist_data["blacklistings"]), 0)
    eq_(blacklist_data["blacklisting_count"], 0)
    
    # Submit a user to the dev2 sandbox
    test_data2 = {}
    test_data2.update(test_data)
    test_data2["email"] = "rob@email.com"
    
    req = create_request(consumer2, "http://localhost/sandbox/v1/submit/user", "POST", urlencode(test_data2))
    
    response = testapp.post("/sandbox/v1/submit/user", req.to_postdata())    
    assert response.status_int == 200
    assert response.json["user_id"] == u"1"
    assert response.json["is_new"]
    
    assert models.IntakeUser.query(models.IntakeUser.api_type=="api").count() == 0
    assert models.IntakeUser.query(models.IntakeUser.org==dev2.org, models.IntakeUser.api_type=="sandbox").count() == 1
    intake_user = models.IntakeUser.query(models.IntakeUser.api_type=="sandbox", models.IntakeUser.org==dev2.org).get()
    
    check_intakeuser(intake_user, test_data2, dev2.key, dev2.org)
    
    # Query for the user using the sandbox query method and the dev that created it
    url = create_GET_url({"email":"rob@email.com", "components":"blacklist"}, 
                         "/sandbox/v1/query/report", consumer2)
    response = testapp.get(url)    
    
    blacklist_data = response.json["blacklist"]
    
    eq_(blacklist_data["blacklisting_count"], 1)
    eq_(len(blacklist_data["blacklistings"]), 1)
    eq_(blacklist_data["blacklistings"][0]["date_banned"], "1983-10-30")
    eq_(blacklist_data["blacklistings"][0]["reason_banned"], "Too awesome.")
    eq_(blacklist_data["blacklistings"][0]["marketplace_type"], "testing")
        
    # Query for the user using the production API, make sure they don't show up
    url = create_GET_url({"email":"rob@email.com", "components":"blacklist"}, 
                         "/api/v1/query/report", consumer2)
    response = testapp.get(url)    
    
    blacklist_data = response.json["blacklist"]
    
    eq_(len(blacklist_data["blacklistings"]), 0)
    eq_(blacklist_data["blacklisting_count"], 0)
    
    # Query for the user using the sandbox API, but the other developer, make 
    # sure developer 2's data doesn't show up.
    url = create_GET_url({"email":"rob@email.com", "components":"blacklist"}, 
                         "/sandbox/v1/query/report", consumer1)
    response = testapp.get(url)    
    
    blacklist_data = response.json["blacklist"]
    
    eq_(len(blacklist_data["blacklistings"]), 0)
    eq_(blacklist_data["blacklisting_count"], 0)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    