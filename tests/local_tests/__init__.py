import oauth2 as oauth
from webtest import TestApp
from urlparse import parse_qs
from urllib import urlencode

import models
from api import app, hmac_sig_method

testapp = TestApp(app)

def setup():
    import cryptography
    import hashlib
    
    cryptography.SALT = "test-salt"
    cryptography.AES_KEY = hashlib.sha256('test').digest()

def setup_datastore():
    
    NUM_DEVS = 2
    
    for i in range(1, NUM_DEVS+1):
        test_org = models.Organization(name="testorg%d" % i, full_name="TestOrg%d" % i,
                                       org_type="testing")
        test_org.put()

        test_dev = models.Developer(email="test%d@test%d.co" % (i, i), org=test_org.key,
                                consumer_key='valid_key%d' % i, consumer_secret='valid_secret%d' % i)
        test_dev.put()

def teardown_datastore():
    intake_keys = models.IntakeUser.query().fetch(keys_only=True)
    for key in intake_keys:
        key.delete()

    for test_dev in models.Developer.query():
        test_dev.key.delete()
    
    for test_org in models.Organization.query():
        test_org.key.delete()

def grant_submit():
    for test_dev in models.Developer.query():
        test_dev.permissions = test_dev.permissions + ["submit"]
        test_dev.put()

def grant_query():
    for test_dev in models.Developer.query():
        test_dev.permissions = test_dev.permissions + ["query"]
        test_dev.put()
        
def grant_component(dev, component):
    if component not in dev.permissions:
        dev.permissions += [component]
        dev.put()

def create_request(consumer, url, method, body=None, headers=None):
    DEFAULT_POST_CONTENT_TYPE = 'application/x-www-form-urlencoded'

    if body == None:
        body = ""

    if not isinstance(headers, dict):
        headers = {}

    if method == "POST":
        headers['Content-Type'] = headers.get('Content-Type', DEFAULT_POST_CONTENT_TYPE)

    is_form_encoded = headers.get('Content-Type') == 'application/x-www-form-urlencoded'

    if is_form_encoded and body:
        parameters = parse_qs(body)
    else:
        parameters = None

    req = oauth.Request.from_consumer_and_token(consumer, 
        token=None, http_method=method, http_url=url, 
        parameters=parameters, body=body, is_form_encoded=is_form_encoded)

    req.sign_request(hmac_sig_method, consumer, None)
    
    return req

def create_GET_url(data, resource_url, consumer):
    qs = "?"+urlencode(data)
    req = create_request(consumer,
                         "http://localhost"+resource_url+qs,
                         "GET")
    return req.to_url().replace("http://localhost", "", 1)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    