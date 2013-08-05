import oauth2 as oauth
from nose import with_setup
from nose.tools import eq_

import models
from local_tests import testapp, setup_datastore, teardown_datastore, create_GET_url,\
                        import_csv, grant_query, grant_component

def _load_test_data():
    import_csv("/Users/rob/code/legitapi/tests/local_tests/query_test_data.csv")

@with_setup(setup_datastore, teardown_datastore)
def test_permissions():
    dev1 = models.Developer.query(models.Developer.consumer_key == "valid_key1").get()
    consumer1 = oauth.Consumer(key=dev1.consumer_key, secret=dev1.consumer_secret)
    
    # Make a call with no api level permissions, confirm that we get a 403
    url = create_GET_url({"email":"rob@email.com","components":"blacklist"}, 
                         "/api/v1/query/report", consumer1)
    response = testapp.get(url, status=403) 
    
    eq_(response.status_int, 403)    
    eq_(response.body, "Insufficent permissions to access this resource")

    grant_query()
    
    # Make a call with api level permissions, but no component permissions, 
    # confirm that we still get a 403
    response = testapp.get(url, status=403) 
    eq_(response.status_int, 403)
    eq_(response.body, "Insufficent permissions to access components: blacklist")
    
    grant_component(dev1, "blacklist")
    
    # Make a request with both api and component level permissions, confirm
    # that everything is a-ok
    response = testapp.get(url)
    eq_(response.status_int, 200)      
       
@with_setup(setup_datastore, teardown_datastore)
def test_blacklist():
    grant_query()
    _load_test_data()
    
    dev1 = models.Developer.query(models.Developer.consumer_key == "valid_key1").get()
    
    grant_component(dev1, "blacklist")
    
    consumer1 = oauth.Consumer(key=dev1.consumer_key, secret=dev1.consumer_secret)
    
    # Check a user who has not been blacklisted
    url = create_GET_url({"email":"lily@email.com", "components": "blacklist"}, 
                         "/api/v1/query/report", consumer1)
    response = testapp.get(url)
    
    eq_(response.status_int, 200)
    
    blacklist_data = response.json["blacklist"]
    
    eq_(blacklist_data["blacklisting_count"], 0)
    eq_(len(blacklist_data["blacklistings"]), 0)
    
    # Check a user who HAS been blacklisted
    # This test also tests our correlation algorithm by querying on a piece of
    # PII that is NOT directly associated with the blacklisting - it's
    # affiliated with the user through another marketplace.
    url = create_GET_url({"email":"rob@email.com", "components": "blacklist"}, 
                         "/api/v1/query/report", consumer1)
    response = testapp.get(url)
    
    eq_(response.status_int, 200)
    
    blacklist_data = response.json["blacklist"]
    
    eq_(blacklist_data["blacklisting_count"], 1)
    eq_(len(blacklist_data["blacklistings"]), 1)
    eq_(blacklist_data["blacklistings"][0]["date_banned"], "2009-09-25")
    eq_(blacklist_data["blacklistings"][0]["reason_banned"], None)
    eq_(blacklist_data["blacklistings"][0]["marketplace_type"], "ride sharing")
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    