import oauth2 as oauth
from nose import with_setup
from nose.tools import eq_

import models
from local_tests import testapp, setup_datastore, teardown_datastore, create_GET_url

@with_setup(setup_datastore, teardown_datastore)
def test_pricing():
    "Test that the pricing module works as advertised."
    pass