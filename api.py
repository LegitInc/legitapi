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

# The Legit API
from functools import wraps
from collections import defaultdict, namedtuple
from contextlib import contextmanager
import logging
import urllib
import base64
import json
import os
from xml.etree import ElementTree

from google.appengine.api.urlfetch import fetch
from google.appengine.ext import ndb
import oauth2 as oauth
from flask import Flask, request, g, abort, jsonify
from wtforms import Form, TextField, IntegerField,\
                    DateField, FloatField, BooleanField,\
                    validators
from wtforms.validators import ValidationError

import validation
from models import Developer, Price, IntakeUser, PII_FIELDS, RequestLog
from cryptography import hash_value, encrypt_value, decrypt_value

# Hack to tell if we're running in development or production
DEVELOPMENT = os.environ.get('SERVER_SOFTWARE','').startswith('Development')

app = Flask(__name__)

@app.errorhandler(400)
def bad_request(error):
    return error.description, 400
    
@app.errorhandler(403)
def forbidden_request(error):
    return error.description, 403
    
@app.errorhandler(500)
def unexpected_error(error):
    desc = getattr(error, "description", "Something unexpectedly went wrong. Please contact support.")
    return desc, 500
    
#################################################
# Request Logging                               #
#################################################
from flask import request_finished, request_started

@request_started.connect_via(app)
def create_request_response_log(sender, **extra):
    r = RequestLog()
    r.request_url = request.base_url
    r.request_resource = request.path
    
    parameters = request.values.to_dict()
    r.request_oauth_parameters = {}
    for k in parameters.keys():
        if k.startswith("oauth_"):
            r.request_oauth_parameters[k] = parameters.pop(k)
    r.request_parameters = parameters
    r.request_method = request.method
    r.put()
    
    g.request_log = r

@request_finished.connect_via(app)
def save_request_response_log(sender, response, **extra):
    r = g.request_log
    if hasattr(g, "consumer"):
        r.developer = g.consumer.key
        r.org = g.consumer.org
        
    if hasattr(g, "price"):        
        r.price = g.price
        r.actually_charged = g.actually_charged
    
    r.response_code = response.status_code
    r.response_text = response.data

    r.put()

#################################################
# Utility Methods                               #
#################################################
def validate_or_400(form):
    if not form.validate():
        abort(400, "Request data validation failed with the following errors: \n%s" %
                    "\n".join("%s - %s" % (field, ",".join(errors)) for field, 
                                           errors in form.errors.items()))

#################################################
# OAuth                                         #
#################################################
hmac_sig_method = oauth.SignatureMethod_HMAC_SHA1()
oauth_server = oauth.Server({hmac_sig_method.name: hmac_sig_method})

class InsufficentPermissionsError(Exception):
    "Error for when a consumer does not have enough credit for the transaction"
    pass

class OAuthError(oauth.Error):
    "The OAuth request was invalid or otherwise incorrect"
    pass

def get_consumer(key=None, secret=None):
    """
    Look up a developer based on their consumer key/secret.
    """
    if not key and not secret:
        raise ValueError("You must specify at least one consumer property to do a lookup.")

    q = Developer.query()    
    if key:
        q = q.filter(Developer.consumer_key == key)    
    if secret:
        q = q.filter(Developer.consumer_secret == secret)    
    consumer = q.get()

    return consumer

def check_oauth_permission(consumer, resource):
    """
    Determines if the given Consumer has permission to access
    the given resource.
    """
    if resource not in consumer.permissions:
        raise InsufficentPermissionsError
        
    return True

def verify_oauth_request(oauth_consumer=None):
    """
    Verifies the OAuth signature on the current request.
    """
    auth_header = {}
    if 'Authorization' in request.headers:
        auth_header = {'Authorization':request.headers['Authorization']}

    oauth_request = oauth.Request.from_request(request.method,
                                               request.base_url,
                                               headers=auth_header,
                                               parameters=dict([(k,v) for k,v in request.values.iteritems()]))
    
    if not oauth_request:
        raise OAuthError("No OAuth credentials provided.")
    
    if not oauth_consumer:
        try:
            consumer = get_consumer(key=oauth_request.get('oauth_consumer_key'))
        except ValueError, e:
            raise OAuthError("OAuth Consumer Key not provided.")
            
        if not consumer:
            raise OAuthError("Could not find OAuth consumer corresponding to key: %s" % 
                                oauth_request.get('oauth_consumer_key'))
                                
        oauth_consumer = oauth.Consumer(consumer.consumer_key, consumer.consumer_secret)

    try:
        oauth_server.verify_request(oauth_request, oauth_consumer, None)
        return consumer
    except oauth.Error, e:
        raise OAuthError(e)
    except KeyError, e:
        raise OAuthError(e)
    
def oauth_authorize(permission):
    """
    Decorator to verify the oauth request and ensure
    that a consumer has the credentials to access a given resource.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                consumer = verify_oauth_request()
            except OAuthError, e:
                abort(400, "Invalid OAuth Request - Error: %s" % e.message)
            try:
                check_oauth_permission(consumer, permission)
            except InsufficentPermissionsError, e:
                abort(403, "Insufficent permissions to access this resource")              
            g.consumer = consumer
            return fn(*args, **kwargs)        
        return wrapper
    return decorator


#################################################
# Credit                                        #
#################################################
class InsufficentCreditError(Exception):
    "Error for when a consumer does not have enough credit for the transaction"
    pass

def get_price(price_name):
    "Looks up the current price for the given cost code."
    price = Price.query(Price.name == price_name).get()
    
    if not price:
        raise ValueError("Price %s not found." % price_name)
    
    return price.price

@ndb.transactional
def deduct_credit(dev, org_key, amount):
    """
    Deducts the given amount of credit from the organization. 
    
    If the organization doesn't have enough credit, raises an 
    InsufficentCreditError. 
    
    Can raise a TransactionFailedError if transaction collisions lead to
    the deduction not being able to complete successfully.
    
    In the case of success, returns the amount of credit remaining.
    """
    org = org_key.get()
    if org.credit >= amount:
        org.credit = org.credit - amount
        org.put()     
        
        # Fire off auto-recharge if needed
        if dev.auto_recharge and org.credit < dev.auto_recharge_min:
            taskqueue.add(url=url_for("auto_recharge"), 
                          params={"dev_key": dev_key})      
    else:
        raise InsufficentCreditError("Insufficent credit for request with cost %f" % amount)
        
    return org.credit
    
@ndb.transactional
def add_credit(org_key, amount):
    """
    Adds the given amount of credit to the organization's account.
    """
    org = org_key.get()
    org.credit = org.credit + amount
    org.put()
    
    return org.credit

@app.route("/tasks/auto_recharge", methods=["POST"])
@ndb.transactional
def auto_recharge():
    """
    Background task to check if a user's account has fallen below their
    auto-recharge amount, and to charge their card & add additional credit
    if that is the case.
    """
    dev_key = request.form["dev_key"]
    dev_key = ndb.Key(urlsafe=dev_key)
    dev = dev_key.get()
    org = dev.org.get()
    
    if dev.auto_recharge and org.credit < dev.auto_recharge_min:        
        try:
            charge = stripe.Charge.create(
                amount = dev.auto_recharge_incr * 100, # This is in cents
                currency = "usd",
                customer = dev.auto_recharge_custid,
                description = "Auto-recharge of %f for %s" % (amount, user.email),
            )
            add_credit(dev.org, amount)   
            
        except stripe.CardError, ex:
            logging.error("Auto-Recharge Stripe Error: %s" % ex.message)
            return jsonify(success=False, error=ex.message)
        except Exception, ex:
            logging.error("Auto-Recharge processing error: %s" % ex.message)            
            return jsonify(success=False, error=ex.message)
    
    return jsonify(success=True)     

def priced(price_name):
    """
    Decorator to deduct the correct amount of credit from an organization's
    account for accessing the given method.
    
    IMPORTANT: The oauth authorize decorator must be applied above this 
    decorator (or g.consumer otherwise set) so credit can be deducted
    from the appropriate organization. 
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # first argument is the api type ('sandbox' or 'api')
            org_key = g.consumer.org
            amount = get_price(price_name)
            g.price = g.actually_charged = amount
            api_type = kwargs.get("api_type", "api")
            is_test = (api_type == "sandbox")
            if not is_test:
                try:
                    deduct_credit(g.consumer, org_key, amount)
                except InsufficentCreditError:
                    abort(403, "Insufficent credit to access this resource.")
            
            try:
                return fn(*args, **kwargs)
            except:
                if not is_test:
                    add_credit(org_key, amount)
                    g.actually_charged = 0.0
                raise
        return wrapper
    return decorator

# Commented out as it's not up to date
# @contextmanager
# def pricing(dev_key, org_key, priced_components):
#     """
#     Context manager to handle priced functionality. Before yielding, it deducts
#     the appropriate amount of credit from the given organization. If the org 
#     lacks the needed credit, it throws an exception. If the managed code throws
#     an exception, the credit is added back to the organization.
#     """
#     amount = sum(get_price(price_name) for price_name in priced_components)
#     try:
#         deduct_credit(dev_key.get(), org_key, amount)
#     except InsufficentCreditError:
#         abort(403, "Insufficent credit to access the specified components.")
#         
#     try:    
#         yield
#     except:
#         add_credit(org_key, amount)
#         raise

#################################################
# Intake                                        #
#################################################   
def prehash_validator(validation_func):
    """
    Validation factory that creates wtforms field validators that are aware of
    prehashing, and do not try to validate pre-hashed data.
    """
    def validator(form, field):
        if not form._pre_hashed and field.data:
            try:
                validation_func(field.data)
            except ValueError, ex:
                raise ValidationError(ex.message)                
    return validator

class PIIField(TextField):
    def process_formdata(self, valuelist):
        super(PIIField, self).process_formdata(valuelist)
        if self.data:
            self.data = self.data.strip()

class PIIForm(Form):
    def __init__(self, *args, **kwargs):
        self._pre_hashed = kwargs.pop("pre_hashed", False)
        super(PIIForm, self).__init__(*args, **kwargs)
          
    name = PIIField(u'Name', 
                    [prehash_validator(validation.validate_name)])
    address = PIIField(u'Address',
                    [prehash_validator(validation.validate_address)])
    ssn = PIIField(u'Social Security Number',
                    [prehash_validator(validation.validate_ssn)])
    phone = PIIField(u'Phone Number',
                    [prehash_validator(validation.validate_phone)])
    email = PIIField(u'Email',
                    [prehash_validator(validation.validate_address)])
    facebook_id = PIIField(u'Facebook ID',
                    [prehash_validator(validation.validate_facebook_id)])
    twitter_id = PIIField(u'Twitter ID',
                    [prehash_validator(validation.validate_twitter_id)])
    linkedin_id = PIIField(u'Linkedin ID',
                    [prehash_validator(validation.validate_linkedin_id)])

class IntakeUserForm(PIIForm):
    user_id = PIIField(u'User ID', [validators.DataRequired()])
    
    transaction_count = IntegerField(u'Transaction Count', [validators.InputRequired()])
    review_count = IntegerField(u'Review Count', [validators.InputRequired()])
    positive_review_percentage = FloatField(u'Positive Review Percentage', [validators.InputRequired()])
    date_joined = DateField(u'Date Joined', [validators.DataRequired()])
    date_banned = DateField(u'Date Banned')
    reason_banned = TextField(u'Reason Banned')
    
    pre_hashed = BooleanField(u'Pre-Hashed')
    
    #negative_events = TextField(u'Negative Events')
    
    def __init__(self, *args, **kwargs):
        super(PIIForm, self).__init__(*args, **kwargs)
        self._pre_hashed = self.pre_hashed.data
    
@app.route('/<api_type>/<api_version>/submit/user', methods=["POST"])
@oauth_authorize('submit')
def intake_user(api_type, api_version):    
    form = IntakeUserForm(request.form)
    # TODO: Change this to validate_or_400 after writing intake tests
    #       to confirm it's proper behavior.           
    if not form.validate():
        abort(400, "Request data validation failed with the following errors: \n%s" % 
                        "\n".join("%s - %s" % (field, ",".join(errors)) for field, errors in form.errors.items()))
    
    user_id = hash_value(form.user_id.data, pre_hashed=form._pre_hashed)
    existing_user = IntakeUser.query(IntakeUser.api_type == api_type,
                                     IntakeUser.user_id == user_id,
                                     IntakeUser.org == g.consumer.org).get()
    
    user_fields = {}
    user_fields.update(form.data)
    
    # Remove fields that are not to be persisted to the IntakeUser itself.
    for field in user_fields.keys():
        if not hasattr(IntakeUser, field):
            del user_fields[field]
    
    updated_user = IntakeUser.create_or_update(user_fields,
                                               g.consumer.key,
                                               g.consumer.org,   
                                               api_type,                                            
                                               existing_user=existing_user,
                                               pre_hashed=form._pre_hashed)
    
    return jsonify(user_id=form.user_id.data, is_new=(existing_user == None))


#################################################
# Blacklist & Reputation                        #
#################################################
MatchingIntakeUser = namedtuple("MatchingIntakeUser", ['user', 'fields'])
LRGSummary = namedtuple("LRGSummary", ["memberships", "transactions",
                                       "reviews", "pos_review_perct",
                                       "banned_dates"])

def intake_users_from_user_sets(user_sets, excluded_orgs=None):
    intake_users = []
    for user_set in user_sets:
        for match_level in user_set:
            for miu in match_level:
                if not excluded_orgs or (miu.user.org not in excluded_orgs):
                    intake_users.append(miu.user)
                    
    return intake_users

def aggregate_pii(intake_users):
    """
    Creates a superset of all the PII across all the given intake users.
    
    Args:
        intake_users: A list of IntakeUser objects
        
    Returns:
        A default dictionary of pii_fields -> (set of values)
    """
    aggregate_pii = defaultdict(set)
    for intake_user in intake_users:
        for field in PII_FIELDS:
            if getattr(intake_user, field, None):
                aggregate_pii[field].add(getattr(intake_user, field))
        
    return aggregate_pii

def find_matching_users(pii_fields, api_type, org_key=None, previous_matches=None):
    """
    Takes a dict of pii fields and finds all matching IntakeUsers.    
    Each match has comes with a list of which PII fields were hits.

    Args:
        pii_fields: A dictionary of pii field -> [set or list of values]. 
        api_type: Which api to search, such as "api" or "sandbox"
        org_key: Organization to which the query should be limited
        previous_matches: A list of keys of all IntakeUser objects
                          matched up to this point.        
    Returns:
        A list of dictionaries of IntakeUser keys to 
        MatchingIntakeUsers with the dict of the most direct matches at the top.
    """
    if not previous_matches:
        previous_matches = set()

    # Scrub the PII - we don't accept empty values. 
    for field, values in pii_fields.items():
        for value in values:
            if not value or not unicode(value).strip():
                values.remove(value)

    #logging.info("FIND USER FROM PII:")
    #logging.info(pii_fields)

    # TODO this should be parallelized, doing it synchronously is dumb.
    # TODO we currently limit PII matches to 100 entities. This seems sane,
    #      and keeps the DB from blowing up on bad queries. But, we might 
    #      want something more sophisticated in place at some point.
    direct_matches = {}
    for field, values in pii_fields.items():        
        if hasattr(IntakeUser, field) and values:
            iu_query = IntakeUser.query(IntakeUser.api_type == api_type)
            if org_key:
                iu_query = iu_query.filter(IntakeUser.org == org_key)
            iu_query = iu_query.filter(getattr(IntakeUser, field).IN(values))
            matching_users = iu_query.fetch(100)
            
            for matching_user in matching_users:
                if matching_user.key not in previous_matches: 
                    if matching_user.key in direct_matches:
                        direct_matches[matching_user.key].fields.append(field)
                    else:                        
                        miu = MatchingIntakeUser(matching_user, [field])
                        direct_matches[matching_user.key] = miu                        

    # Update our ongoing list of matches
    previous_matches.update(direct_matches.keys())

    # We have a set of all the IntakeUsers who matched on the inital data. 
    # Next see if our matching IntakeUsers have yielded new PII
    # not present in the original query.
    new_pii = defaultdict(list)
    for matching_user in (v.user for v in direct_matches.values()):
        for field in PII_FIELDS:
            field_value = getattr(matching_user, field)
            if (field_value and field_value not in pii_fields.get(field, [])):
                new_pii[field].append(field_value)

    if new_pii:
        indirect_matches = find_matching_users(new_pii, 
                                                api_type, 
                                                org_key=org_key,
                                                previous_matches=previous_matches)
    else:
        indirect_matches = None

    rv = [direct_matches]
    if indirect_matches:
        rv.extend(indirect_matches)

    return rv

    
def find_users(pii_fields, api_type, org_key=None, pre_hashed=False):
    """
    Method for finding users matching the given PII. Adds more
    intelligence to the process through the following:
    
        Isolating "user sets", non-intersecting groups of users tied 
        to different fields of the given PII. This could be the innocent 
        result of sparse information, an indicator of fraud, or a sign that
        the given PII belongs to multiple individuals. 
    
        Idenfitying conflicting PII. These are PII values within a set 
        of supposedly coherent users that does not agree. This could be 
        the result of user using different contact information with 
        different organizations, or possibly a sign of fraud.
    
    Args:
        pii_fields: A dictionary of pii_field -> value
        
    Returns:
        A list of user sets. Each user set is a list of lists of 
        MatchingIntakeUsers, each sub-list representing a level of matching
        directness.
    """
    #logging.info("Find Users for: %s" % pii_fields)
    
    hashed_pii = {}
    for key, value in pii_fields.items():
        if value:
            hashed_pii[key] = hash_value(value) if not pre_hashed else value
    
    combined_pii = defaultdict(set)
    user_sets = []
    for field, value in hashed_pii.items():
        if field in combined_pii and value in combined_pii[field]:
            # If we've run across this pii value in a previous user set, 
            # we don't need to search on it again.
            continue
            
        matching_users = find_matching_users({field:[value]}, 
                                              api_type, 
                                              org_key=org_key)
        
        # Get rid of the dictionary part, we don't need it anymore.
        #logging.info("Matching Users: %s" % matching_users)
        user_set = [match_dict.values() for match_dict in matching_users]
        user_sets.append(user_set)        
                
        user_set_pii = aggregate_pii([miu.user for match_level in user_set 
                                                for miu in match_level])
                                                                            
        for k,v in user_set_pii.items():
            combined_pii[k].update(v)
            
    return user_sets


def lrg_summary(intake_users):
    """
    Returns a summary of the LRG data we measure for a set of intake users
    """
    agg_transactions = sum(iu.transaction_count for iu in intake_users)
    agg_reviews = sum(iu.review_count for iu in intake_users)
    pos_reviews = sum(iu.review_count * iu.positive_review_percentage
                           for iu in intake_users)
    agg_pos_review_perct = round(pos_reviews / agg_reviews, 2) if agg_reviews else 0.0    
    banned_dates = [{"date_banned": str(iu.date_banned),
                     "marketplace_type": iu.org.get().org_type,
                     "reason_banned": iu.reason_banned } 
                     for iu in intake_users if iu.date_banned]
    
    memberships = set([iu.org for iu in intake_users])
    
    return LRGSummary(memberships=len(memberships),
                      transactions=agg_transactions,
                      reviews=agg_reviews,
                      pos_review_perct=agg_pos_review_perct,
                      banned_dates=banned_dates)

def generate_lrg_summary(user_sets, excluded_orgs=None):
    """
    Compiles the report for a set of intake users who we believe
    to all represent the same user, spread across different systems.
    """
    #logging.info("Generating LRG Summary for: %s" % query_data)    
    #logging.info("Found %d User Sets." % len(user_sets))
    #logging.info("User Sets: %s" % user_sets)
    #logging.info("Excluded Orgs: %s" % excluded_orgs)
    
    intake_users = intake_users_from_user_sets(user_sets, 
                                                excluded_orgs=excluded_orgs)
     
    #logging.info("Non-excluded Users: %s" % intake_users) 
                
    if not intake_users:
        return None
    
    users_by_category = defaultdict(list)
    for iu in intake_users:
        users_by_category[iu.org.get().org_type].append(iu)
    
    overall_summary = lrg_summary(intake_users)
    
    lrg_data = {}
    lrg_data["marketplace_memberships"] = overall_summary.memberships
    lrg_data["total_transactions"] = overall_summary.transactions
    lrg_data["total_reviews"] = overall_summary.reviews
    lrg_data["overall_positive_feedback"] = overall_summary.pos_review_perct
    lrg_data["permanent_removals"] = overall_summary.banned_dates
    lrg_data["categories"] = {}
    
    for k,v in users_by_category.items():
        category_summary = lrg_summary(v)
        for bd in category_summary.banned_dates:
            bd.pop("market_type","")                
        lrg_data["categories"][k] = {
            "marketplace_memberships": category_summary.memberships,
            "transactions": category_summary.transactions,
            "reviews": category_summary.reviews,
            "positive_feedback": category_summary.pos_review_perct,
            "permanent_removals": category_summary.banned_dates,
        }
    
    return lrg_data


def generate_legit_report(components, query_data, api_type, 
                          org_key=None, pre_hashed=False):
    """
    The big mama jama. Pulls together all our sources of data into a
    LegitReport as well as computes a LegitScore
    
    The components piece determines which pieces of data are assembled into the
    report. So far the supported components are:
        blacklist - checkes the given query data against the LRG blacklist.
    """    
    ### LRG Summary ###
    user_sets = find_users(query_data, 
                           api_type, 
                           org_key=org_key, 
                           pre_hashed=pre_hashed)
    
    #logging.info("Generate Legit Report -- User Sets Found: %d" % len(user_sets))
    
    lrg_data = generate_lrg_summary(user_sets)
    intake_users = intake_users_from_user_sets(user_sets)
    agg_pii = aggregate_pii(intake_users)
    
    legit_report = {}
    legit_score = 50

    # Create the specified report components
    if "blacklist" in components:
        blacklist_report = {}
        blacklistings = lrg_data["permanent_removals"] if lrg_data else []
        blacklist_report["blacklistings"] = blacklistings
        blacklist_report["blacklisting_count"] = len(blacklistings)
        
        legit_score -= (40 * blacklist_report["blacklisting_count"])                
        legit_report["blacklist"] = blacklist_report
    
    if "reputation" in components:
        legit_report["lrg_reputation"] = lrg_data
    
    # Limit the legitscore and add it to the report
    legit_score = max([0, min([legit_score, 100])]) # Force 0-100    
    legit_report["legit_score"] = legit_score
    
    return legit_report, intake_users

class ReportForm(PIIForm):
    components = TextField(u"Report Components", [validators.DataRequired()])
    
VALID_COMPONENTS = ("blacklist",)
SANDBOX_COMPONENTS = ("blacklist",)

def component_authorize(func):
    """
    Decorator that ensures the consumer making the call has permission to access
    all of the query components they have specified. If they have not, it an
    autorization exception is thrown.
    
    IMPORTANT: the oauth_authorize decorator MUST be applied first, such that
    the current g object has a consumer property. 
    
    Also checks that all passed in components are valid and aborts if an invalid
    component is found. Yes technically this goes above and beyone "authorization",
    but fuck you. Also aborts if no components argument is found.
    """
    
    # TODO This wrapper should just handle pricing as well. doing it in a separate
    # context manager is dumb. Rob just did that because he was excited about
    # using context managers. However, we're keeping that complexity out for now
    # as we concentrate on getting the blacklist functional.
    
    @wraps(func)
    def wrapper(*args, **kwargs):        
        components = request.values.get("components", "")
        if components:
            components = [c.strip() for c in components.split(",") if c]
        
        if not components:
            abort(400, "No report components specified.")
        
        # First see if they're in our component list
        invalid_components = set(components) - set(VALID_COMPONENTS)
        
        # If any of the components were invalid, abort
        if invalid_components:        
            abort(400, "Invalid report components: %s" % 
                       ",".join(invalid_components))
        
        unauthorized_components = [c for c in components
                                   if c not in g.consumer.permissions]
            
        if unauthorized_components:
            abort(403, "Insufficent permissions to access components: %s" %
                ",".join(unauthorized_components))
        
        g.components = components
        
        return func(*args, **kwargs)        
    return wrapper

@app.route('/<api_type>/<api_version>/query/reputation', methods=["GET"])
@oauth_authorize('query')
@component_authorize
def query_report(api_type, api_version):    
    form = ReportForm(request.args) 
    validate_or_400(form)
    
    form_data = form.data
    components = g.components   
    
    # Make sure we have a valid components list for the sandbox. Not every
    # component is available in the sandbox.
    if api_type == "sandbox":
        non_sandbox_components = set(components) - set(SANDBOX_COMPONENTS)
        if non_sandbox_components:
            abort(400, "Non-sandbox components: %s" %
                       ",".join(non_sandbox_components))
    
    # Set the org_key based on the api type (sandbox or api)
    org_key = g.consumer.org if api_type == "sandbox" else None    
    
    # Generate the legit report, with appropriate pricing
    # TODO Right now we ignore pricing, for simplicity. We will need to fix this
    # when we actually have priced components. It should either be handled as 
    # shown by the commented code (with a context manager) or be added to the
    # component_authorize decorator (probably the best bet)
    
    legit_report, intake_users = generate_legit_report(components,
                                                       form_data,
                                                       api_type,
                                                       org_key=org_key)
    
    # if api_type != "sandbox":
    #         with pricing(org_key, components):    
    #             legit_report, intake_users = generate_legit_report(components,
    #                                                                form_data, 
    #                                                                api_type, 
    #                                                                org_key=org_key)
    #     else:
    #         legit_report, intake_users = generate_legit_report(components,
    #                                                            form_data, 
    #                                                            api_type, 
    #                                                            org_key=org_key)       
        
    return jsonify(legit_report) if legit_report else "No results found."
    
@app.route('/<api_type>/<api_version>/query/blacklist', methods=["GET"])
@oauth_authorize('blacklist')
@component_authorize
def query_blacklist(api_type, api_version):    
    form = ReportForm(request.args) 
    validate_or_400(form)

    form_data = form.data
    components = g.components   

    # Make sure we have a valid components list for the sandbox. Not every
    # component is available in the sandbox.
    if api_type == "sandbox":
        non_sandbox_components = set(components) - set(SANDBOX_COMPONENTS)
        if non_sandbox_components:
            abort(400, "Non-sandbox components: %s" %
                       ",".join(non_sandbox_components))

    # Set the org_key based on the api type (sandbox or api)
    org_key = g.consumer.org if api_type == "sandbox" else None    

    # Generate the legit report, with appropriate pricing
    # TODO Right now we ignore pricing, for simplicity. We will need to fix this
    # when we actually have priced components. It should either be handled as 
    # shown by the commented code (with a context manager) or be added to the
    # component_authorize decorator (probably the best bet)

    legit_report, intake_users = generate_legit_report(components,
                                                       form_data,
                                                       api_type,
                                                       org_key=org_key)

    # if api_type != "sandbox":
    #         with pricing(org_key, components):    
    #             legit_report, intake_users = generate_legit_report(components,
    #                                                                form_data, 
    #                                                                api_type, 
    #                                                                org_key=org_key)
    #     else:
    #         legit_report, intake_users = generate_legit_report(components,
    #                                                            form_data, 
    #                                                            api_type, 
    #                                                            org_key=org_key)       

    return jsonify(legit_report) if legit_report else "No results found."
    
    
    
    