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

# Admin interface
import logging
import json
import re
import os
from collections import OrderedDict, defaultdict

from google.appengine.ext import ndb
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from wtforms import Form, TextField, BooleanField, FloatField, PasswordField, FileField, validators
from webapp2_extras import security
from google.appengine.api import taskqueue, memcache, files, urlfetch

from models import IntakeUser, CombinedUser, Organization, Invite, Developer, Price, RequestLog, PII_FIELDS
from cryptography import hash_value, decrypt_value
from api import PIIForm, find_users, generate_legit_report, generate_lrg_summary

app = Flask(__name__)

app.secret_key = "\xc9z\x91'\xdc\x17\xa2\xb7\x0f\xba\x7fN\x1a\x94\xee\x9f\xbd!\xcf\xf1\x16cF\x0e"

if os.environ.get('SERVER_SOFTWARE','').startswith('Development'):
    DEVELOPMENT = True
else:
    DEVELOPMENT = False

@app.route("/admin/", methods=["GET"])
def home():
    return render_template("admin/base.html")

##################
# Developers     #
##################
@app.route("/admin/developers/", methods=["GET"])
def developers_management():
    existing_developers = Developer.query().fetch(100)
        
    return render_template("admin/developers.html", developers=existing_developers)

class DeveloperForm(Form):
    name = TextField("Name")
    permissions = TextField("Permissions")
    password = PasswordField("Password")
    is_admin = BooleanField("Is Admin")

@app.route("/admin/developer/<developer_key>/", methods=["GET", "POST"])
def developer_management(developer_key):
    developer = ndb.Key(urlsafe=developer_key).get()
    
    if request.method == "POST":
        form = DeveloperForm(request.form)
        if form.validate():
            developer.permissions = [perm.strip() for perm in form.permissions.data.split(",")]
            developer.name = form.name.data
            if form.password:
                developer.password = security.generate_password_hash(form.password.data, length=12)
            developer.is_admin = form.is_admin.data            
            developer.put()
            flash("Developer %s successfully updated." % developer.email)
    else:
        form = DeveloperForm(name=developer.name, is_admin=developer.is_admin,
                             permissions=",".join(developer.permissions))
        
    return render_template("admin/developer.html", developer=developer, form=form)

##################
# Organizations  #
##################
class CreateOrganizationForm(Form):
    full_name = TextField("Full Org Name", [validators.DataRequired()])
    short_name = TextField("Short Org Name", [validators.DataRequired()])
    org_type = TextField("Marketplace Type", [validators.DataRequired()])
        
@app.route("/admin/organizations/", methods=["GET", "POST"])
def organizations_management():
    if request.method == "POST":
        form = CreateOrganizationForm(request.form)
        if form.validate():
            org = Organization(name=form.short_name.data, full_name=form.full_name.data)
            org.put()
    else:
        form = CreateOrganizationForm()
    
    existing_orgs = Organization.query().fetch(100)    
    
    return render_template("admin/organizations.html",
                            existing_orgs=existing_orgs,
                            form=form)


def org_pii_stats(organization_key):
    org = organization_key.get()
    pii_stats = {}
    for pii_field in PII_FIELDS:
        if hasattr(IntakeUser, pii_field):
            count = IntakeUser.query(IntakeUser.org == org.key).filter(
                                getattr(IntakeUser, pii_field) != None).count()
        else:
            count = 0
            
        pii_stats[pii_field] = count        
        
    return pii_stats
    
def org_transaction_stats(organization_key):
    org = organization_key.get()
    transaction_stats = OrderedDict()
    UPPER_BOUND = 10
    for i in range(UPPER_BOUND + 1):
        count_q = IntakeUser.query(IntakeUser.org == org.key)
        if i < UPPER_BOUND:
            count_q = count_q.filter(IntakeUser.transaction_count == i)
        else:
            count_q = count_q.filter(IntakeUser.transaction_count >= i)
        count = count_q.count()
        
        key_name = unicode(i)
        if i >= UPPER_BOUND:
            key_name += "+"

        transaction_stats[key_name] = count
   
    return transaction_stats
    

class OrganizationForm(Form):
    credit = FloatField("Credit")
    org_type = TextField("Marketplace Type", [validators.DataRequired()])
                            
@app.route("/admin/organization/<organization_key>/", methods=["GET", "POST"])
def organization_management(organization_key):
    org = ndb.Key(urlsafe=organization_key).get()
    intake_user_count = IntakeUser.query(IntakeUser.org == org.key).count()
    most_recent_update = IntakeUser.query().order(-IntakeUser.updated).get()
    
    if most_recent_update:
        most_recent_update = most_recent_update.updated.strftime(
                                                        "%a %b %d %H:%M:%S %Y")
    
    pii_stats = org_pii_stats(org.key)
    ordered_transaction_stats = org_transaction_stats(org.key)

    ordered_pii_stats = OrderedDict()
    ordered_pii_stats["total"] = intake_user_count
    for field, value in sorted(pii_stats.items(), key=lambda i: i[1], reverse=True):
        ordered_pii_stats[field] = value
    
    if request.method == "POST":
        form = OrganizationForm(request.form)
        if form.validate():
            org.credit = form.credit.data
            org.org_type = form.org_type.data
            org.put()
            flash("Organization %s successfully updated." % org.full_name)
    else:
        form = OrganizationForm(credit=org.credit, 
                                org_type=org.org_type)
        
    return render_template("admin/organization.html", org=org, form=form,
                           intake_user_count=intake_user_count,
                           most_recent_update=most_recent_update,
                           pii_stats=ordered_pii_stats,
                           transaction_stats=ordered_transaction_stats)
    
##################
# Prices         #
##################
class CreatePriceForm(Form):
    name = TextField("Name", [validators.DataRequired()])
    price = FloatField("Price", [validators.DataRequired()])
    
@app.route("/admin/prices/", methods=["GET", "POST"])
def prices_management():
    if request.method == "POST":
        form = CreatePriceForm(request.form)
        if form.validate():
            price = Price(name=form.name.data, price=form.price.data)
            price.put()
    else:
        form = CreatePriceForm()
        
    existing_prices = Price.query().fetch(100)
    
    return render_template("admin/prices.html",
                            existing_prices=existing_prices,
                            form=form)
                            
class PriceForm(Form):
    name = TextField("Name", [validators.DataRequired()])
    price = FloatField("Price", [validators.DataRequired()])
    
@app.route("/admin/price/<price_key>/", methods=["GET", "POST"])
def price_management(price_key):
    price = ndb.Key(urlsafe=price_key).get()
    
    if request.method == "POST":
        form = PriceForm(request.form)
        if form.validate():
            price.name = form.name.data
            price.price = form.price.data
            price.put()
            flash("Price %s successfually updated." % price.name)
            
    else:
        form = PriceForm(price=price.price, name=price.name)
        
    return render_template("admin/price.html", price=price, form=form)

##################
# Invites        #
##################
def create_invite(code, org_name):
    org = Organization.query(Organization.name == org_name).get()
    i = Invite(org=org.key, code=code)
    i.put()

class CreateInviteForm(Form):
    code = TextField("Invite Code", [validators.DataRequired()])
    org_name = TextField("Organization Name", [validators.DataRequired()])
    
@app.route("/admin/invites/", methods=["GET"])
def invite_management():
    form = CreateInviteForm()
    existing_invites = Invite.query().fetch(100)
    
    return render_template("admin/invites.html",
                            existing_invites=existing_invites,
                            form=form)

@app.route("/admin/invites/create", methods=["POST"])
def invite_create():
    form = CreateInviteForm(request.form)
    if form.validate():
        create_invite(form.code.data, form.org_name.data)
    
    return redirect(url_for("invite_management"))

##################
# Databases      #
##################
class CreateDatabaseForm(Form):
    db_id = TextField("Database ID", [validators.DataRequired()])
        
@app.route("/admin/databases/", methods=["GET","POST"])
def databases():
    if request.method == "POST":
        form = CreateDatabaseForm(request.form)
        if form.validate():
            database = Database(id=form.db_id.data)
            database.put()
            
            return redirect(url_for("databases"))
    else:
        form = CreateDatabaseForm()
        
    dbs = Database.query().fetch(100)
    
    return render_template("admin/databases.html",
                            dbs=dbs, form=form)

##################
# Analysis       #
##################
class AnalysisReport(ndb.Model):
    org_name = ndb.StringProperty()
    blob_key = ndb.BlobKeyProperty()

def get_legit_report(intake_user, api_type="api"):
    pii = aggregate_pii([intake_user])
    query_dict = {}
    for k,v in pii.items():
        if v:
            query_dict[k] = v.pop()
                
    return generate_legit_report(query_dict, api_type, pre_hashed=True)
    
@app.template_filter()
def dev_decrypt(value):
    "Jinja2 filter for decrypting values in development"
    import hashlib
    
    if DEVELOPMENT:
        return decrypt_value(value, aes_key=hashlib.sha256("dev_key").digest())
    else:
        return value

def analyze_user(intake_user_key):
    #logging.debug("Analyzing User Key: %s" % intake_user_key)
    intake_user = intake_user_key.get()
    counter_key = "analysis::run_count::%s" % intake_user.org.urlsafe()
    
    count = CombinedUser.query(CombinedUser.intake_users == intake_user.key).count(1)
    if not count:  
        # Generate a legit report
        legit_report, intake_users = get_legit_report(intake_user, api_type="api")

        # Create a combined user
        cu = CombinedUser.create(intake_users, legit_report)
        cu.put()
        
    # Check one off the list
    #memcache.decr(counter_key)
    
    return "Great Success"

def generate_csv(org_name):
    org = Organization.query(Organization.name == org_name).get()
    combined_users = CombinedUser.query(CombinedUser.orgs == org.key)
    
    rv = "UserID,LegitScore,Memberships,Transactions,Reviews,PositiveReviewPercentage,Bannings,Facebook,Twitter,Linkedin\n"
    for cu in combined_users:
        org_user_id = [ui for ui in cu.user_id if ui.startswith(org_name)][0]
        has_facebook = 1 if cu.facebook_id else 0
        has_twitter = 1 if cu.twitter_id else 0
        has_linkedin = 1 if cu.linkedin_id else 0
        rv += ("%s,%.1f,%d,%d,%d,%.2f,%d,%d,%d,%d\n" % 
                    (org_user_id,
                     cu.legit_report["legitscore"],
                     cu.legit_report["lrg_reputation"]["marketplace_memberships"],
                     cu.legit_report["lrg_reputation"]["total_transactions"],
                     cu.legit_report["lrg_reputation"]["total_reviews"],
                     cu.legit_report["lrg_reputation"]["overall_positive_feedback"],
                     len(cu.legit_report["lrg_reputation"]["permanent_removals"]),
                     has_facebook,
                     has_twitter,
                     has_linkedin))
    
    #logging.info("CSV FILE")
    #logging.info(rv)
                     
    file_name = files.blobstore.create(mime_type='text/plain',
                                       _blobinfo_uploaded_filename="%s-analysis" % org_name)
    with files.open(file_name, 'a') as f:
        f.write(rv)
        
    files.finalize(file_name) 
    blob_key = files.blobstore.get_blob_key(file_name)
    
    ar = AnalysisReport.query(AnalysisReport.org_name == org_name).get() or AnalysisReport(org_name=org_name)
    ar.blob_key = blob_key
    ar.put()
    
@app.route("/admin/analysis/run_analysis/<org_key>", methods=["POST"])    
def run_analysis(org_key=None):
    """
    Task that deletes all existing CombinedUsers and regenerates them from the
    underlying IntakeUsers. This task can take a long time to run, so it should
    be run on a dedicated instance. 
    """
    DELETE_BATCH = 500
    ANALYZE_BATCH = 50
    
    # Clear out the existing combined users    
    cu_query = CombinedUser.query()
    if org_key:
        org_key = ndb.Key(urlsafe=org_key)
        cu_query = cu_query.filter(CombinedUser.orgs == org_key)
    
    while True:
        results, cursor, more = cu_query.fetch_page(DELETE_BATCH, keys_only=True)
        ndb.delete_multi(results)
        if not more:
            break            
    
    # Analyze all the intake users, on a per-organization basis  
    if org_key:
        org_keys = [org_key]
    else:
        org_keys = Organization.query().iter(keys_only=True)
    
    for org_key in org_keys:
        counter_key = "analysis::run_count::%s" % org_key.urlsafe()
        memcache.set(key=counter_key, value=0)
        
        iu_query = IntakeUser.query(IntakeUser.org == org_key)        
        for iu_key in iu_query.iter(keys_only=True):
            memcache.incr(counter_key)            
            #deferred.defer(analyze_user, intake_user_key=iu_key)
            analyze_user(iu_key)
        
        generate_csv(org_key.get().name)

    return "Great Success"


@app.route("/admin/analysis", methods=["GET","POST"])
def analysis():
    orgs = Organization.query().fetch(50)

    orgs_info = {}   
    for org in orgs:
        total_users = IntakeUser.query(IntakeUser.org == org.key).count()
        if total_users == 0:
            continue            
        orgs_info[org.name] = {}
        counter_key = "analysis::run_count::%s" % org.key.urlsafe()
        orgs_info[org.name]["analyzed_users"] = memcache.get(counter_key)
        orgs_info[org.name]["total_users"] = total_users
        orgs_info[org.name]["org_key"] = org.key.urlsafe()
    
    if request.method == "POST":
        org_key = request.form.get("org_key", None)            
        taskqueue.add(url=url_for("run_analysis", org_key=org_key), 
                      target="analyzer")
        return redirect(url_for("analysis"))

    return render_template("admin/analysis.html",
                            orgs_info=orgs_info)

@app.route("/admin/analsys/<org_name>.csv", methods=["GET"])
def get_csv(org_name):
    ar = AnalysisReport.query(AnalysisReport.org_name == org_name).get()
    
    resp = Response("", mimetype="text/plain")
    resp.headers.add("X-AppEngine-BlobKey", str(ar.blob_key))
    
    return resp

##################
# Query          #
##################
class QueryForm(PIIForm):
    prehashed = BooleanField(u"Data is Prehashed")

@app.route("/admin/query", methods=["GET","POST"])
def query():
    matching_users = None
    if request.method == "POST":
        form = QueryForm(request.form)
        if form.validate():
            #logging.info("Request Data: %s" % request.form)
            #logging.info("Form Data: %s" % form.data)

            query_data = form.data
            is_prehashed = query_data.pop("prehashed")

            # for k,v in query_data.items():
            #                 if v:
            #                     query_data[k] = hash_value(v)
            #                 else:
            #                     del query_data[k]

            user_sets = find_users(query_data, "api", pre_hashed=is_prehashed)

            lrg_summaries = []
            for user_set in user_sets:
                lrg_summaries.append(generate_lrg_summary([user_set]))

            user_sets = zip(user_sets,lrg_summaries)

            legit_report, intake_users = generate_legit_report(
                                                    query_data, 
                                                    "api", 
                                                    pre_hashed=is_prehashed)    
            legit_report_pretty = json.dumps(legit_report, sort_keys=True, indent=4)        
    else:
        user_sets = None
        legit_report = None
        legit_report_pretty = None
        form = QueryForm()

    return render_template("admin/query.html", 
                            form=form, 
                            PII_FIELDS=PII_FIELDS,
                            DEVELOPMENT=DEVELOPMENT,
                            user_sets=user_sets,
                            legit_report=legit_report,
                            legit_report_pretty=legit_report_pretty)
                            
##################     
# Data Quality   #
##################        
@ndb.transactional
def _rehash_pii(intake_user_key):
    intake_user = intake_user_key.get()
    iu_dict = intake_user.to_dict()
    for key in iu_dict.keys():
        if key.endswith("_enc"):
            key_for_hashed = key[:-4]
            encrypted_value = iu_dict[key]
            
            if not encrypted_value:
                setattr(intake_user, key_for_hashed, None)
                continue
            
            decrypted_value = decrypt_value(encrypted_value)
            
            if (isinstance(decrypted_value, str) or 
                isinstance(decrypted_value, unicode)):
                decrypted_value = decrypted_value.strip()
            
            if decrypted_value:
                setattr(intake_user, key_for_hashed, 
                        hash_value(decrypted_value))
            else:
                setattr(intake_user, key_for_hashed, None)
                
    intake_user.put()

@app.route("/admin/data_quality/rehash_pii", methods=["POST"])
def rehash_pii_task():
    urlsafe_intake_keys = json.loads(request.data)
    intake_keys = [ndb.Key(urlsafe=urlsafe) for urlsafe in urlsafe_intake_keys]
    
    logging.info("Processing batch of %d intake keys." % len(intake_keys))
    
    processed = 0
    errors = 0
    for intake_key in intake_keys:
        try:
            _rehash_pii(intake_key)
            processed += 1
        except Exception as ex:
            errors += 1
            logging.error(ex)
    
    logging.info("Successfully processed %d users with %d errors." % (processed, errors))
    
    if errors:
        abort(500, "Failed to process all entries.")
    
    return jsonify(success=True, processed=processed, errors=errors)

def _enqueue_rehashing(key_batch):
    taskqueue.add(url=url_for("rehash_pii_task"), 
                  payload=json.dumps(key_batch))
                  
    logging.info("Successfully enqueued %d users for rehashing." % len(key_batch))
    
@app.route("/admin/data_quality", methods=["GET","POST"])
def data_quality():
    if request.method == "POST":
        BATCH_SIZE = 200
        key_batch = []
        for intake_user_key in IntakeUser.query().iter(keys_only=True):
            key_batch.append(intake_user_key.urlsafe())            
            if len(key_batch) == BATCH_SIZE:                
                _enqueue_rehashing(key_batch)
                key_batch = []

        if key_batch:
            _enqueue_rehashing(key_batch)

        return redirect(url_for("data_quality"))

    return render_template("admin/data_quality.html")        
        
    
#######################    
# We Can Haz Value?   #
#######################
class OverlappingUser(ndb.Model):
    membership_count = ndb.IntegerProperty()
    report = ndb.JsonProperty(compressed=True)

class ValueSummary(ndb.Model):
    organization = ndb.KeyProperty(kind=Organization)
    org_name = ndb.StringProperty()
    
    # Value Stats
    overlap_counts = ndb.JsonProperty()
    #overlapping_users = ndb.StructuredProperty(OverlappingUser, repeated=True)

    # Processing Status
    processed_users = ndb.IntegerProperty()
    total_users = ndb.IntegerProperty()
    is_running = ndb.BooleanProperty()
    
    def sorted_overlap_counts(self):
        ordered_overlap_counts = OrderedDict()
        for field, value in sorted(self.overlap_counts.items(), 
                                   key=lambda i: i[0]):
            ordered_overlap_counts[field] = value
            
        return ordered_overlap_counts
            
    
@app.route("/admin/compute_org_value/<organization_key>", methods=["POST"])
def compute_org_value(organization_key):
    """
    Task that computes the current value of our data for the given organization.
    This task can take a long time and should be run on a backend.
    """
    org = ndb.Key(urlsafe=organization_key).get()
    vs = ValueSummary.query(ValueSummary.organization == org.key).get()
    if not vs:
        vs = ValueSummary(organization=org.key)        

    vs.processed_users = 0
    vs.total_users = IntakeUser.query(IntakeUser.org == org.key).count()
    vs.is_running = True    
    vs.overlap_counts = {}
    vs.org_name = org.full_name
    
    vs.put()

    overlap_counts = defaultdict(int)
    for intake_user in IntakeUser.query(IntakeUser.org == org.key):
        #logging.info(intake_user.pii_dict())
        user_sets = find_users(intake_user.pii_dict(), pre_hashed=True)
        #logging.info("USER SETS:")
        #logging.info(user_sets)
        lrg_summary = generate_lrg_summary(user_sets, [org.key])
        #logging.info("LRG SUMMARY:")
        #logging.info(lrg_summary)
        if lrg_summary:
            overlap_counts[lrg_summary["marketplace_memberships"]] += 1
        vs.processed_users += 1
        vs.put()
           
    vs.is_running = False
    vs.overlap_counts = overlap_counts
    vs.put()
    
    return jsonify(success=True, processed_users=vs.processed_users)
           
@app.route("/admin/value", methods=["GET"])
def value():    
    summaries = ValueSummary.query().fetch()    
    
    return render_template("admin/value.html", summaries=summaries)
    
@app.route("/admin/compute_value", methods=["POST"])    
def kickoff_compute_value():
    org_keys = Organization.query().iter(keys_only=True)
    for org_key in org_keys:
        url = url_for("compute_org_value", organization_key=org_key.urlsafe())
        if DEVELOPMENT:
            taskqueue.add(url=url)
        else:
            taskqueue.add(url=url, target="1.analyzer")

    return redirect(url_for("value"))
    
################
# Task Runner  #  
################
@app.route("/admin/enqueue_task/<task_func>", methods=["POST"])
def enqueue_task(task_func):
    BATCH_SIZE = 5 if DEVELOPMENT else 200
    key_batch = []
    total_size = 0
    for intake_user_key in IntakeUser.query().iter(keys_only=True):
        key_batch.append(intake_user_key.urlsafe()) 
        total_size += 1           
        if len(key_batch) == BATCH_SIZE:                
            taskqueue.add(url=url_for(task_func), 
                          payload=json.dumps(key_batch))

            logging.info("Successfully enqueued %d users for task %s." % (len(key_batch), task_func))
            key_batch = []

    if key_batch:
        taskqueue.add(url=url_for(task_func), 
                      payload=json.dumps(key_batch))

        logging.info("Successfully enqueued %d users for task %s." % (len(key_batch), task_func))
        
    return jsonify(total_size=total_size)
        
class RunTaskForm(Form):
    task_func = TextField("Task Function", [validators.DataRequired()])
    
@app.route("/admin/run_task", methods=["GET", "POST"])
def run_task():
    if request.method == "POST":
        form = RunTaskForm(request.form)
        if form.validate():
            task_func = form.task_func.data
            taskqueue.add(url=url_for("enqueue_task", task_func=task_func),
                            target="analyzer")

            return redirect(url_for("run_task"))
        
    else:
        form = RunTaskForm()
            
    return render_template("admin/run_task.html", form=form)
    
@app.route("/admin/task_set_api_type", methods=["POST"])
def task_set_api_type():
    urlsafe_intake_keys = json.loads(request.data)
    intake_keys = [ndb.Key(urlsafe=urlsafe) for urlsafe in urlsafe_intake_keys]
    
    logging.info("Processing batch of %d intake keys." % len(intake_keys))
    
    intake_users = []
    for k in intake_keys:
        iu = k.get()
        iu.api_type = "api"
        intake_users.append(iu)
    ndb.put_multi(intake_users)

    return jsonify(processed_users=len(intake_users))
    
@app.route("/admin/check_on_data", methods=["GET"])
def check_on_data():
    api_user_count = IntakeUser.query(IntakeUser.api_type=="api").count()
    sandbox_user_count = IntakeUser.query(IntakeUser.api_type=="sandbox").count()
    total_user_count = IntakeUser.query().count()
    
    return render_template("admin/check_on_data.html",
                            api_user_count=api_user_count,
                            sandbox_user_count=sandbox_user_count,
                            total_user_count=total_user_count)
                         
                            
#########################
# Map Reduce Processing #    
#########################
from mapreduce import base_handler, mapreduce_pipeline
from api import aggregate_pii, generate_legit_report
@app.route("/admin/mapreduce_processing/", methods=["GET", "POST"])
def mapreduce_processing():
    if request.method == "POST":
        pipeline_name = request.form.get("pipeline")
        if pipeline_name == "compute_legit_scores":
            pipeline = LegitScorePipeline()
        else:
            flash("Unknown Pipline: %s" % pipeline_name)            
            return redirect(url_for("mapreduce_processing"))
            
        pipeline.start()
        return redirect(pipeline.base_path + "/status?root=" + pipeline.pipeline_id)
    
    pipelines = [("Compute Legit Scores","compute_legit_scores")]
    return render_template("admin/mapreduce_processing.html",
                           pipelines=pipelines) 

def legit_score_map(data):
    logging.info("Legit Score Map Function -- Key: %s" % data)
    logging.info(type(data))
    entity_key = ndb.Key.from_old_key(data)
    entity = entity_key.get()
    logging.info("Legit Entity: %s" % entity)
    legit_report, intake_users = get_legit_report(entity)
    logging.info("Legit Report: %s" % legit_report)
    value = {
        "legit_report": legit_report,
        "org_name": entity.org.get().name,
        "user_id": entity.user_id,
    }
    
    yield (entity_key, json.dumps(value))
    
def legit_score_reduce(key, values):
    logging.info("Legit Reduce Function -- Key: %s  Values: %s" % (key, values))
    value = json.loads(values[0])
    logging.info("JSON Decoded Value: %s" % value)
    if value["legit_report"]["lrg_reputation"]:
        lrg_rep_values = (value["legit_report"]["lrg_reputation"]["marketplace_memberships"],
                          value["legit_report"]["lrg_reputation"]["total_transactions"],
                          value["legit_report"]["lrg_reputation"]["total_reviews"],
                          value["legit_report"]["lrg_reputation"]["overall_positive_feedback"],
                          len(value["legit_report"]["lrg_reputation"]["permanent_removals"]))
    else:
        lrg_rep_values = (0, 0, 0, 0.0, 0)
        
    csv_string = "%s,%s,%f,%d,%d,%d,%f,%d\n" % ((value["user_id"], value["org_name"],
                                                value["legit_report"]["legitscore"],) + lrg_rep_values)
    yield csv_string

class LegitScorePipeline(base_handler.PipelineBase):
    #logging.info("Running the Legit Score Map Reduce Pipeline")    
    def run(self):
        output = yield mapreduce_pipeline.MapreducePipeline(
            "compute_legit_scores",
            "admin.legit_score_map",
            "admin.legit_score_reduce",
            "mapreduce.input_readers.DatastoreKeyInputReader",
            "mapreduce.output_writers.BlobstoreOutputWriter",
            mapper_params={
                "entity_kind": "IntakeUser",
                "namespace": "",
            },
            reducer_params={
                "mime_type": "text/plain",
            },
            shards=16)    
    
#################
# Request Log   #
#################
@app.route("/admin/request_log/", methods=["GET"])    
def request_log():
    requests = RequestLog.query().order(-RequestLog.created).fetch(25)
    
    return render_template("admin/request_log.html",
                            requests=requests)
                            
    
    
    
    
    
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
    