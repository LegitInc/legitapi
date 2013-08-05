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

# The Legit Dev Website
import os
import base64
import logging
from collections import defaultdict
from urllib import urlencode
import oauth2 as oauth
import json

import stripe
from google.appengine.api import mail, urlfetch
import webapp2
from webapp2_extras import jinja2, sessions, auth, security
from google.appengine.ext import ndb
from wtforms import Form, TextField, PasswordField, HiddenField, BooleanField, SelectField, validators
import markdown

from models import Developer, Invite, INITIAL_PERMISSIONS
from api import add_credit, IdentityForm, hmac_sig_method, get_price

# Hack to tell if we're running in development or production
DEVELOPMENT = os.environ.get('SERVER_SOFTWARE','').startswith('Development')
SITE_DOMAIN = 'http://localhost:8081' if DEVELOPMENT else 'https://APP_URL'

stripe.api_key = "xarhKBUESLULwLEdtalM8tlqw1iWOFla" # TEST KEY

def markdown_filter(value, paragraph=False):
    result = markdown.markdown(value)
    # hack to get rid of starting/ending p tags
    if not paragraph:
        if result.startswith("<p>"):
            result = result[3:]
        if result.endswith("</p>"):
            result = result[:-4]
            
    return result
    

def jinja2_factory(app):
    "true ninja method for attaching additional globals/filters to jinja"
    
    j = jinja2.Jinja2(app)
    j.environment.globals.update({
        'uri_for': webapp2.uri_for,
    })
    j.environment.filters['markdown'] = markdown_filter
    return j

class BaseHandler(webapp2.RequestHandler):
    "Base handler for all site request handlers"
    
    # Session setup
    def dispatch(self):        
        try:
            super(BaseHandler, self).dispatch()
        finally:
            self.session_store.save_sessions(self.response)
            
    @webapp2.cached_property
    def session_store(self):
        return sessions.get_store(request=self.request)
            
    @webapp2.cached_property
    def session(self):
        return self.session_store.get_session(backend="memcache")
    
    # Auth/User setup
    @webapp2.cached_property
    def auth(self):
        return auth.get_auth(request=self.request)
    
    @webapp2.cached_property
    def user(self):
        user = self.auth.get_user_by_session()
        return user
    
    @webapp2.cached_property
    def user_complete(self):
        complete_user, timestamp = self.auth.store.user_model.get_by_auth_token(
                            self.user['user_id'], self.user['token']
                        ) if self.user else (None, None)
        return complete_user
    
    # Jinja2 setup
    @webapp2.cached_property
    def jinja2(self):
        return jinja2.get_jinja2(factory=jinja2_factory, app=self.app)
    
    def render_response(self, _template, **context):
        #Bit of a hack, adding in some global context variables,
        # is this the right way to do this?      
        messages = defaultdict(list)
        for message, level in self.session.get_flashes():
            messages[level].append(message)
              
        ctx = {'user': self.user_complete,
                'messages':  messages}
        ctx.update(context)
        rv = self.jinja2.render_template(_template, **ctx)
        self.response.write(rv)

#################################################
# Developer Accounts                            #
#################################################
def create_consumer():
    """Creates a new consumer key/secret pair"""
    key = base64.urlsafe_b64encode(os.urandom(24))
    secret = base64.urlsafe_b64encode(os.urandom(24))

    return key, secret

def legit_auth_id(email):
    return 'legit:%s' % email

class UserCreationError(Exception):
    pass

def create_user(auth, email, name, password, invite_code):
    """Creates a new user and assigns a OAuth consumer key/secret"""
    key, secret = create_consumer()
    
    invite = Invite.query(Invite.code==invite_code, Invite.is_used==False).get()
    if not invite:
        raise UserCreationError("Invalid invite code: %s" % invite_code)
        
    success, info = auth.store.user_model.create_user(
        legit_auth_id(email),
        unique_properties=['email', 'consumer_key', 'consumer_secret'],
        email=email,
        name=name,
        org=invite.org,
        invite_code=invite.code,     
        permissions=INITIAL_PERMISSIONS,           
        password_raw=password,
        consumer_key=key,
        consumer_secret=secret)
        
    if not success:
        error_msg = "That email is already in use." if 'email' in info else "Something has gone horrible wrong. Email Rob, he probably messed up."
        raise UserCreationError(error_msg)
    else:
        invite.is_used = True
        invite.put()
        
    return info
        
class SignupForm(Form):
    name = TextField('Name', [validators.DataRequired(), validators.Length(min=2, max=50)])
    email = TextField('Email', [validators.DataRequired(), validators.Length(min=6, max=50), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])
    invite_code = TextField('Invite Code', [validators.DataRequired()])
    
class SignupHandler(BaseHandler):
    "Serves up a signup form, creates new users"
    def get(self):
        self.render_response("auth/signup.html", form=SignupForm())
            
    def post(self):
        form = SignupForm(self.request.POST)
        if form.validate():
            try:
                user = create_user(self.auth, form.email.data, form.name.data,
                                   form.password.data, form.invite_code.data)
                self.auth.get_user_by_password(user.auth_ids[0], form.password.data)
                return self.redirect_to("home")
            except UserCreationError, e:
                self.session.add_flash(e.message, 'local')     
        self.render_response("auth/signup.html", form=form)

class LoginForm(Form):
    email = TextField('Email', [validators.DataRequired(), validators.Length(min=6, max=50), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])

class LoginHandler(BaseHandler):
    def get(self):
        self.render_response("auth/login.html", form=LoginForm())
        
    def post(self):
        form = LoginForm(self.request.POST)
        if form.validate():
            try:
                self.auth.get_user_by_password(legit_auth_id(form.email.data), form.password.data)
                return self.redirect_to('home')
            except (auth.InvalidAuthIdError, auth.InvalidPasswordError), e:                    
                self.session.add_flash("Invalid Email / Password", 'local')
        self.render_response("auth/login.html", form=form)

def user_required(handler):
    "Decorator that requires that a user be logged in to access the resource"
    def check_login(self, *args, **kwargs):     
        if not self.user:
            self.redirect_to('login', _abort=True, next=self.request.path_qs)
        else:
            return handler(self, *args, **kwargs)
    return check_login

class ProfileContactForm(Form):
    name = TextField('Name', [validators.DataRequired(), validators.Length(min=3, max=50)])
    email = TextField('Email', [validators.DataRequired(), validators.Length(min=6, max=50), validators.Email()])

class ProfilePasswordForm(Form):
    current_password = PasswordField("Current Password", [validators.DataRequired()])
    new_password = PasswordField("New Password", [validators.DataRequired(), 
        validators.EqualTo('confirm_password', message="Passwords must match.")])
    confirm_password = PasswordField("Confirm New Password", [validators.DataRequired()])

CREDIT_CHOICES = ((20, "$ 20.00"),
                  (40, "$ 40.00"),
                  (60, "$ 60.00"),
                  (80, "$ 80.00"),
                  (100, "$ 100.00"),
                  (200, "$ 200.00"),
                  (500, "$ 500.00"),
                  (1000, "$ 1000.00"))

class ProfileAutoRechargeForm(Form):
    is_auto_recharge = BooleanField("Enable auto-recharge")
    auto_recharge_min = SelectField("Auto-recharge minimum", choices=CREDIT_CHOICES, coerce=int)
    auto_recharge_incr = SelectField("Auto-recharge increment", choices=CREDIT_CHOICES, coerce=int)
    
class ProfileHandler(BaseHandler):
    """Display the user's profile page where they can update their info."""    
    
    @user_required
    def get(self):
        return self.credentials()
        
    @user_required
    def credentials(self):
        self.render_response("auth/profile/credentials.html")

    @user_required
    def settings(self):
        contact_form = ProfileContactForm(None, self.user_complete)
        password_form = ProfilePasswordForm(None, self.user_complete)
        
        self.render_response("auth/profile/settings.html", 
                             contact_form=contact_form,
                             password_form=password_form)
        
    @user_required
    def change_password(self):
        password_form = ProfilePasswordForm(self.request.POST)
        contact_form = ProfileContactForm(None, self.user_complete)
        dev = self.user_complete
        if password_form.validate():                        
            if security.check_password_hash(password_form.current_password.data, dev.password):
                dev.password = security.generate_password_hash(
                                password_form.new_password.data, length=12)
                dev.put()     
                self.session.add_flash("Password successfully changed.", "local")                 
                return self.redirect_to("profile_settings")                      
            else:
                password_form.current_password.errors.append("Current password was invalid.")
        
        self.render_response("auth/profile/settings.html",
                             contact_form=contact_form,
                             password_form=password_form)
    
    @user_required    
    def update_contact(self):
        password_form = ProfilePasswordForm(None, self.user_complete)
        contact_form = ProfileContactForm(self.request.POST)
        if contact_form.validate():
            dev = self.user_complete
            dev.name = contact_form.name.data
            dev.put()
            
            if dev.email == contact_form.email.data:
                self.session.add_flash("Contact info successfully updated.", "local")
                return self.redirect_to("profile_settings")                
            else:    
                auth_id = legit_auth_id(contact_form.email.data)                        
                if auth_id not in dev.auth_ids:
                    success, info = dev.add_auth_id(auth_id)
                    if success:
                        old_auth_id = legit_auth_id(dev.email)
                        dev.auth_ids.remove(old_auth_id)
                        dev.email = contact_form.email.data
                        dev.put()
                        unique = '%s.auth_id:%s' % (dev.__class__.__name__, old_auth_id)
                        dev.unique_model.delete_multi([unique])
                        self.session.add_flash("Contact info successfully updated.", "local")
                        return self.redirect_to("profile_settings")
                    else:
                        contact_form.email.errors.append("That email is already in use.")

        self.render_response("auth/profile/settings.html",            
                             contact_form=contact_form,
                             password_form=password_form)

    @user_required
    def credit(self):
        self.render_response("auth/profile/credit.html")
    
    def get_saved_cards(self):
        stripe_customers = [stripe.Customer.retrieve(c_id) for c_id in 
                            self.user_complete.stripe_customer_ids]
        saved_cards = []
        for stripe_cust in stripe_customers:
            card = {
                "type": stripe_cust["active_card"]["type"],
                "last4": stripe_cust["active_card"]["last4"],
                "exp_month": stripe_cust["active_card"]["exp_month"],
                "exp_year": stripe_cust["active_card"]["exp_year"],
                "customer_id": stripe_cust["id"],
            }                  
            saved_cards.append(card)        
        
        return saved_cards
    
    @user_required
    def credit_add_credit(self):
        saved_cards = self.get_saved_cards()
        
        self.render_response("auth/profile/credit_add_credit.html", 
                             saved_cards=saved_cards)        

    @user_required
    def credit_auto_recharge(self):
        user = self.user_complete
        form = ProfileAutoRechargeForm(is_auto_recharge=user.auto_recharge,
                                       auto_recharge_min=user.auto_recharge_min,
                                       auto_recharge_incr=user.auto_recharge_incr)
        saved_cards = self.get_saved_cards()
        
        self.render_response("auth/profile/credit_auto_recharge.html", 
                             saved_cards=saved_cards,
                             form=form)    
                             
    @user_required
    def update_auto_recharge(self):
        logging.info("Processing auto recharge update...")        
        form = ProfileAutoRechargeForm(self.request.POST)
        logging.info(form.data)
        auto_recharge_custid = self.request.POST.get("credit-card-radios")
        user = self.user_complete
        user.auto_recharge = form.is_auto_recharge.data
        user.auto_recharge_min = form.auto_recharge_min.data
        user.auto_recharge_incr = form.auto_recharge_incr.data
        
        saved_cards = self.get_saved_cards()        
        cust_ids = [c["customer_id"] for c in saved_cards]
        
        if auto_recharge_custid in cust_ids:            
            user.auto_recharge_custid = auto_recharge_custid
        else:
            self.session.add_flash("Invalid credit card selected.", "error")
            return self.render_response("auth/profile/credit_auto_recharge.html", 
                             saved_cards=saved_cards,
                             form=form) 
        
        user.put()
        self.session.add_flash("Auto-recharge settings updated.", "local")
        self.redirect_to("profile_credit_auto_recharge")

    @user_required
    def remove_card(self):
        stripe_customer_id = self.request.POST.get("customer_id")
        self.user_complete.stripe_customer_ids.remove(stripe_customer_id)
        self.user_complete.put()

        self.redirect_to('profile_credit')

    @user_required
    def process_credit(self):
        stripeToken = self.request.POST.get("stripeToken")
        card_selection = self.request.POST.get("credit-card-radios")
        amount = int(self.request.POST.get("credit-amount")) # This is in dollars
        user = self.user_complete
        org = self.user_complete.org.get()
        
        try:
            if card_selection == "new_card":            
                customer = stripe.Customer.create(
                    description = "Stripe Customer for %s" % user.email,
                    card = stripeToken 
                )
                user.stripe_customer_ids.append(customer.id)
                user.put()
                customer_id = customer.id
            else:
                customer_id = card_selection
                
            charge = stripe.Charge.create(
                amount = amount * 100, # This is in cents
                currency = "usd",
                customer = customer_id,
                description = "Add credit of %f for %s" % (amount, user.email),
            )
            add_credit(self.user_complete.org, amount)   
            self.session.add_flash(
                "$%2.f of credit has been successfully added to %s" 
                % (amount, org.full_name), "local"
            )
            
        except stripe.CardError, ex:
            self.session.add_flash(ex.message, "error")
        except Exception, ex:
            self.session.add_flash("Something unexpected has gone wrong. Please contact Legit support.", "error")
            logging.error("Payment processing error: %s" % ex.message)            
        
        self.redirect_to("profile_credit_add_credit")
    
    @user_required
    def permissions(self):
        self.render_response("auth/profile/permissions.html")

class LogoutHandler(BaseHandler):
    """Destroy the user session and send them back to the login screen."""
    @user_required
    def get(self):
        self.auth.unset_session()
        self.session.add_flash("You have been logged out.", "global")
        self.redirect(self.uri_for('login'))            

class ForgotPasswordEmailForm(Form):
    email = TextField('Email', [validators.DataRequired(), validators.Length(min=6, max=50), validators.Email()])

class ForgotPasswordEmailHandler(BaseHandler):
    "Ask the user for the email associated with their account"
    def get(self):
        self.render_response("auth/forgot_password_email.html", form=ForgotPasswordEmailForm())
        
    def post(self):
        form = ForgotPasswordEmailForm(self.request.POST)
        if form.validate():
            d = Developer.query(Developer.email == form.email.data).get()
            if d:
                d.password_reset_token = base64.urlsafe_b64encode(os.urandom(12))
                d.put()
                
                message = mail.EmailMessage(sender="FROM_EMAIL",
                                            to=d.email,
                                            subject="Legit Dev Password Reset",
                                            body="""
Someone (hopefully you) has requested a reset of your Legit Developer account password. If it was you, click the link below to
reset your password. If it wasn't you, delete this email and we can forget this whole thing ever happened.\n\n
%s%s?%s
""" % (SITE_DOMAIN, self.uri_for('forgot_password_set'), urlencode({'email': d.email, 'token': d.password_reset_token})))
                message.send()

                return self.redirect_to("forgot_password_sent")
            else:
                self.session.add_flash("Couldn't find a developer account with that email.", "local")
        self.render_response("auth/forgot_password_email.html", form=form)            
            
class ForgotPasswordSentHandler(BaseHandler):
    "Let the user know we've sent them a password resent email"
    def get(self):
        self.render_response("auth/forgot_password_sent.html")
 
class ForgotPasswordSetForm(Form):
    token = HiddenField()
    email = HiddenField()
    new_password = PasswordField('New Password', [validators.DataRequired(), validators.EqualTo('confirm_password', message="Passwords must match.")])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])
    
class ForgotPasswordSetHandler(BaseHandler):
    "Have the user enter a new password"
    def get(self):
        token = self.request.GET.get('token')
        email = self.request.GET.get('email')
        d = Developer.query(ndb.StringProperty('password_reset_token') == token, Developer.email == email).get()
        if not d:
            self.session.add_flash("Invalid password reset link. Please generate a fresh one.", "local")
            return self.redirect_to('forgot_password_email')
        form = ForgotPasswordSetForm(self.request.GET)            
        self.render_response("auth/forgot_password_set.html", form=form)
        
    def post(self):
        form = ForgotPasswordSetForm(self.request.POST)
        if form.validate():
            d = Developer.query(ndb.StringProperty('password_reset_token') == form.token.data, 
                                Developer.email == form.email.data).get()
            d.password = security.generate_password_hash(form.new_password.data, length=12)
            d.put()
            self.auth.set_session(self.auth.store.user_to_dict(d))
            return self.redirect_to('profile')
        self.render_response("auth/forgot_password_set.html", form=form)    

#################################################
# Site Pages                                    #
#################################################       
class HomeHandler(BaseHandler):
    "Dev site homepage. Where the magic begins."
    @user_required    
    def get(self): 
        self.render_response("home.html")

class GuideHandler(BaseHandler):
    @user_required
    def overview(self):
        self.render_response("guides/overview.html")
    
    @user_required
    def authentication(self):
        self.render_response("guides/authentication.html")
    
    @user_required    
    def submitting(self):
        self.render_response("guides/submitting.html")
    
    @user_required
    def querying(self):
        self.render_response("guides/querying.html")
    
    @user_required
    def pricing(self):
        self.render_response("guides/pricing.html")

# Doc Handlers
def discover_apis():
    apis_folder = 'docs/xml/apis/'
    api_folders = sorted(os.listdir(apis_folder), reverse=False)
    apis = [f for f in api_folders if os.path.isdir(apis_folder+f)]
    
    # Filter the list so only the ready APIs are exposed
    apis = [a for a in apis if a in ('reputation', 'submit')]
    
    return apis


def parse_api_xml(api_name):
    import xml.etree.ElementTree

    api_filename = 'docs/xml/apis/'+api_name+'/'+api_name+'.xml'
    method_base = 'docs/xml/apis/'+api_name+'/methods/'
    method_filenames = sorted([method_base+f for f in os.listdir(method_base) if f.endswith('.xml')])

    with open(api_filename) as api_file:
        api_etree = xml.etree.ElementTree.parse(api_file)

    method_etrees = []
    for method_filename in method_filenames:
        with open(method_filename) as method_file:
            method_etrees.append(xml.etree.ElementTree.parse(method_file))

    api_name = api_etree.find('Name').text
    api_description = api_etree.find('Description').text
    api_baseURL = api_etree.find('BaseURL').text
    api_categories = []
    for cat_etree in api_etree.find('Categories').getiterator('Category'):
        api_categories.append({
            'name': cat_etree.find('Name').text,
            'description': cat_etree.find('Description').text,
            'methods': []
        })

    for method_etree in method_etrees:
        method_cat = method_etree.find('Category').text
        for cat in api_categories:
            if cat['name'] == method_cat:
                cat['methods'].append({
                    'name': method_etree.find('Name').text,
                    'description': method_etree.find('Description').text,
                    'short_description': method_etree.find('ShortDescription').text,
                    'httpmethod': method_etree.find('HttpMethod').text,
                })
                break
                
    return {
        'api_name': api_name,
        'api_description': api_description,
        'api_baseURL':api_baseURL,
        'api_categories':api_categories,
    }
   
def parse_method_xml(api_name, method_name):
        import xml.etree.ElementTree

        method_filename = 'docs/xml/apis/'+api_name+'/methods/'+method_name+'.xml'
        with open(method_filename) as method_file:
            method_etree = xml.etree.ElementTree.parse(method_file)

        method_name = method_etree.find('Name').text
        method_http_method = method_etree.find('HttpMethod').text
        method_description = method_etree.find('Description').text
        method_short_description = method_etree.find('ShortDescription').text
        method_parameters = []
        for param_etree in method_etree.find('Parameters').getiterator('Parameter'):
            method_parameters.append({
                'name': param_etree.find('Name').text,
                'description': param_etree.find('Description').text,
                'required': bool(param_etree.find('Required').text in ('true', 'True', 'yes', 'Yes')),
                'example_value': param_etree.find('ExampleValue').text,
            })

        request_etree = method_etree.find('ExampleRequest')
        method_example_data = request_etree.find('RequestData').text
        method_example_response = request_etree.find('ResponseContent').text

        method_sections = []
        for section_etree in method_etree.getiterator('ExplanatorySection'):
            section = {
                "name": section_etree.find('Name').text,
                "content": section_etree.find('Content').text
            }
               
            tab_section = section_etree.find('TabularContent')
            if tab_section:
                section["table"] = []
                for entry_etree in tab_section.getiterator("Entry"):
                    section["table"].append((entry_etree.find('Key').text,
                                            entry_etree.find('Value').text))
                                            
            method_sections.append(section)                              

        return {
            "method_name":method_name,
            "method_description":method_description,
            "method_http_method":method_http_method,
            "method_parameters":method_parameters,
            "method_example_data":method_example_data,
            "method_example_response":method_example_response,
            "method_sections": method_sections,
        }

def get_api_summaries():
    apis = discover_apis()
    api_data = [parse_api_xml(api) for api in apis]
    
    return api_data
    
class DocAPIHandler(BaseHandler):
    @user_required
    def get(self):
        api_summaries = get_api_summaries()
        api_sections = []
        for api_context in api_summaries:
            api_sections.append(self.jinja2.render_template("docs/api_section.html", **api_context))

        self.render_response("docs/apis.html", api_sections=api_sections,
                                                api_summaries=api_summaries)

# class DocAPISummaryHandler(BaseHandler):
#     def get(self, api_name):
#         parsed_xml = parse_api_xml(api_name)
# 
#         self.render_response("docs/api.html", **parsed_xml)
            
class DocAPIMethodHandler(BaseHandler):
    @user_required
    def get(self, api_name, method_name):
        context = {}
        context['api_summaries'] = get_api_summaries()        
        parsed_api = parse_api_xml(api_name)
        parsed_method = parse_method_xml(api_name, method_name)
        
        context.update(parsed_api)
        context.update(parsed_method)
        
        self.render_response("docs/method.html", **context)

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

    logging.info("About to sign url:")
    logging.info(url)

    req = oauth.Request.from_consumer_and_token(consumer, 
        token=None, http_method=method, http_url=url, 
        parameters=parameters, body=body, is_form_encoded=is_form_encoded)

    req.sign_request(hmac_sig_method, consumer, None)
    
    return req

def create_GET_url(data, resource_url, base_url, consumer):
    # Strip out any empty params
    data = dict((k,v) for k,v in data.items() if v not in (None, ""))            
    qs = "?"+urlencode(data)
    req = create_request(consumer,
                         base_url+resource_url+qs,
                         "GET")
    return req.to_url() #.replace(base_url, "", 1)

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'zomg-this-key-is-so-secret',
}
config['webapp2_extras.auth'] = {
    'user_model': Developer,
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', handler=HomeHandler, name="home"),

    # user auth routes
    webapp2.Route('/signup', handler=SignupHandler, name="signup"),
    webapp2.Route('/login', handler=LoginHandler, name="login"),
    webapp2.Route('/logout', handler=LogoutHandler, name="logout"),    
    # profile
    webapp2.Route('/profile', handler=ProfileHandler, handler_method="credentials", name="profile"),
    webapp2.Route('/profile/credentials', handler=ProfileHandler, handler_method="credentials", name="profile_credentials"),        
    webapp2.Route('/profile/settings', handler=ProfileHandler, handler_method="settings", name="profile_settings"),
    webapp2.Route('/profile/settings/update_contact', handler=ProfileHandler, handler_method="update_contact", name="profile_settings_contact", methods=["POST"]),
    webapp2.Route('/profile/settings/change_password', handler=ProfileHandler, handler_method="change_password", name="profile_settings_password", methods=["POST"]),
    webapp2.Route('/profile/credit', handler=ProfileHandler, handler_method="credit", name="profile_credit"),
    webapp2.Route('/profile/credit/add_credit', handler=ProfileHandler, handler_method="credit_add_credit", name="profile_credit_add_credit"),   
    webapp2.Route('/profile/credit/auto_recharge', handler=ProfileHandler, handler_method="credit_auto_recharge", name="profile_credit_auto_recharge"),          
    webapp2.Route('/profile/credit/process', handler=ProfileHandler, handler_method="process_credit", name="profile_process_credit", methods=["POST"]),
    webapp2.Route('/profile/credit/remove_card', handler=ProfileHandler, handler_method="remove_card", name="profile_remove_card", methods=["POST"]),     
    webapp2.Route('/profile/credit/update_auto_recharge', handler=ProfileHandler, handler_method="update_auto_recharge", name="profile_update_auto_recharge", methods=["POST"]), 
    webapp2.Route('/profile/permissions', handler=ProfileHandler, handler_method="permissions", name="profile_permissions"),
    

    webapp2.Route('/forgot_password_email', handler=ForgotPasswordEmailHandler, name="forgot_password_email"),
    webapp2.Route('/forgot_password_sent', handler=ForgotPasswordSentHandler, name="forgot_password_sent"),
    webapp2.Route('/forgot_password_set', handler=ForgotPasswordSetHandler, name="forgot_password_set"),

    # guides
    webapp2.Route('/overview', handler=GuideHandler, name="overview", handler_method="overview", methods=["GET"]),
    webapp2.Route('/authentication', handler=GuideHandler, name="authentication", handler_method="authentication", methods=["GET"]),
    webapp2.Route('/submitting', handler=GuideHandler, name="submitting", handler_method="submitting", methods=["GET"]),
    webapp2.Route('/querying', handler=GuideHandler, name="querying", handler_method="querying", methods=["GET"]),
    # webapp2.Route('/pricing', handler=GuideHandler, name="pricing", handler_method="pricing", methods=["GET"]),

    # docs
    webapp2.Route('/docs/apis/', handler=DocAPIHandler, name='doc_apis'),
    # webapp2.Route('/docs/apis/<api_name>', handler=DocAPISummaryHandler, name='doc_api_summary'),
    webapp2.Route('/docs/apis/<api_name>/<method_name>', handler=DocAPIMethodHandler, name='doc_api_method'),

    # tool
    webapp2.Route('/tool', handler=ToolAPIHandler, name='api_tool'),

], debug=False, config=config)












