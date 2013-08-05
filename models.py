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

import json
import logging
import hashlib

from google.appengine.ext import ndb
from webapp2_extras.appengine.auth import models as auth_models

from cryptography import hash_value, encrypt_value, decrypt_value

############################
# API Management           #
############################
class Organization(ndb.Model):
    name = ndb.StringProperty()
    full_name = ndb.StringProperty()
    is_intake_analyzed = ndb.BooleanProperty()
    org_type = ndb.StringProperty()
    credit = ndb.FloatProperty(default=0)
    
class Invite(ndb.Model):
    code = ndb.StringProperty()
    org = ndb.KeyProperty(kind=Organization)
    is_used = ndb.BooleanProperty(default=False)

INITIAL_PERMISSIONS = ['identity_risk',]#['submit', 'query']    
class Developer(auth_models.User):
    name = ndb.StringProperty()
    email = ndb.StringProperty()
    org = ndb.KeyProperty(kind=Organization)
    invite_code = ndb.StringProperty()
    consumer_key = ndb.StringProperty()
    consumer_secret = ndb.StringProperty()
    permissions = ndb.StringProperty(repeated=True)    
    stripe_customer_ids = ndb.StringProperty(repeated=True)
    auto_recharge = ndb.BooleanProperty()
    auto_recharge_min = ndb.IntegerProperty()
    auto_recharge_incr = ndb.IntegerProperty()
    auto_recharge_custid = ndb.StringProperty()
    
    is_admin = ndb.BooleanProperty(default=False)
    
class Price(ndb.Model):
    name = ndb.StringProperty()
    price = ndb.FloatProperty(default=0)

class RequestLog(ndb.Model):
    created = ndb.DateTimeProperty(auto_now=True)
    request_url = ndb.StringProperty()
    request_resource = ndb.StringProperty()
    request_outh_parameters = ndb.JsonProperty()
    request_parameters = ndb.JsonProperty()  
    request_method = ndb.StringProperty()      
    developer = ndb.KeyProperty(kind=Developer)
    org = ndb.KeyProperty(kind=Organization)    
    price = ndb.FloatProperty()
    actually_charged = ndb.FloatProperty()
    response_code = ndb.IntegerProperty()
    response_text = ndb.TextProperty()
    api_version = ndb.TextProperty()

    @property
    def response_json(self):
        try:
            return json.loads(self.response_text)            
        except:
            return None

############################
# Intake                   #
############################
PII_FIELDS = ("name", "address", "ssn", "phone", "email",
              "facebook_id", "twitter_id", "linkedin_id",
              "drivers_lic")
              
class IntakeUser(ndb.Expando):
    org = ndb.KeyProperty(kind=Organization)
    developer = ndb.KeyProperty(kind=Developer)
    created = ndb.DateTimeProperty(auto_now=True)
    updated = ndb.DateTimeProperty(auto_now_add=True)
    api_type = ndb.StringProperty()
    
    user_id = ndb.StringProperty()
    user_id_enc = ndb.StringProperty()

    # PII
    name = ndb.StringProperty()
    address = ndb.StringProperty()
    ssn = ndb.StringProperty()
    phone = ndb.StringProperty()
    email = ndb.StringProperty()    
    facebook_id = ndb.StringProperty()
    twitter_id = ndb.StringProperty()
    linkedin_id = ndb.StringProperty()
    drivers_lic = ndb.StringProperty()
    
    name_enc = ndb.StringProperty()
    address_enc = ndb.StringProperty()
    ssn_enc = ndb.StringProperty()
    phone_enc = ndb.StringProperty()
    email_enc = ndb.StringProperty()    
    facebook_id_enc = ndb.StringProperty()
    twitter_id_enc = ndb.StringProperty()
    linkedin_id_enc = ndb.StringProperty()
    drivers_lic_enc = ndb.StringProperty()
    
    # Reputation
    transaction_count = ndb.IntegerProperty()
    review_count = ndb.IntegerProperty()
    positive_review_percentage = ndb.FloatProperty()
    negative_events = ndb.StringProperty() # This should likely be a structured / repeated property
    date_joined = ndb.DateProperty()
    date_banned = ndb.DateProperty()
    reason_banned = ndb.StringProperty()
    
    def pii_dict(self):
        self_dict = self.to_dict()
        for k in self_dict.keys():
            if k not in PII_FIELDS:
                del self_dict[k]

        return self_dict
    
    @classmethod
    def create_or_update(cls, fields, dev_key, org_key, api_type,
                         existing_user=None, pre_hashed=False):
        """
        Creates an IntakeUser model from the given data or updates 
        an existing model.
        
        Note that this method DOES persist the resulting model to the database.
        
        Args:
            fields: dictionary of field -> value
            org_key: entity key for the org this user belongs to
            dev_key: entity key for the dev who uploaded this user
            existing_model: an existing intake user model to be updated
            pre_hashed: bool indicating whether the PII has already been hashed.
            db_key: key of the database entity to use as an ancestor for this 
                    user.
            
        Returns:
            An intake user model that has been persisted to the DB.
        """
        if existing_user:
            intake_user = existing_user
        else:
            intake_user = IntakeUser()

        intake_user.org = org_key
        intake_user.developer = dev_key
        intake_user.api_type = api_type

        values_to_set = {}           
        for field, value in fields.items():
            # Hash and encrypt the PII data     
            if field in (('user_id',) + PII_FIELDS):
                # Only save an encrypted version if we got raw data, it's 
                # a bit silly to save a copy of the raw pre-hashed data.
                
                if ((isinstance(value, str) or isinstance(value, unicode))
                    and not value.strip()):
                    # don't even save pure whitespace PII
                    continue
                    
                if not pre_hashed:
                    values_to_set[field+"_enc"] = encrypt_value(value)
                value = hash_value(value, pre_hashed=pre_hashed)
                         
            values_to_set[field] = value

        for key, value in values_to_set.items():
            setattr(intake_user, key, value)
        
        intake_user.put()
        
        return intake_user
    
class CombinedUser(ndb.Model):
    intake_users = ndb.KeyProperty(kind=IntakeUser, repeated=True)
    orgs = ndb.KeyProperty(kind=Organization, repeated=True)
    
    user_id = ndb.StringProperty(repeated=True)
    name = ndb.StringProperty(repeated=True)
    address = ndb.StringProperty(repeated=True)
    ssn = ndb.StringProperty(repeated=True)
    phone = ndb.StringProperty(repeated=True)
    email = ndb.StringProperty(repeated=True)    
    facebook_id = ndb.StringProperty(repeated=True)
    twitter_id = ndb.StringProperty(repeated=True)
    linkedin_id = ndb.StringProperty(repeated=True)
    drivers_lic = ndb.StringProperty(repeated=True)
    
    legit_report = ndb.JsonProperty()
    
    @classmethod
    def create(cls, intake_users, legit_report):
        cu = cls()
        
        for iu in intake_users:
            org_name = iu.org.get().name
            if iu.key not in cu.intake_users:
                cu.intake_users.append(iu.key)
                for attr in PII_FIELDS:
                    iu_attr = getattr(iu, attr)
                    cu_attrs = getattr(cu, attr) or []
                    if iu_attr and iu_attr not in cu_attrs:                        
                        logging.info("COMBINED USER ATT: %s" % cu_attrs)
                        logging.info("INTAKE USER ATT: %s" % iu_attr)
                        cu_attrs.append(iu_attr)
                        setattr(cu,attr,cu_attrs)
                
                if iu.org not in cu.orgs:
                    cu.orgs.append(iu.org)
                    
                user_id = "%s::%s" % (org_name, iu.user_id)
                if user_id not in cu.user_id:
                    cu.user_id.append(user_id)
       
        cu.legit_report = legit_report        
        
        return cu
    
    # def merge(self, to_merge):
    #     for attr in ('intake_users', ) + PII_FIELDS:
    #         combined_attr = list(set(getattr(self, attr) + getattr(to_merge, attr)))
    #         setattr(self,attr,combined_attrs)
    #         
    # def add_intake(self, intake_user):
    #     if intake_user.key not in self.intake_users:
    #         self.intake_users.append(intake_user.key)
    #     for attr in PII_FIELDS:
    #         value = getattr(intake_user, attr)
    #         if value and value not in getattr(self, attr):
    #             getattr(self, attr).append(value)




