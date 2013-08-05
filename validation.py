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

import re

def validate_ssn(ssn):
    """
    SSNs should be in 123-12-1234 format, although we accept anything that
    has 9 digits in it, and then re-format it into the standard format.
    """
    if not ssn.isdigit():
        raise ValueError("Non-numeric SSN Number: %s" % ssn)
        
    if len(ssn) != 9:
        raise ValueError("Incorrect length for SSN number: %s" % ssn)
    
def validate_email(email):
    """
    Emails are notoriously hard to validate. We accept anything
    in the [characters]@[characters].[characters] format.
    """
    if not re.match(r'^.+@[^.].*\.[a-z]{2,10}$', email, flags=re.IGNORECASE):
        raise ValueError("Invalid email address: %s" % email)
            
def validate_phone(phone):
    """
    Phone numbers should be in E.164 format:
    +[country code][number]
    
    So an example US number would be:
    +14152329700, since the US country code is 1.
    
    Maximum # of digits is 15. We set an abitrary minium length of 6, 
    unclear if there is a true official minium for international numbers.   
    """ 
    if not re.match(r'^\+\d{6,15}$', phone):
        raise ValueError("Invalid phone number: %s" % phone)
    
def validate_name(name):
    """
    We'll take anything.
    """
    pass
    
def validate_address(address):
    """
    We'll take anything
    """
    pass
    
def validate_facebook_id(facebook_id):
    if not facebook_id.isdigit():
        raise ValueError("Invalid facebook id: %s" % facebook_id)
            
def validate_twitter_id(twitter_id):
    if not twitter_id.isdigit():
        raise ValueError("Invalid twitter id: %s" % twitter_id)
            
def validate_linkedin_id(linkedin_id):
    if not linkedin_id.isdigit():
        raise ValueError("Invalid linkedin id: %s" % linkedin_id)
    
def validate_drivers_lic(drivers_lic):
    pass
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    