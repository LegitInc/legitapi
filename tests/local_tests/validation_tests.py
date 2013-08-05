from nose.tools import eq_, ok_, raises

import validation

#################
# SSN           #
#################
def test_correct_ssn():
    validation.validate_ssn("111223333")
    
@raises(ValueError)
def test_hyphen_ssn():
    validation.validate_ssn("111-22-1234")
    
@raises(ValueError)
def test_short_ssn():
    validation.validate_ssn("12345678")

@raises(ValueError)
def test_long_ssn():
    validation.validate_ssn("1234567890")

#################
# Email         #
################# 
    
    