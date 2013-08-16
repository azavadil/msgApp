import hashsecret
import hmac
import hashlib
import cgi
import re

########## PASSWORD STORAGE ##########

## put the secret into another module and change to a unique 
## secret for your app

SECRET = hashsecret.getSecret()

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw,salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s|%s' %(h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)
	
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()
	
def make_secure_val(s):
    """make secure value is used to generate outgoing keys
    to be sent and stored by the browser"""
    ##s is the string
    ##hash_str(s) the is hashed value of the string
    return '%s|%s' %(s, hash_str(s))

def check_secure_val(h):
    """(str) -> str or Nonetype
        check_secure_val take a string in the format
        {value} | {hashed value of (value + secret)}
        and returns the value if the hashing the value
        the secret matches the hash value component of the string
    """ 
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
		
def gray_style(lst):
    for n, x in enumerate(lst):
	if n % 2 == 0:
		yield x, ''
	else:
		yield x, 'gray'
		
########## PASSWORD VERIFICATION ##########		

def escape_html(input_string):
    return cgi.escape(input_string,quote=True)

def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    if USER_RE.match(username):
		return True 
    return False

def valid_password(user_password):
	""" 
		require 1 uppercase, 1 lowercase, 1 digit, length of at least 6
		
		^                  		the start of the string
		(?=.*[a-z])        		use positive look ahead to see if at least one lower case letter exists
		(?=.*[A-Z])        		use positive look ahead to see if at least one upper case letter exists
		(?=.*\d)           		use positive look ahead to see if at least one digit exists
		.+                 		gobble up the entire string
		$                  		the end of the string
	"""
	PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)\w{6,20}$")
	if PASSWORD_RE.match(user_password):
		return True 
	return False
	
def valid_email_address(email_address):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    if EMAIL_RE.match(email_address):
		return True 
    return False