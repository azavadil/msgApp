import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

import webapp2
import jinja2
import hmac
import hashlib
import re
import cgi
import random
import string
import urllib
import json
import logging
import time
import hashsecret
import markdown

from google.appengine.ext import db
from google.appengine.api import memcache




template_dir = os.path.join(os.path.dirname(__file__), 'templates')


jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),\
								autoescape = True, extensions=['jinja2.ext.autoescape'])
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


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
	
def valid_groupname(groupname): 
	GROUP_RE = re.compile(r"^[a-zA-Z0-9_]{3,10}$")
	if GROUP_RE.match(groupname): 
		return True
	return False
	

########## PERMALINK FUNCTION ##########

##  the URLs are organized by date and title  
##  to create a unique identifier
##  Format is /year/day/title
##  e.g. /2013/150/lebron-wins-title


def get_id_from(input_string):
    
    regexp = r'[0-9]+$'
		
    return int(input_string[re.search(regexp,input_string).start():\
				re.search(regexp,input_string).end()])
		
					
########## DATABASE CLASSES ##########	
def users_DB_rootkey(group = 'default'):
	""" 	
		parent keys are used to ensure all users are in the same entity group. 
		The parent key is in the form kind/key_name (e.g. user_DB/'default') 
		Child keys are in the format kind/parent/ID (e.g. user_DB/'default'/XXXXXX)
		
		There's an equivalent format user_DB(key_name=group) 
	"""
	return db.Key.from_path('user_DB', group)	
    

class user_DB(db.Model):
    ##required = True, will raise an exception if we try to create 
    ##content without a title
    user_name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    ##auto_now_add sets created to be the current time
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
	
    @classmethod
    def db_by_id(cls, uid):
    	return user_DB.get_by_id(uid,users_DB_rootkey())

    @classmethod
    def db_by_name(cls, name):
    	u = user_DB.all().filter('user_name =', name).get()
    	return u
		
		
    @classmethod   
    def register(cls, name, pw, email = None):
		
		current_pw_hash = make_pw_hash(name, pw)
		
		return user_DB(parent = users_DB_rootkey(),\
            				user_name = name,\
							pw_hash = current_pw_hash)

    @classmethod
    def db_login(cls, name, pw):
		u = cls.db_by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u, ''
		elif u:
			return u, "Username and password don't match"
		else:
			return None, "Invalid login"

########## MESSAGE DATABASE ##########
	
def message_DB_rootkey(group = 'default'):
	""" 
		message_DB_rootkey takes a string and returns a key. 
		The returned key is used as the parent key for the entire 
		Message class. For this class a parent key isn't strictly 
		necessary except to ensure consistency. 
	"""
	return db.Key.from_path('Message', group)
		
class Message(db.Model):
    ##required = True, will raise an exception if we try to create 
    ##content without a title
	author = db.StringProperty(required = True)
	authorID = db.IntegerProperty(required = True)
	recipientIDs = db.ListProperty(long, required = True)
	subject = db.StringProperty(required = False)
	body = db.TextProperty(required = False)
	hasBeenRead = db.StringProperty(required = True, indexed = False)
	##auto_now_add sets created to be the current time
	created = db.DateTimeProperty(auto_now_add = True)
	
	def render(self, b_summarize = None):
		self._render_text = self.body.replace('\n','<br>')
		return render_str("formattedMsg.html", page = self, summarize_text = b_summarize)
    	
	@classmethod 
	def db_by_id(cls, msgID):
		return Message.get_by_id(msgID, message_DB_rootkey())
	
    		
########## USER GROUP DATABASE ##########

def group_DB_rootkey(group = 'default'):
	""" 
		group_DB_rootkey takes a string and returns a key. 
		The returned key is used as the parent key for the entire 
		Message class. For this class a parent key isn't strictly 
		necessary except to ensure consistency. 
	"""
	return db.Key.from_path('UserGroup', group)

	
class UserGroup(db.Model):
    groupname = db.StringProperty(required = True)
    groupIDs = db.ListProperty(long, required = True)
    groupAuthor = db.IntegerProperty(required = True, indexed = False)
    	
   


########## CACHING FUNCTIONS ##########		
		
##  cache_user is used for our user tracking system
##  (e.g. when the front page is generated or we generate
##   a user page) 

	
def cache_user(userID, update = False):
	""" (str, bool) -> user_DB entity 
		param userID: string that's used as database key
        param update: specifies whether the cache should be overwritten
	"""
	user_result = memcache.get(userID)
	if user_result is None or update:
		logging.error("Cache_user - DB hit")
		user_result = user_DB.db_by_id(int(userID))	
		memcache.set(userID, user_result)
	return user_result

def cache_user_group(userID, update = False): 
	""" (int, bool) -> Group entities
		param userID: string that's used as database key
        param update: specifies whether the cache should be overwritten
	"""
	logging.error("cache_user_group called")
	
	user_group_key = "group_" + str(userID)
	group_result = memcache.get(user_group_key)
	if group_result is None or update: 
		group_result = UserGroup.all().filter("groupIDs =",userID).fetch(10)
		logging.error("cache_user_group, update %s, %s"%(user_group_key, group_result))
		memcache.set(user_group_key, group_result)
	return group_result
		
def cache_group(group_name, update = False): 
	""" (str, bool) -> Group entities
		param group_name: string that's used as database key
        param update: specifies whether the cache should be overwritten
	"""
	
	group_result = memcache.get(group_name)
	if group_result is None or update: 
		group_result = UserGroup.all().filter("groupname =",group_name.lower()).get()
		memcache.set(group_name, group_result)
	return group_result

########## REQUEST HANDLERS ##########
	
##  baseHandler is the main request handler that
##  other handlers inherit from. We put the convience  
##  methods in baseHandler
		
########## GENERAL PURPOSE HANDLER ##########							
class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
    def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)
	
    def render(self, template, **kw):
    	self.write(self.render_str(template, **kw))
	
    def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie','%s=%s; Path=/' % (name, cookie_val))
	
    def read_secure_cookie(self, name):
        """(str) -> str or Nonetype
            read_secure_cookie uses a python shortcut
            if expression 1 and expression 2 match, the return value is expression 1
            if expression 1 and expression 2 don't match, the return value is expression 2
			if expression 1 or expression 2 is False, the return value is false
			
			check_secure_val takes the cookie value which is in the format 
			userID | hashed value and returns the userID portion if the hashed value
			validates
			e.g. 1 | 2b1423ca5183a0ff98bda78157ac08df would return 1 
        """
        
    	cookie_val = self.request.cookies.get(name)
    	return cookie_val and check_secure_val(cookie_val)

    def handler_login(self, user):
    	self.set_secure_cookie('user_id', str(user.key().id()))

    def handler_logout(self):
		"""()->Nonetype
           handler_logout is implemented by setting the user_id value of the
           cookie to be blank
        """
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
		"""
           () -> Nonetype
           initialize check to see if the user is logged in/logged out
           Allows the app to display differently depending on whether
           the user is logged in. The framework calls webapp2 with
           every request triggering initialize with every request.
           Initialize checks for a user cookie, if a cookie exists,
           initialize checks the cookie and sets the cookie if the cookie is valid
        """
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')				## return string value of user ID
		self.user = uid and cache_user(uid)
		if self.user:
			self.inbox = Message.all().filter("recipientIDs =", self.user.key().id()).order("-created")
			self.outbox = Message.all().filter("authorID =", self.user.key().id())
			
    def notfound(self):
		self.error(404)
		self.write('<h1>404: Note Found</h1> Sorry, my friend, but that page does not exist. ')					
			
########## FRONT PAGE ##########	
class MainPage(BaseHandler):
	def get(self):
		##query the database for all msgs in the users inbox 
		## userInbox = cache_inbox(self.user)   
		
		## pass the inbox as a parameter to render 
		if not self.user: 
			self.render("summaryPanel.html")
		else:
			self.render("summaryPanel.html", numMsgs = self.inbox.count(), numSentMsgs = self.outbox.count(), msgs = self.inbox.fetch(20))
			
	
	def post(self):
		""" we have two cases where a form can be posted from the MainPage. 
		    If the user has not logged in then we post login information. 
			The app can also post from the MainPage when the user is 
			making, joining, or leaving a group 
		"""
		##hold what the user entered
		input_username = self.request.get('username')
		input_password = self.request.get('password')
	
		##check the password
		user, pw_msg = user_DB.db_login(input_username,input_password)
		## db_login returns the user id and the empty string if the password validates, 
		## the user and the msg "Username and password don't match" if the user was found 
		## but the password doesn't validate, and "Invalid login" otherwise
		
		if user and pw_msg == '': 
			self.handler_login(user)
			self.redirect("/")
		else:
			self.render('base.html', name_provided = input_username, password_error = pw_msg) 
		
		

	
########## COMPOSE MESSAGE ##########				
class ComposeMessage(BaseHandler):
	def get(self):
		if not self.user:
			self.error(400)
			return
		
		self.render("composeMsg.html", numMsgs = self.inbox.count(), numSentMsgs = self.outbox.count())
		
	def post(self):
		if not self.user:
			self.error(400)
			return
		
		##retreive the field named "subject" and the field named "content"
		##from the form submission
		recipient = self.request.get("recipient")
		msg_subject = self.request.get("subject")
		msg_body = self.request.get("body")
		
		
		## check if the message is a global broadcast
		if recipient.lower() == "all": 
			recipients = db.Query(user_DB, keys_only=True)
			
			recipientIDs = map(lambda x: x.id(), list(recipients))
			logging.error("composeMsg = %s, %s"%(recipientIDs,type(recipientIDs))) 
			
			to_store = Message(parent = message_DB_rootkey(),\
							author = self.user.user_name,\
							authorID = self.user.key().id(),\
							recipientIDs = map(lambda x:x.id(),list(recipients)),\
							subject = msg_subject,\
							body = msg_body,\
							hasBeenRead = "not-read-style")
			to_store.put()
			self.redirect("/")
			
			
		group_qry = UserGroup.all().filter("groupname =", recipient).get()	
		if group_qry: 
			##create a new Message entity
	
			to_store = Message(parent = message_DB_rootkey(),\
							author = self.user.user_name,\
							authorID = self.user.key().id(),\
							recipientIDs = group_qry.groupIDs,\
							subject = msg_subject,\
							body = msg_body,\
							hasBeenRead = "not-read-style")
		
			to_store.put()
			self.redirect("/")
	
		
		##Query the database for the recipient
		recipientEntity = user_DB.db_by_name(recipient) 
		
		
		if recipientEntity:
			##create a new Message entity
	
			to_store = Message(parent = message_DB_rootkey(),\
							author = self.user.user_name,\
							authorID = self.user.key().id(),\
							recipientIDs = [recipientEntity.key().id()],\
							subject = msg_subject,\
							body = msg_body,\
							hasBeenRead = "not-read-style")
		
			
			##store the new blog object
			to_store.put()
			self.redirect("/")
			
		else: 
			error = "That recipient doesn't exist"
			
			##pass the error message to the render fuction
			##the function then passes 'error' to the form
			self.render("composeMsg.html",recipient = recipient, subject = msg_subject, body = msg_body, error=error)


########## COMPOSE MESSAGE ##########				
class ViewMessage(BaseHandler):
	def get(self,path):
		if not self.user:
			self.error(400)
			return
		
		## we're using the key as a url. The app extracts the URL (which is actually a key) 
		## and uses the key to retrieve the message from the database. 
		## use path[1:] to strip off the leading "/"
		msg = Message.db_by_id(int(path[1:]))
		
		## check that the user that's logged in is actually a reipient of this message
		## if not, fail silently. Don't give the user an more information 
		if self.user.key().id() not in msg.recipientIDs: 
			self.error(400)
			return 
		
		msg.hasBeenRead = "read-style" 
		msg.put() 
		
		self.render("viewMsg.html", message_HTML = markdown.markdown(msg.body), numMsgs = self.inbox.count(), numSentMsgs = self.outbox.count())
	
	def post(self,path): 
		msg = Message.get(db.Key(path[1:]))
		logging.error("ViewMsg = %d"%len(msg.recipientIDs))
		if len(msg.recipientIDs) == 1: 
			msg.delete()
		else: 
			msg.recipientIDs.remove(self.user.key().id())
			msg.put()
		self.redirect("/") 
		
########## GROUPS ##########				
class ViewGroup(BaseHandler):
	def get(self):
		if not self.user:
			self.error(400)
			return
		
		## we're using the key as a url. The app extracts the URL (which is actually a key) 
		## and uses the key to retrieve the message from the database. 
		## use path[1:] to strip off the leading "/"
		groupsUserBelongsTo = cache_user_group(self.user.key().id()); 
		temp = UserGroup.all().filter("groupIDs = ", self.user.key().id()).get()
		logging.error("ViewGroup/Get groups =%s, %s"%(groupsUserBelongsTo,temp))
		
		## check that the user that's logged in is actually a reipient of this message
		## if not, fail silently. Don't give the user an more information 
		
		self.render("viewGroup.html", groups = groupsUserBelongsTo)
	
	def post(self): 
		
		groupsUserBelongsTo = cache_user_group(self.user.key().id());
		input_groupname = self.request.get("groupname"); 
		selected_action = self.request.get("selectedAction"); 		
		
		
		error_msg = ""
		if not valid_groupname(input_groupname): 
			error_msg = "Please enter a valid groupname"
			self.render("viewGroup.html", user_input_groupname = input_groupname, groups = groupsUserBelongsTo, error = error_msg)
		
		if selected_action == "makeGroup": 
			qry = cache_group(input_groupname) 
			
			if qry: 
				error_msg = "That group already exists" 
				self.render("viewGroup.html", user_input_groupname = input_groupname, groups = groupsUserBelongsTo, error = error_msg)
			else:
				to_store = UserGroup(parent = group_DB_rootkey(), groupname = input_groupname.lower(),\
							groupIDs = [self.user.key().id()], groupAuthor = self.user.key().id())
				to_store.put()
				cache_group(input_groupname, update=True)
				cache_user_group(self.user.key().id(), update=True)
				self.redirect("/group")
		
		if selected_action == "joinGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html", user_input_groupname = input_groupname, groups = groupsUserBelongsTo, error = error_msg)
			else: 
				qry.groupIDs.append(self.user.key().id())
				qry.put()
				cache_user_group(self.user.key().id(), update=True)
				self.redirect("/group")
		
		if selected_action == "leaveGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html", user_input_groupname = input_groupname, groups = groupsUserBelongsTo, error = error_msg)
			else: 
				qry.groupIDs.remove(self.user.key().id())
				qry.put()
				cache_user_group(self.user.key().id(), update=True)
				self.redirect("/group")
		
		if selected_action == "deleteGroup": 
			qry = UserGroup.all().filter("groupname =", input_groupname.lower()).get()
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html", user_input_groupname = input_groupname, groups = groupsUserBelongsTo, error = error_msg)
			elif qry.groupAuthor != self.user.key().id(): 
				error_msg = "Only group author can delete group"
				self.render("viewGroup.html", user_input_groupname = input_groupname, groups = groupsUserBelongsTo, error = error_msg)
			else: 
				## we have a problem here in that we need to update the cache for all members of the group
				qry.delete()
				for user in qry.groupIDs: 
					cache_user_group(user, update=True)
				
				self.redirect("/group")
				
		
		
########## SIGNUP PAGE ##########						
class SignupPage(BaseHandler):
	
	def get(self):
		if self.user:
			self.error(400)
			return
			
		self.render("signupPage.html", isSignupPage = True)
	
	def post(self):
		
		## check if the user is logged in. If the user is logged in then we 
		## shouldn't be on this page 
		if self.user:
			self.error(400)
			return
	
		##store what the user entered
		self.input_username = self.request.get('username')
		self.input_password = self.request.get('pwd1')
		self.password_verify = self.request.get('pwd2')
		
		params = dict(name_provided = self.input_username)

		error_msg = "" 
		have_error = False
		
		##test for validity
		##test for valid user_name
		if not valid_username(self.input_username):
			error_msg += "That's not a valid username"
			have_error = True

		if not valid_password(self.input_password):
			error_msg += "That wasn't a valid password" if error_msg == "" else ", that isn't a valid password" 
			have_error = True
		
		if self.input_password != self.password_verify:
			error_msg += "Passwords don't match" if error_msg == "" else ", passwords don't match" 
			have_error = True
	
		if have_error:
			params["fallback_error"] = error_msg
			self.render('signupPage.html',**params)	
			##set cookie, redirect to welcome page	
		else: 
			##set cookie, redirect to welcome page	
			self.done()
		
	def done(self,*a,**kw):
		"""not implemented in signupPage. Overwriten in Register below"""
		raise NotImplementedError

## Register's purpose is to extend the signupPage class to include an additional check 
## of whether a user exists before adding a user to the database. Register is implemented
## by inheriting from signupPage and overwriting the done() method. 
			
class Register(SignupPage):

    def done(self):
    ##make sure the user doesn't already exist
    ##username in self.username is a field in the signup page. 
		user = user_DB.db_by_name(self.input_username)
		if user:
			msg = 'That user already exists.'
			self.render('signupPage.html', fallback_error = msg, isSignupPage = True)
		else:
			email_addr = self.input_username + "@umail.com"
			user = user_DB.register(self.input_username, self.input_password)
			user.put()
			
			self.handler_login(user)
			## [NTD: uncomment] cache_user(user.key().id())
			self.redirect("/")
			
		
########## LOGOUT PAGE ##########					
class LogoutPage(BaseHandler):
	
    def get(self):
		self.handler_logout()
		##send user to the page they came from
		self.redirect("/")
		
		

########## DELETE POST ##########
class DeletePost(BaseHandler): 
	
	def get(self, path):
		if not self.user:
			self.error(400)
			return
		
			
		logging.error('deletePost - get - path %s'%path)
		markedForDeletion = insiderContent.by_path(path).get()
		insiderContent.delete(markedForDeletion); 		
		self.redirect("/edit")
		
##anything that is in paratheses gets passed in to the handler
##the regular expression matches ()		

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+)*)'

app = webapp2.WSGIApplication([('/', MainPage),
								('/newMsg', ComposeMessage),
								('/group', ViewGroup), 
								('/signup', Register),
								('/logout',LogoutPage),
								('/delete' + PAGE_RE, DeletePost), 
								( PAGE_RE, ViewMessage),
								],debug = True)
