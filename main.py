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
import urlparse
from collections import OrderedDict


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
		(?=.*[a-z])        		use positive look ahead to see if at 
								least one lower case letter exists
		(?=.*[A-Z])        		use positive look ahead to see if at 
								least one upper case letter exists
		(?=.*\d)           		use positive look ahead to see if at 
								least one digit exists
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
		Child keys are in the format kind/parent/ID 
		(e.g. user_DB/'default'/XXXXXX)
		
		There's an equivalent format user_DB(key_name=group) 
	"""
	return db.Key.from_path('user_DB', group)	
    

class user_DB(db.Model):
	##required = True, will raise an exception if we try to create 
	##content without a title
	user_name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	msg_file = db.ReferenceProperty(required = True)
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
	def register(cls, name, pw, msg_file_key):
		current_pw_hash = make_pw_hash(name, pw)
		
		return user_DB(parent = users_DB_rootkey(),\
            				user_name = name,\
							pw_hash = current_pw_hash,\
							msg_file = msg_file_key)

	@classmethod
	def db_login(cls, name, pw):
		u = cls.db_by_name(name)	
		if u and valid_pw(name, pw, u.pw_hash):
			return u, ''
		elif u:
			return u, "Username and password don't match"
		else:	
			return None, "Invalid login"

##
# Implementation note: 
# --------------------
# class: Message
# 
##
	
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
	subject = db.StringProperty(required = False)
	body = db.TextProperty(required = False)
	recipientKeys = db.ListProperty(db.Key, required = True, indexed = False) 
	hasBeenRead = db.StringProperty(required = False)
	##auto_now_add sets created to be the current time
	created = db.DateTimeProperty(auto_now_add = True)
	
	def render(self, b_summarize = None):
		self._render_text = self.body.replace('\n','<br>')
		return render_str("formattedMsg.html",\
							page = self,\
							summarize_text = b_summarize)
    	
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
	groupKeys = db.ListProperty(db.Key, required = True)
	groupAuthor = db.ReferenceProperty(required = True, indexed = False)
    	
	@classmethod
	def db_by_name(cls, groupname): 
		return UserGroup.all().ancestor(group_DB_rootkey()).filter("groupname = ", groupname).get()

def usermsg_DB_rootkey(group = 'default'):
	""" 
		group_DB_rootkey takes a string and returns a key. 
		The returned key is used as the parent key for the entire 
		Message class. For this class a parent key isn't strictly 
		necessary except to ensure consistency. 
	"""
	return db.Key.from_path('MsgFile', group)
		
##
# Class: UserMsg
# -------
#
#
##

class MsgFile(db.Model):
	messageKeys = db.ListProperty(db.Key, required = True, indexed = False)
	unreadKeys = db.ListProperty(db.Key, required = True, indexed = False)
	sentKeys = db.ListProperty(db.Key, required = True, indexed = False)
	
	@classmethod
	def register(cls): 
		msgFile = MsgFile(parent = usermsg_DB_rootkey())
		msgFile.put()
		return msgFile
		
	
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

def cache_user_group(user, update = False): 
	""" (int, bool) -> Group entities
		param userID: string that's used as database key
        param update: specifies whether the cache should be overwritten
	"""
	# REFACTOR DELETE CTRLF LOGGING
	logging.error("cache_user_group called")
	
	user_group_key = "group_" + str(user.key().id())
	list_of_users_groups = memcache.get(user_group_key)
	if list_of_users_groups is None or update: 
		list_of_users_groups = UserGroup.all().ancestor(group_DB_rootkey()).filter("groupKeys =",user.key()).fetch(10)
		# REFACTOR DELETE
		logging.error("cache_user_group, update %s, %s"%(user_group_key, list_of_users_groups))
		memcache.set(user_group_key, list_of_users_groups)
	return list_of_users_groups
		
def cache_group(groupname, update = False): 
	""" (str, bool) -> Group entities
		param group_name: string that's used as database key
        param update: specifies whether the cache should be overwritten
	"""
	
	group_result = memcache.get(groupname)
	if group_result is None or update: 
		group_result = UserGroup.all().filter("groupname =",groupname.lower()).get()
		memcache.set(groupname, group_result)
	return group_result

##
# Implementation note: Request Handlers
# -------------------------------------
# baseHandler is the main request handler that other handlers inherit from. We put the convience  
# methods in baseHandler
## 
		
##
# Class: BaseHandler 
# ------------------
# 
## 
							
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
            if expression 1 and expression 2 match, 
			the return value is expression 1
            if expression 1 and expression 2 doesn't match, 
			the return value is expression 2
			if expression 1 or expression 2 is False, 
			the return value is false
			
			check_secure_val takes the cookie value which 
			is in the format userID | hashed value and returns 
			the userID portion if the hashed value
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
           initialize checks the cookie and sets the cookie if the 
		   cookie is valid
        """
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')				## return string value of user ID
		self.user = uid and cache_user(uid)
		if self.user:
			userMsgFile = self.user.msg_file
			self.inbox = sorted(db.get(userMsgFile.messageKeys),\
			key=lambda x:x.created, reverse=True)
			self.outbox = sorted(db.get(userMsgFile.sentKeys),\
			key=lambda x:x.created, reverse =True)
			
    def notfound(self):
		self.error(404)
		self.write('<h1>404: Note Found</h1> Sorry, my friend, but that page does not exist. ')					
			
########## FRONT PAGE ##########	
class MainPage(BaseHandler):
	def get(self):
		
		## pass the inbox as a parameter to render 
		if not self.user: 
			self.render("summaryPanel.html")
		else:
			
			self.render("summaryPanel.html",\
						numMsgs = len(self.inbox),\
						numSentMsgs = len(self.outbox),\
						msgs = self.inbox[:10],\
						user = self.user)
			
	
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
		# db_login returns the user id and the empty string 
		# if the password validates, the user and the msg 
		# "Username and password don't match" if the user 
		# was found but the password doesn't validate, and 
		# "Invalid login" otherwise
		
		if user and pw_msg == '': 
			self.handler_login(user)
			self.redirect("/")
		else:
			self.render('base.html',\
					name_provided = input_username,\
					password_error = pw_msg) 
		
class SentPage(BaseHandler):
	def get(self):
		
		## pass the inbox as a parameter to render 
		if not self.user: 
			self.error(400)
			return 
		else:
			self.render("sentPanel.html",\
						numMsgs = len(self.inbox),\
						numSentMsgs = len(self.outbox),\
						msgs = self.outbox,\
						user = self.user)
					

	
##
# Class: ComposeMessage
# ---------------------
# 
# 
##
				
class ComposeMessage(BaseHandler):
	def get(self, path):
		if not self.user:
			self.error(400)
			return
		
		## REFACTOR
		if self.request.arguments != []: 
			logging.error("ComposeMessage = %s, %s"%(self.request.arguments, self.request.get('msgAuthor')))
			self.render("composeMsg.html",\
				numMsgs = len(self.inbox),\
				numSentMsgs = len(self.outbox),\
				recipient = self.request.get('msgAuthor'),\
				subject = "RE: " + self.request.get('msgSubject'))
		else: 
			
			self.render("composeMsg.html",\
				numMsgs = len(self.inbox),\
				numSentMsgs = len(self.outbox))
		
	def post(self,path):
		if not self.user:
			self.error(400)
			return
		
		##retreive the field named "subject" and the field named "content"
		##from the form submission
		msg_recipient = self.request.get("recipient")
		msg_subject = self.request.get("subject")
		msg_body = self.request.get("body")
		
		
		## check if the message is a global broadcast
		if msg_recipient.lower() == "all": 
			## check
			recipients = db.Query(user_DB)
			recipientKeys = db.Query(user_DB, keys_only=True)
			
			to_store = Message(parent = message_DB_rootkey(),\
							author = self.user.user_name,\
							authorID = self.user.key().id(),\
							subject = msg_subject,\
							body = msg_body,\
							recipientKeys = list(recipientKeys))
			to_store.put()
			
			for recipient in recipients: 
				curr_file = recipient.msg_file
				curr_file.messageKeys.append(to_store.key())
				curr_file.unreadKeys.append(to_store.key())
				curr_file.put()

			# add the message to the user's sent message list
			self.user.msg_file.sentKeys.append(to_store.key())
			self.user.msg_file.put()
			
			self.redirect("/")
			
			
		group_qry = UserGroup.all().filter("groupname =", msg_recipient).get()	
		if group_qry: 
			##create a new Message entity
	
			to_store = Message(parent = message_DB_rootkey(),\
							author = self.user.user_name,\
							authorID = self.user.key().id(),\
							subject = msg_subject,\
							body = msg_body,\
							recipientKeys = group_qry.groupKeys)
		
			to_store.put()
			
			for recipient in group_qry.groupKeys: 
				msg_file = recipient.msg_file
				msg_file.messageKeys.append(to_store.key())
				msg_file.unreadKeys.append(to_store.key())
				msg_file.put()

			self.user.msg_file.sentKeys.append(to_store.key())
			self.user.msg_file.put()
			
			self.redirect("/")
	
		
		##Query the database for the recipient
		recipientEntity = user_DB.db_by_name(msg_recipient) 
		
		
		if recipientEntity:
			##create a new Message entity
			to_store = Message(parent = message_DB_rootkey(),\
							author = self.user.user_name,\
							authorID = self.user.key().id(),\
							subject = msg_subject,\
							body = msg_body, 
							recipientKeys = [recipientEntity.key()])
				
			# store the message object
			to_store.put()
			
			# retrieve the recipient's message file and
			# add the message to their message list
			# and unread message list
			msg_file = recipientEntity.msg_file
			msg_file.messageKeys.append(to_store.key())
			msg_file.unreadKeys.append(to_store.key())
			msg_file.put()
			
			# add the message to the user's sent message list
			self.user.msg_file.sentKeys.append(to_store.key())
			self.user.msg_file.put()
			
			self.redirect("/")
			
		else: 
			error = "That recipient doesn't exist"
			
			##pass the error message to the render fuction
			##the function then passes 'error' to the form
			self.render("composeMsg.html",\
						recipient = recipient,\
						subject = msg_subject,\
						body = msg_body,\
						error=error)


########## VIEW MESSAGE ##########				
class ViewMessage(BaseHandler):
	def get(self, path):
		if not self.user:
			self.error(400)
			return
		
		## 
		# Implementation note: 
		# --------------------
		# we're using the key as a url. The app extracts
		# the URL (which is actually a key) and uses the
		# key to retrieve the message from the database. 
		# use path[1:] to strip off the leading "/"
		#
		# Originally there was no parent key and the key == id. 
		# That allowed code Message.get(db.Key(path[1:])) where 
		# the function db.Key() converted a string to a key. 
		# When there is a parent component to the path the 
		# key != ID so 
		##
		msg = Message.db_by_id(int(path[1:]))
		
		## 
		# Impmlementation note: 
		# ---------------------
		# Validate that the user that's logged in is either
		# the reipient or the author of the message. If not, 
		# fail silently. Don't give the user an more information
		# [REFACTOR - add recipientKeys back to the message. 
		# validate that user.key() is in recipientKey]
		##
		if self.user.key() not in msg.recipientKeys and self.user.key().id() != msg.authorID: 
			self.error(400)
			return 
		
		if msg.key() in self.user.msg_file.unreadKeys: 
			self.user.msg_file.unreadKeys.remove(msg.key()) 
			self.user.msg_file.put() 
		
		self.render("viewMsg.html",\
					message_HTML = markdown.markdown(msg.body),\
					message = msg,\
					numMsgs = len(self.inbox),\
					numSentMsgs = len(self.outbox))
	
	
	
	##
	# Implementation note: 
	# -------------------
	# The app posts to the ViewMessage handlers when either
	# the 'Reply' or 'Delete' button is clicked. When the 
	# 'Reply' button is clicked, we extract the values for 
	# the message author and subject, build a query string, 
	# and redirect to /newMsg with the query string allowing 
	# the app to fill in the recipient and subject of the new 
	# message 
	#
	# When the 'Delete' button is clicked, we verify that we 
	# are the last recipient and delete the message
	# [NTD: REFACTOR]
	##
	
	def post(self, path): 
		
		selectedAction = self.request.get("selectedAction")
		msgAuthor = self.request.get("msgAuthor")
		msgSubject = self.request.get("msgSubject")
		
	
		msg = Message.db_by_id(int(path[1:]))
		
		if selectedAction == "reply":
		
			qsParams = OrderedDict([("msgAuthor",msgAuthor),("msgSubject", msgSubject)])
			
			self.redirect("/newMsg?" + urllib.urlencode(qsParams))
		
		if selectedAction == "delete": 
	
			self.user.msg_file.messageKeys.remove(msg.key())
			if msg.key() in self.user.msg_file.unreadKeys: 
				self.user.msg_file.unreadKeys.remove(msg.key()) 
			self.user.msg_file.put()
			
			self.redirect("/") 
		
		
			
					
########## GROUPS ##########				
class ViewGroup(BaseHandler):
	def get(self):
		if not self.user:
			self.error(400)
			return
		
		# we're using the key as a url. The app extracts
		# the URL (which is actually a key) and uses the 
		# key to retrieve the message from the database. 
		# use path[1:] to strip off the leading "/"
		groupsUserBelongsTo = cache_user_group(self.user.key().id()); 
		temp = UserGroup.all().filter("groupIDs = ", self.user.key().id()).get()
		logging.error("ViewGroup/Get groups =%s, %s"%(groupsUserBelongsTo,temp))
		
		# check that the user that's logged in is actually
		# a reipient of this message if not, fail silently. 
		# Don't give the user an more information 
		
		self.render("viewGroup.html",\
				groups = groupsUserBelongsTo,\
				numMsgs = len(self.inbox),\
				numSentMsgs = len(self.outbox))
	
	def post(self): 
		
		groupsUserBelongsTo = cache_user_group(self.user);
		input_groupname = self.request.get("groupname"); 
		selected_action = self.request.get("selectedAction"); 		
		
		
		error_msg = ""
		if not valid_groupname(input_groupname): 
			error_msg = "Please enter a valid groupname"
			self.render("viewGroup.html",\
						user_input_groupname = input_groupname,\
						groups = groupsUserBelongsTo,\
						error = error_msg)
			return
			
		if selected_action == "makeGroup": 
			qry = cache_group(input_groupname) 
			user = user_DB.db_by_name(self.input_username)
			if qry or user: 
				error_msg = "That group already exists" 
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groupsUserBelongsTo,\
							error = error_msg)
			else:
				to_store = UserGroup(parent = group_DB_rootkey(),\
									groupname = input_groupname.lower(),\
									groupKeys = [self.user.key()],\
									groupAuthor = self.user.key())
				to_store.put()
				cache_group(input_groupname, update=True)
				cache_user_group(self.user, update=True)
				self.redirect("/group")
		
		if selected_action == "joinGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groupsUserBelongsTo,\
							error = error_msg)
			else: 
				qry.groupKeys.append(self.user.key())
				qry.put()
				cache_user_group(self.user, update=True)
				self.redirect("/group")
		
		if selected_action == "leaveGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groupsUserBelongsTo,\
							error = error_msg)
			else: 
				if self.user.key() not in qry.groupKeys: 
					error_msg = "You don't belong to that group" 
					self.render("viewGroup.html",\
								user_input_groupname = input_groupname,\
								groups = groupsUserBelongsTo,\
								error = error_msg)
				else:
					qry.groupKeys.remove(self.user.key())
					qry.put()
					cache_user_group(self.user, update=True)
					self.redirect("/group")
		
		if selected_action == "deleteGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groupsUserBelongsTo,\
							error = error_msg)
			elif qry.groupAuthor != self.user.key(): 
				error_msg = "Only group author can delete group"
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groupsUserBelongsTo,\
							error = error_msg)
			else: 
				## we have a problem here in that we need to update the cache for all members of the group
				qry.delete()
				##[REFACTOR. this needs to be tested]  
				for userKey in qry.groupKeys: 
					userEntity = user_DB.get(userKey)
					cache_user_group(userEntity, update=True)
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
	## REFACTOR GROUP NAME / NAME COLLISIONS
		user = user_DB.db_by_name(self.input_username)
		groupname = UserGroup.db_by_name(self.input_username)
		if user or groupname:
			msg = 'That user already exists.'
			self.render('signupPage.html', fallback_error = msg, isSignupPage = True)
		else:
			newMsgFile = MsgFile.register()
			user = user_DB.register(self.input_username, self.input_password, newMsgFile.key())
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
		
		
		
##anything that is in paratheses gets passed in to the handler
##the regular expression matches ()		

MSGKEY_RE = r'(/(?:[a-zA-Z0-9_-]+)*)'

NEWMSG_RE = r'/newMsg(.*)'

app = webapp2.WSGIApplication([('/', MainPage),
								( NEWMSG_RE, ComposeMessage),
								('/group', ViewGroup), 
								('/signup', Register),
								('/sent', SentPage), 
								('/logout',LogoutPage),
								( MSGKEY_RE, ViewMessage),
								],debug = True)
