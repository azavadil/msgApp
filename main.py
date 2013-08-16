import os
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

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),\
								autoescape = True)
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
	

########## PERMALINK FUNCTION ##########

##  the URLs are organized by date and title  
##  to create a unique identifier
##  Format is /year/day/title
##  e.g. /2013/150/lebron-wins-title


def get_id_from(input_string):
    
    regexp = r'[0-9]+$'
		
    return int(input_string[re.search(regexp,input_string).start():\
				re.search(regexp,input_string).end()])

def make_urlpath(input_string):

    input_string = input_string.replace(' ','-')
	
    ##we have to find at least one eligible character
    ##then we optionally find additional characters
    regexp = r'[a-zA-Z0-9_-]+'
    result = ''.join(re.findall(regexp,input_string))
    return result

def make_url_datepath(input_string):
    """(str) -> str
        make_url_datepath generates a string in the format
       /year/day/inputstring where days is a value between 1-366
       e.g. /2012/150/lebron is good"""
    year = time.localtime().tm_year
    day_of_year = time.localtime().tm_yday
    return '/' + str(year) + '/' + str(day_of_year) + '/' + input_string
		
			
					
########## DATABASE CLASSES ##########	
def users_DB_key(group = 'default'):
    return db.Key.from_path('users', group)	
    ##the users_DB_key fuction returns an empty object
    ##that we can use for organization

class user_DB(db.Model):
    ##required = True, will raise an exception if we try to create 
    ##content without a title
    user_name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    user_email = db.StringProperty(required = False)
    ##auto_now_add sets created to be the current time
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
	
    @classmethod
    def db_by_id(cls, uid):
    	return user_DB.get_by_id(uid,users_DB_key())

    @classmethod
    def db_by_name(cls, name):
    	u = user_DB.all().filter('user_name =', name).get()
    	return u
		
		
    @classmethod
    def register(cls, name, pw, email = None):
	
		## replace these values with actual values 
		frontpage_authors = ['alan','bob','carol']

		frnt_author = False
		if name in frontpage_authors:
			frnt_author = True
		
		current_pw_hash = make_pw_hash(name, pw)
		
		return user_DB(parent = users_DB_key(), \
            				user_name = name, \
							pw_hash = current_pw_hash, \
							user_email = email, \
            				frnt_author = frnt_author)

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
	
def message_key(name = 'default'):
    return db.Key.from_path('insider',name)
		
class Message(db.Model):
    ##required = True, will raise an exception if we try to create 
    ##content without a title
	author = db.StringProperty(required = True)
	authorID = db.IntegerProperty(required = True)
	recipientID = db.IntegerProperty(required = True)
	subject = db.StringProperty(required = False)
	body = db.StringProperty(required = False)
	##auto_now_add sets created to be the current time
	created = db.DateTimeProperty(auto_now_add = True)
	
	def render(self, b_summarize = None):
		self._render_text = self.body.replace('\n','<br>')
		return render_str("formattedMsg.html", page = self, summarize_text = b_summarize)
    	
    ##doesn't need an instance of the class
    ##e.g. can be called on insiderContent 
	@staticmethod
	def parent_key(path):
		return db.Key.from_path(path,'pages')
		
    ## doesn't run on an instance of the class
    ## e.g. can be called on insiderContent
	## get posts by URL path
	
	@classmethod
	def by_path(cls,path):
		q = cls.all()
		q.ancestor(cls.parent_key(path))
		q.order("-created")
		return q
    
	## get posts by ID 
	
	@classmethod
	def by_id(cls,page_id,path):
		return cls.get_by_id(page_id,cls.parent_key(path))
    		
########## COMMENT DATABASE ##########
	
class postComment(db.Model):
    ##required = True, will raise an exception if we try to create 
    ##content without a title
    cmt_title = db.StringProperty(required = False)
    cmt_comment = db.TextProperty(required = True)
    cmt_author = db.StringProperty(required = True)
    cmt_url_path = db.StringProperty(required = True)  ##NTD:need to check for uniqueness
    ##auto_now_add sets created to be the current time
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    	
    def render(self, b_summarize = None):
    	self._render_text = self.cmt_comment.replace('\n','<br>')
    	return render_str("formatted_comment.html", page = self)
	
    @staticmethod
    def parent_key(path):
    	return db.Key.from_path(path,"comments")
		
    @classmethod
    def by_path(cls,path):
    	q = cls.all()
    	q.ancestor(cls.parent_key(path))
    	q.order("-created")
    	return q


########## CACHING FUNCTIONS ##########		
		
##  cache_allpost is applied when we cache multiple posts
##  (e.g. when the front page is generated or we generate
##   a user page) 

	
# def cache_allpost(front_val = "", update = False):
	# """ (str, bool) -> str 
		# param front_val: string that's used set construct database keys
        # param update: specifies whether the cache should be overwritten
	# """

	# key = 'top'+front_val
	# if front_val == "":
		# db_frnt_property = True
	# else: 
		# db_frnt_property = False
		# ##keys have to be strings
		# logging.error("cache allpost %s" %key)
	# frontpage_res = memcache.get(key)
	# if frontpage_res is None or update:
		# logging.error("cache_allpost - DB QUERY")
		# frontpage_res = insiderContent.all().filter("front_page =", db_frnt_property).order("-created").fetch(8)	
		# memcache.set(key, frontpage_res)
	# return frontpage_res


##  cache_singlepost is applied to cache a single post

# def cache_singlepost(key_val,update = False):
    # """(str) -> str or Nonetype"""

    # cache_key = str(key_val)
    # ##keys have to be strings
    # ##the key is a string of the path
    # singlepost_res = memcache.get(cache_key)
    # if singlepost_res is None or update:
		# logging.error("cache_singlePost - DB SINGLEPOST QUERY")
		# singlepost_res = insiderContent.by_path(key_val).get()
		
		# ##return None if db is empty
		# if not singlepost_res:
			# return None
		# memcache.set(cache_key,singlepost_res)
    # return singlepost_res	
	
# def cache_comments(key_val,update = False):
    # ##key_val is the url_path
	# cache_key = "cmt_" + str(key_val)
	# comment_res = memcache.get(cache_key)
	# if comment_res is None or update: 
		# comment_res = list(postComment.by_path(key_val))
	# if not comment_res:
		# return None
	# memcache.set(cache_key,comment_res)
	# return comment_res


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
		uid = self.read_secure_cookie('user_id')
		self.user = uid and user_DB.db_by_id(int(uid))
		
    def get_prior_url(self):
		"""
			get_prior_url is used in Signup to redirect the user back to 
			whatever page they initiated the signup from. 
			Convience that returns the user to the page they were on when 
			they initiated the signup process
			
			referer: the referer is sent as part of every http request and 
			is the page that generated the http request (i.e. the page the user
			is coming from)
		"""
		return self.request.headers.get('referer','/')
	
    def get_prior_url_set_next_url(self):
		"""
			get_prior_url is used in SignupPage and LoginPage. We extract the hidden field 
			prior_url from the form and use the result to redirect the user back to whatever
			page they were on when they initiated the signup/login process
		"""
			
		next_url = str(self.request.get('prior_url'))
		logging.error("baseHandlers - get_prior_url_set_next_url - next_url = %s" %next_url)
		
		## check that we have a url and the url is not the login page (wrt login page, 
		## if the user came from the login page we don't want to redirect back to the login 
		## page when we finish the signup/login process
		if not next_url or next_url.startswith('/login'):
			next_url = '/'
		## strip off trailing '/'
		if len(next_url) > 1 and next_url[-1] == '/':
			next_url = next_url[:-1]
		return next_url
	
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
			qry = Message.all().filter("recipientID =", self.user.key().id())
			self.render("summaryPanel.html", numMsgs = qry.count(), msgs = qry)
			
		
			
		
		
	
	def post(self):
	
      	
		##hold what the user entered
		input_username = self.request.get('username')
		input_password = self.request.get('password')
	
		logging.error("mainpage = %s, %s" %(input_username, input_password))	
	
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

########## DISCRETE PAGE ##########					
class ViewMsg(BaseHandler):
    def get(self, path):
		
		
		if not self.user:
			self.error(404)
			return
				
		self.render("discretePost.html", singlePost = singlePost, path = path, readerComments = readerComments)		


	
########## COMPOSE MESSAGE ##########				
class ComposeMessage(BaseHandler):
	def get(self):
		if not self.user:
			self.error(400)
			return
		self.render("composeMsg.html")
		
	def post(self):
		if not self.user:
			self.error(400)
			return
		
		##retreive the field named "subject" and the field named "content"
		##from the form submission
		recipient = self.request.get("recipient")
		msg_subject = self.request.get("subject")
		msg_body = self.request.get("body")
		
		
		##we have to query the database for the recipient
		recipientEntity = user_DB.db_by_name(recipient) 
		
		
		
		if recipientEntity:
			##create a new Message entity
	
			to_store = Message(author = self.user.user_name,\
							authorID = self.user.key().id(),\
							recipientID = recipientEntity.key().id(),\
							subject = msg_subject,\
							body = msg_body)
		
			
			##store the new blog object
			to_store.put()
		
			##only cache the relevant section. If it's a
			##frontpage writer, we need to cache the frontpage
			##if it's a reader, we need to cache the reader
			
			##  cache_allpost("readers",True)
			##cache the permalink page for the post
			##  cache_singlepost(path_title,True)
			##redirect to a permalink page, pass the id
			self.redirect("/")
			
		else: 
			error = "That recipient doesn't exist"
			
			##pass the error message to the render fuction
			##the function then passes 'error' to the form
			self.render("composeMsg.html",recipient = recipient, subject = msg_subject, body = msg_body, error=error)


			
			
########## SIGNUP PAGE ##########						
class SignupPage(BaseHandler):
	
	def get(self):
		if self.user:
			self.error(400)
			return
			
		## establish prior url so use gets returned to whatever page they were on 
		## when they complete signup
		prior_url = self.get_prior_url()
		## we fill in prior_url as a hidden field in the signup for 
		## when the form is posted we extract prior_url and redirect the user
		## to the URL they came from
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
			user = user_DB.register(self.input_username, self.input_password, email_addr)
			user.put()
			
			self.handler_login(user)
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

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/', MainPage),
								('/newMsg', ComposeMessage),
								('/signup', Register),
								('/logout',LogoutPage),
								('/delete' + PAGE_RE, DeletePost), 
								( PAGE_RE, ViewMsg),
								],debug = True)
