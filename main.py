import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))


from users_db import UsersDb
from message_db import MessageDb
from message_db import message_db_rootkey

from user_group_db import UserGroup
from user_group_db import group_db_rootkey

from msgfile_db import MsgFile

from user_names_db import UserNames

from validation_fn import escape_html
from validation_fn import valid_username
from validation_fn import valid_password
from validation_fn import valid_groupname

from memcache_fn import cache_user
from memcache_fn import cache_user_group
from memcache_fn import cache_group

from base_handler import BaseHandler

import webapp2
import logging
import time
import markdown
import pickle
import urllib

from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import taskqueue
import urlparse
from collections import OrderedDict


#
# Implementation note: 
# -------------------
# The app uses 5 database models. 
#
# UsersDb: 		models a single user. Used for managing 
#				a secure user login system
# Messages: 	models a single message
# UserGroup: 	models a group of users. 
# MsgFile: 		models a relationship between a user and the 	
#				user's messages. Each MsgFile belongs to one user
# UserNames: 	models a list of all the users. Used to rapidly provide
#				a name list for transmital to client to build the 
#				an autocompletion trie
#

		
			
#
# Class: SentPage
# ---------------
# SentPage manages displaying the user's outbox
#		
		
class SentPage(BaseHandler):
	def get(self):
		
		if not self.user: 
			self.error(400)
			return 
		else:
			self.render("summaryPanel.html",\
						num_msgs=len(self.inbox),\
						num_sent_msgs=len(self.outbox),\
						msgs=self.outbox,\
						user=self.user,\
						pageNum= '0'
						)
	def post(self):

		if not self.user: 
			self.error(400)
			return 
		
		else: 
			pageNum = int(self.request.get('hiddenPageNum'))
			selectedAction = self.request.get('selectedAction')
			
			
			if selectedAction == 'Older': 
				if (pageNum + 1) * 10 < len(self.outbox): 
					pageNum += 1 
			else:  				# selected action is 'Newer' 
				if (pageNum - 1) >= 0: 
					pageNum -= 1
			startIndex = pageNum * 10 
			endIndex = startIndex + 10
			
			
			self.render("summaryPanel.html",\
						num_msgs=len(self.inbox),\
						num_sent_msgs=len(self.outbox),\
						msgs=self.outbox[startIndex:endIndex],\
						user=self.user,\
						pageNum=str(pageNum)
						)
			
#
# Class: ComposeMessage
# ---------------------
# ComposeMessage manages the creation and sending of messages. 
# 
#
				
class ComposeMessage(BaseHandler):
	def get(self, path):
		if not self.user:
			self.error(400)
			return
		
		
		#
		# Implementation note: 
		# -------------------
		# The only time ComposeMessage is rendered with msgAuthor
		# parameters is on a redirect from the ViewMessage handler.
		# The ViewMessage handler extracts the post data, builds 
		# a query string from the post data, and redirects to 
		# the /newMsg URL
		# 
		if self.request.get('msgAuthor'): 
			self.render("composeMsg.html",\
				num_msgs=len(self.inbox),\
				num_sent_msgs=len(self.outbox),\
				recipient=self.request.get('msgAuthor'),\
				subject="RE: " + self.request.get('msgSubject')
				)
		else: 
			
			self.render("composeMsg.html",\
				num_msgs=len(self.inbox),\
				num_sent_msgs=len(self.outbox)
				)
		
	def post(self,path):
		if not self.user:
			self.error(400)
			return
		
		# retreive the field named "subject" and the field 
		# named "content" from the form submission
		msg_recipient = self.request.get("recipient")
		msg_subject = self.request.get("subject")
		msg_body = self.request.get("body")
		
		q_params = {}
		q_params['recipient'] = msg_recipient 
		q_params['subject'] = msg_subject
		q_params['body'] = msg_body
		q_params['user_key'] = self.user.key()
		
		
		# check if the message is a global broadcast
		if msg_recipient.lower() == "all": 
			
			# send to taskqueue to manage distribution 
			taskqueue.add( params=q_params )
			self.redirect("/")
					
		group_qry = UserGroup.all().filter("groupname =", msg_recipient).get()	
		if group_qry: 
			
			# create a new Message entity
			to_store = MessageDb(
							parent=message_db_rootkey(),\
							author=self.user.key().name(),\
							subject=msg_subject,\
							body=msg_body,\
							recipient_keys=group_qry.group_keys)
		
			to_store.put()
			
			for recipientKey in group_qry.group_keys:
				msg_file = UsersDb.get(recipientKey).msg_file
				msg_file.message_keys.append(to_store.key())
				msg_file.unread_keys.append(to_store.key())
				msg_file.put()

			self.user.msg_file.sent_keys.append(to_store.key())
			self.user.msg_file.put()
			
			self.redirect("/")
	
		
		# Query the database for the recipient
		recipientEntity = UsersDb.db_by_name(msg_recipient) 
		
		if recipientEntity:
			# create a new Message entity
			to_store = MessageDb(parent=message_db_rootkey(),\
							author=self.user.key().name(),\
							subject=msg_subject,\
							body=msg_body, 
							recipient_keys=[recipientEntity.key()]
							)
				
			# store the message object
			to_store.put()
			
			# retrieve the recipient's message file and
			# add the message to their message list
			# and unread message list
			msg_file = recipientEntity.msg_file
			msg_file.message_keys.append(to_store.key())
			msg_file.unread_keys.append(to_store.key())
			msg_file.put()
			
			# add the message to the user's sent message list
			self.user.msg_file.sent_keys.append(to_store.key())
			self.user.msg_file.put()
			
			self.redirect("/")
			
		else: 
			error = "That recipient doesn't exist"
			
			# pass the error message to the render fuction
			# the function then passes 'error' to the form
			self.render("composeMsg.html",\
						recipient=msg_recipient,\
						subject=msg_subject,\
						body=msg_body,\
						num_msgs=len(self.inbox),\
						num_sent_msgs=len(self.outbox),\
						fallback_error=error
						)


#
# Class: ViewMessage
# ------------------
# ViewMessage manages the display of a single message
#
				
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
		# 
		# Defensive programming: validate we don't have a
		# string integer before calling int() on the path
		# [test required] 
		##
		
		logging.warning(path)
		if not path[1:].isdigit() or path is None: 
			self.notfound()
			return
		
		msg = MessageDb.db_by_id(int(path[1:]))
		
		##
		# Implementation note: defend against a garbage URL
		# --------------------------------------------------
		# If the ID doesn't return a message return not found
        # [test required] 		
		## 
		if not msg:
			self.notfound()
			return
		
		## 
		# Impmlementation note: defend against malicious users
		# ----------------------------------------------------
		# Validate that the user that's logged in is either
		# the recipient or the author of the message. If not, 
		# fail silently. Don't give the user any more information
		# [test required]
		##
		
		if self.user.key() not in msg.recipient_keys and self.user.key().name() != msg.author: 
			self.error(400)
			return 
		
		if msg.key() in self.user.msg_file.unread_keys: 
			self.user.msg_file.unread_keys.remove(msg.key()) 
			self.user.msg_file.put() 
		
		# TODO: escape html
		self.render("viewMsg.html",\
					message_HTML=markdown.markdown(msg.body),\
					message=msg,\
					num_msgs=len(self.inbox),\
					num_sent_msgs=len(self.outbox),\
					user= self.user)
	
	
	
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
	##
	
	def post(self, path): 
		
		selectedAction = self.request.get('selectedAction')
		msgAuthor = self.request.get('msgAuthor')
		msgSubject = self.request.get('msgSubject')
		
	
		msg = MessageDb.db_by_id(int(path[1:]))
		
		if selectedAction == "reply":
		
			qsParams = OrderedDict([("msgAuthor",msgAuthor),("msgSubject", msgSubject)])
			self.redirect("/newMsg?" + urllib.urlencode(qsParams))
		
		if selectedAction == "delete": 
			if msg.key() in self.user.msg_file.message_keys: 
				self.user.msg_file.message_keys.remove(msg.key())
			if msg.key() in self.user.msg_file.unread_keys: 
				self.user.msg_file.unread_keys.remove(msg.key()) 
			self.user.msg_file.put()
			
			self.redirect("/") 
			
					
##
# Class: View Group
# -----------------
# ViewGroup manages the CRUD actions for user groups. 
## 				
class ViewGroup(BaseHandler):
	def get(self):
		if not self.user:
			self.error(400)
			return
		
		groups_user_belongs_to = cache_user_group(self.user); 
			
		self.render("viewGroup.html",\
				groups=groups_user_belongs_to,\
				num_msgs=len(self.inbox),\
				num_sent_msgs=len(self.outbox))
	
	def post(self): 
		
		groups_user_belongs_to = cache_user_group(self.user)
		input_groupname = self.request.get("groupname")
		selected_action = self.request.get("selectedAction") 		
		
		
		error_msg = ""
		if not valid_groupname(input_groupname): 
			error_msg = "Please enter a valid groupname. Groupname must be lowercase/uppercase/digit and at least 1 underscore."
			self.render("viewGroup.html",\
						user_input_groupname=input_groupname,\
						groups=groups_user_belongs_to,\
						num_msgs=len(self.inbox),\
						num_sent_msgs=len(self.outbox),\
						error=error_msg)
			return
		
		##
		# Implementation note: 
		# --------------------
		# The programs checks for conflicts with both groupnames
		# and usernames. The program takes the 'To' field and looks
		# for a group or user that matches. Therefore, we must for 
		# unique names
		## 
			
		if selected_action == "makeGroup": 
			ent, group_created = UserGroup.my_get_or_insert(
				input_groupname.lower(), 
				group_keys=[self.user.key()], 
				group_author=self.user.key()
				)
				
			if not group_created: 
				error_msg = "That group already exists" 
				self.render("viewGroup.html",\
							user_input_groupname=input_groupname,\
							groups=groups_user_belongs_to,\
							num_msgs=len(self.inbox),\
							num_sent_msgs=len(self.outbox),\
							error=error_msg)
			else:
				cache_group(input_groupname.lower(), update=True)
				cache_user_group(self.user, update=True)
				self.redirect("/group")
		
		if selected_action == "joinGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html",\
							user_input_groupname=input_groupname,\
							groups=groups_user_belongs_to,\
							num_msgs=len(self.inbox),\
							num_sent_msgs=len(self.outbox),\
							error=error_msg)
			else: 
				qry.group_keys.append(self.user.key())
				qry.put()
				cache_group(input_groupname, update=True)
				cache_user_group(self.user, update=True)
				self.redirect("/group")
		
		if selected_action == "leaveGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groups_user_belongs_to,\
							num_msgs = len(self.inbox),\
							num_sent_msgs = len(self.outbox),\
							error = error_msg)
			else: 
				if self.user.key() not in qry.group_keys: 
					error_msg = "You don't belong to that group" 
					self.render("viewGroup.html",\
								user_input_groupname = input_groupname,\
								groups = groups_user_belongs_to,\
								num_msgs = len(self.inbox),\
								num_sent_msgs = len(self.outbox),\
								error = error_msg)
				else:
					qry.group_keys.remove(self.user.key())
					qry.put()
					cache_group(input_groupname, update=True)
					cache_user_group(self.user, update=True)
					self.redirect("/group")
		
		if selected_action == "deleteGroup": 
			qry = cache_group(input_groupname)
			if not qry: 
				error_msg = "That group doesn't exist" 
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groups_user_belongs_to,\
							num_msgs = len(self.inbox),\
							num_sent_msgs = len(self.outbox),\
							error = error_msg)
			##
			# Implementation note: 
			# --------------------
			# group_author is set as Reference property on the group. 
			# Therefore, qry.group_author dereferences a user entity. 
			# This may be a surprising result since we set group_author
			# to be self.user.key().
			##
			elif qry.group_author.key() != self.user.key(): 
				error_msg = "Only group author can delete group"
				self.render("viewGroup.html",\
							user_input_groupname = input_groupname,\
							groups = groups_user_belongs_to,\
							num_msgs = len(self.inbox),\
							num_sent_msgs = len(self.outbox),\
							error = error_msg)
			else: 
				## we have a problem here in that we need to update the cache for all members of the group
				qry.delete()
				cache_group(input_groupname, update = True)
				## REFACTOR. this needs to be tested  
				for userKey in qry.group_keys: 
					userEntity = UsersDb.get(userKey)
					cache_user_group(userEntity, update=True)
				self.redirect("/group")
				
		
		
##
# Class: SignupPage
# -----------------
# SignupPage manages the creation of a new user
#
##						
class SignupPage(BaseHandler):
	
	def get(self):
		if self.user:
			self.error(400)
			return
			
		self.render("signupPage.html", isSignupPage = True)
	
	def post(self):
		
		# check if the user is logged in. If the user is logged in then we 
		# shouldn't be on this page 
		if self.user:
			self.error(400)
			return
	
		# store what the user entered
		self.input_username = self.request.get('username')
		self.input_password = self.request.get('pwd1')
		self.password_verify = self.request.get('pwd2')
		
		params = dict(name_provided = self.input_username)

		error_msg = "" 
		have_error = False
		
		# test for valid user_name
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

##
# Class: Register
# ---------------
# Register extends the signupPage class to include an 
# additional check of whether a user exists before adding 
# a user to the database. Register is implemented by 
# inheriting from signupPage and overwriting the done() 
# method. 
#
			
class Register(SignupPage):

	
	def done(self):
		
		#
		# Implementation note: 
		# --------------------
		# If the user already exists, then my_get_or_insert
		# returns a tuple with false as the second value
		# TODO: [test required]
		 
		user_entity, user_created = UsersDb.my_get_or_insert(
			self.input_username, 
			pwd=self.input_password
			)
		
		if not user_created: 
			self.render('signupPage.html',
				fallback_error='User already exists'
				)	
			
		new_msg_file = MsgFile.create_msg_file()
		user_entity.msg_file = new_msg_file
		user_entity.put()
		
					
		UserNames.add_name(user_entity.key().name())
		
		self.handler_login(user_entity)
		# TODO: cache_user(user.key().id())
		self.redirect("/")

		
#
# Class: LogoutPage
# -----------------
# LogoutPage manages user logout. Simple class
# that calls the handler_logout() method (defined 
# in the BaseHanlder class and redirects to the 
# home page 
# 					
class LogoutPage(BaseHandler):
	
    def get(self):
		self.handler_logout()
		self.redirect("/")
		
class AllManager(webapp2.RequestHandler): 
	
	def post(self): 
		
		logging.warning('task queue triggered')
		recipients = db.Query(UsersDb)
		recipient_keys = db.Query(UsersDb, keys_only=True)
			
		user_key = self.request.get('user_key')
		curr_user = UsersDb.get(user_key)
			
		to_store = MessageDb(
			parent=message_db_rootkey(),\
			author=curr_user.key().name(),\
			subject=self.request.get('subject'),\
			body=self.request.get('body'),\
			recipient_keys=list(recipient_keys)
			)
		to_store.put()
		
		for recipient in recipients: 
			curr_file = recipient.msg_file
			curr_file.message_keys.append(to_store.key())
			curr_file.unread_keys.append(to_store.key())
			curr_file.put()

		# add the message to the user's sent message list
		curr_user.msg_file.sent_keys.append(to_store.key())
		curr_user.msg_file.put()
					
#
# Implementation note: 
# -------------------
# anything that is in paratheses gets passed in to 
# the handler the regular expression matches ()		
#

MSGKEY_RE = r'(/(?:[a-zA-Z0-9_-]+)*)'

NEWMSG_RE = r'/newMsg(.*)'

app = webapp2.WSGIApplication([('/', MainPage),
								( NEWMSG_RE, ComposeMessage),
								('/group', ViewGroup), 
								('/signup', Register),
								('/sent', SentPage), 
								('/logout',LogoutPage),
								( MSGKEY_RE, ViewMessage),
								( '/_ah/queue/default', AllManager), 
								],debug = True)
