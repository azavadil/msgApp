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
from validation_fn import valid_groupname

from memcache_fn import cache_user
from memcache_fn import cache_user_group
from memcache_fn import cache_group

from base_handler import BaseHandler
from main_page import MainPage
from signup_page import Register
from sent_page import SentPage
from compose_message import ComposeMessage
from view_message import ViewMessage

import webapp2
import logging
import time
import pickle

from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import taskqueue
import urlparse
from collections import OrderedDict

		


					
#
# Class: View Group
# -----------------
# ViewGroup manages the CRUD actions for user groups. 
# 				
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
		
		#
		# Implementation note: 
		# --------------------
		# The programs checks for conflicts with both groupnames
		# and usernames. The program takes the 'To' field and looks
		# for a group or user that matches. Therefore, we must for 
		# unique names
		# 
			
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
			#
			# Implementation note: 
			# --------------------
			# group_author is set as Reference property on the group. 
			# Therefore, qry.group_author dereferences a user entity. 
			# This may be a surprising result since we set group_author
			# to be self.user.key().
			#
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
