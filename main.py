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
from view_group import ViewGroup

import webapp2
import logging
import time
import pickle

from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import taskqueue
import urlparse


					
				
		
	
		
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
