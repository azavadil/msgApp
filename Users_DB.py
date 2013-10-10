import sys
sys.path.append( 'G:\\msgApp\\msg' )

from google.appengine.ext import db
from passwordFn import make_pw_hash
from passwordFn import valid_pw


def users_DB_rootkey(group = 'default'):
	""" 	
		user_DB_rootkey returns a default parent key for 
		the user_DB class. Parent keys are used to organize 
		all user_DB entities into a single entity group. 
		The parent key is in the form kind/key_name 
		(e.g. user_DB/'default').  
		Child keys are in the format kind/parent/ID 
		(e.g. user_DB/'default'/XXXXXX)
		
		There's an equivalent syntax user_DB(key_name=group) 
	"""
	return db.Key.from_path('user_DB', group)	
    
##
# class: user_DB
# --------------
# The user_DB model models a single user.  
##
	
class user_DB(db.Model):
	user_name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True, indexed = False)
	msg_file = db.ReferenceProperty(required = False, indexed = False)
	##auto_now_add sets created to be the current time
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	
	@classmethod
	def db_by_id(cls, uid):
		return user_DB.get_by_id(uid,users_DB_rootkey())

	@classmethod
	def db_by_name(cls, name):
		u = user_DB.all().ancestor(users_DB_rootkey()).filter('user_name =', name).get()
		return u
		
	@classmethod   
	def register(cls, name, pw):
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
