from google.appengine.ext import db

#
# Function: group_db_rootkey
# --------------------------
# Generates default key to serve as parent key for 
# the UserGroup entity model 
#



def group_db_rootkey(group = 'default'):
	
	""" 
		group_db_rootkey returns a default parent key. 
		parent keys are used to organize all UserGroups 
		entities into a single entity group. 
	"""
	
	return db.Key.from_path('UserGroup', group)

	
class UserGroup(db.Model):
	
	
	groupname = db.StringProperty(required = True)
	group_keys = db.ListProperty(db.Key, required = True)
	group_author = db.ReferenceProperty(required = True, indexed = False)
    	
	@classmethod
	def db_by_name(cls, groupname): 
		
		return UserGroup.all().ancestor(group_db_rootkey())\
			.filter("groupname = ", groupname).get()
