import sys
sys.path.append( 'G:\\msgApp\msg' )  

import unittest
from google.appengine.ext import testbed

# Databases split out as modules
import memcache_fn
import users_db
  
class TestDbs(unittest.TestCase):

	def setUp(self):
		# First, create an instance of the Testbed class
		self.testbed = testbed.Testbed()
		# Then activate the testbed, which prepares the service stubs for use.
		self.testbed.activate()
		# Next, declare which service stubs you want to use.
		self.testbed.init_datastore_v3_stub()
		self.testbed.init_memcache_stub()

		test_user = users_db.UsersDb.register('Laplace', 'pwd')
		test_user.put()
		self.test_user = test_user

	def tearDown(self):
		self.testbed.deactivate()	
		
	def test_cache_user(user_id):
	
		uid = self.test_user.key().id()
		result = memcache_fn.cache_user( str(uid) )
		assertEquals( self.test_user.key(), result.key()) 
	
	
if __name__ == '__main__':
    unittest.main()
	