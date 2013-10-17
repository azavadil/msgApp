import sys
sys.path.append( 'C:\Program Files (x86)\Google\google_appengine' )


import webapp2
import webtest
import unittest

from main_page import MainPage	   
from signup_page import Register 
from google.appengine.ext import db
from google.appengine.ext import testbed

	   
class HandlerTest(unittest.TestCase):
	
	
	def setUp(self):
		# Create a WSGI application.
		app = webapp2.WSGIApplication([('/', MainPage), 
			('/signup', Register)
			])
        # Wrap the app with WebTest TestApp
		self.testapp = webtest.TestApp(app)
		
		# First, create an instance of the Testbed class
		self.testbed = testbed.Testbed()
		# Then activate the testbed, which prepares the service stubs for use.
		self.testbed.activate()		
		self.testbed.init_datastore_v3_stub()
		self.testbed.init_memcache_stub()
		
	def tearDown(self):
		self.testbed.deactivate()	


    # Test the handler.
	def test_MainPage(self):
		response = self.testapp.get('/')
		self.assertEqual(response.status_int, 200)
		self.assertEqual(response.content_type, 'text/html')
	
	def test_SignupPage(self):
		response = self.testapp.get('/signup')
		self.assertEqual(response.status_int, 200)
	
	def test_SignupPage_post(self): 
		response = self.testapp.post('/signup', {'username':'anth','pwd1':'Star88','pwd2':'Star88'})
		redirect = response.follow()
		self.assertEqual(redirect.status_int, 200)
		
		