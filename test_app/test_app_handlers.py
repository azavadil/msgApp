#import sys
#sys.path.append( 'G:\msgApp\msg' )

import webapp2
import webtest
import unittest

from main_page import MainPage	   
from main import SignupPage	   
	   
class AppTest(unittest.TestCase):
    def setUp(self):
        # Create a WSGI application.
        app = webapp2.WSGIApplication([('/', MainPage), 
			('/signup', SignupPage)
			])
        # Wrap the app with WebTest TestApp
        self.testapp = webtest.TestApp(app)

    # Test the handler.
    def test_MainPage(self):
        response = self.testapp.get('/')
        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.content_type, 'text/html')
		
	def test_SignupPage(self): 
		response = self.testapp.get('/')
        self.assertEqual(response.status_int, 200)