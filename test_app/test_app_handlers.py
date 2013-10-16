#import sys
#sys.path.append( 'G:\msgApp\msg' )

import webapp2
import webtest
import unittest

from main import MainPage	   
	   
	   
class AppTest(unittest.TestCase):
    def setUp(self):
        # Create a WSGI application.
        app = webapp2.WSGIApplication([('/', MainPage)])
        # Wrap the app with WebTest TestApp
        self.testapp = webtest.TestApp(app)

    # Test the handler.
    def testMainPageHandler(self):
        response = self.testapp.get('/')
        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.content_type, 'text/html')