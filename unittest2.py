import validationFn
import unittest

class TestValidationFunctions(unittest.TestCase):


	def test_valid_username1(self):
		username = 'anth'
		self.assertTrue( validationFn.valid_username( username ) )

	def test_valid_username2(self):
		username = 'ant' 
		self.assertFalse( validationFn.valid_username( username ) )

	def test_valid_password1(self):
		
		pwd = 'Passwd1'
		self.assertTrue( validationFn.valid_password( pwd ) )
		
	def test_valid_password2(self):
		
		pwd = 'Passwd'
		self.assertFalse( validationFn.valid_password( pwd ) )
	
	def test_valid_password3(self):
		
		pwd = 'passwd1'
		self.assertFalse( validationFn.valid_password( pwd ) )
		
	def test_valid_password4(self):
		
		pwd = 'Pass1'
		self.assertFalse( validationFn.valid_password( pwd ) )

		
	def test_valid_groupname1(self):
		
		grp = 'cs_107' 
		self.assertTrue( validationFn.valid_groupname( grp ) )

	def test_valid_groupname2(self):
		
		grp = 'c_1' 
		self.assertTrue( validationFn.valid_groupname( grp ) )

	def test_valid_groupname3(self): 
		grp = '11_' 
		self.assertTrue( validationFn.valid_groupname( grp ) )
	
	def test_valid_groupname4(self): 
		grp = 'aa_' 
		self.assertTrue( validationFn.valid_groupname( grp ) )


	def test_valid_groupname5(self):
		
		grp = 'cs107' 
		self.assertFalse( validationFn.valid_groupname( grp ) )
	
	def test_valid_groupname6(self):
		
		grp = '107' 
		self.assertFalse( validationFn.valid_groupname( grp ) )
	
def suite():
	suite = unittest.TestLoader().loadTestsFromTestCase(TestValidationFunctions)
	return suite
		
if __name__ == '__main__':
    unittest.main()
	