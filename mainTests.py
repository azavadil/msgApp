from passwordFns import make_pw_hash
from passwordFns import valid_username
from passwordFns import valid_password

def test1(): 
	
	hash = "63875680629273d60a1443db79182f54b8790e4f85e1595d66da9e32ad8be2ef"
	salt = "ViVnw"
	
	salt = "ViVnw"
	res = make_pw_hash("anthony","Domino00", salt)
	print res
	

def test2(): 
	
	print valid_username('anthony')
	print valid_password('Domino00')
	

def test():
	print valid_password('Domino00')
	print valid_password('anthony')
	print valid_password('Anthony')
	print valid_password('Anthony1')
	
test()
	