

function getAndSubmitCustomMsg(){ 
	var elem = document.getElementById("pwd1"); 
	var dropbox = document.getElementById("password_error_dropbox");
	elem.setCustomValidity(dropbox.getAttribute("value")); 

	var submitBtn = document.getElementById("mainPageSignInBtn"); 
	submitBtn.click(); 
}

getAndSubmitCustomMsg()



