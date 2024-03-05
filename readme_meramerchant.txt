0. Test Api 

http://localhost:8080/test


#########################################################################


1 .  Register api 

http://localhost:8080/register

inputs : 
{
    "email":"sarfu@gmail.com",
    "password":"12345",
    "password_confirm":"12345",
    "first_name":"sarfu",
    "last_name":"shaikh",
    "company":"Sarfu company",
    "phone":"9980950000"
}



#######################################################################

2 . Login api 

http://localhost:8080/login

inputs : 
{
    "email":"sarfraz.sk015@gmail.com",
    "password":"12345"
}

########################################################################

3 .  To get perticular user details 

http://localhost:8080/get_user_data

inputs : 

In headers need to pass token - d93b73e79e65720018a08db1efd6525934ea4272b4667a4c6842a8493a016fc6

###############################################################

4 . logout 

http://localhost:8080/logout

input : 

In headers need to pass token - d93b73e79e65720018a08db1efd6525934ea4272b4667a4c6842a8493a016fc6

##############################################################

5 . forgot password 

http://localhost:8080/forgot_password

input : 

{
    "email":"sarfraz.sk015@gmail.com"
}

This will going to give the OTP on email address.

#####################################################################


6 . Reset password 

http://localhost:8080/reset_password

input : 

{
    "otp":"1472",
    "new_password":"12345",
    "confirm_password":"12345"
}


7 . Generate tester token 

http://localhost:8080/generate_tester_token

input : 

{
    "password_length":"32",
    "alphabets":"false",
    "numbers":"true",
    "symbols":"false"
}



