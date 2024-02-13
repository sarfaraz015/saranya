<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\ResponseInterface;
use App\Models\UserModel;
use App\Libraries\UserLibrary;
use App\Libraries\SecureDataHandler;

class UserController extends BaseController
{

    public $usermodel;
    public $userlibrary;
    public $dataHandler;

    public function __construct()
    {
           $secret_key = $_ENV['ENCRYPTION_KEY'];
           $salt = $_ENV['SALT'];
           $this->usermodel = new UserModel();
           $this->userlibrary = new UserLibrary();
           $this->dataHandler = new SecureDataHandler($secret_key, $salt);
    }
    public function index()
    {
        echo "Calling index from UserController";
    }

    public function test()
    {
         echo "Calling test from UserController";
    }

public function generateUserId()
{
    $final_id = '';
    $attempts = 0;
      while(true){
            $user_id = rand(100000, 999999);
            $result = $this->usermodel->checkUserIdExists($user_id);
            if($attempts <= 3){
                if(!$result){
                    $final_id = $user_id;
                    break;
                }
                else{
                    $attempts = $attempts+1;
                }
            }
            else{
                $final_id = rand(1000000, 9999999);
                break;
            }   
      }
    return $final_id;
}


public function encryptUserData($data)
{
       $username_encrypt = $this->dataHandler->encryptAndStore($data['username']);
       $email_encrypt = $this->dataHandler->encryptAndStore($data['email']);
       $first_name_encrypt = $this->dataHandler->encryptAndStore($data['first_name']);
       $last_name_encrypt = $this->dataHandler->encryptAndStore($data['last_name']);
       $company_encrypt = $this->dataHandler->encryptAndStore($data['company']);
       $phone_encrypt = $this->dataHandler->encryptAndStore($data['phone']);

       $encryptedData = array(
           'uid'=>$data['uid'],
           'ip_address'=>$data['ip_address'],
           'username'=>$username_encrypt,
           'password'=>$data['password'],
           'email'=>$email_encrypt,
           'created_on'=>$data['created_on'],
           'active'=>$data['active'],
           'first_name'=>$first_name_encrypt,
           'last_name'=>$last_name_encrypt,
           'company'=>$company_encrypt,
           'phone'=>$phone_encrypt
       );

       return $encryptedData;

}

public function register()
{
    if ($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';
        
        $rules = [
            'email'=>'required|valid_email',
            'password'=>'required',
            'password_confirm'=>'required|matches[password]',
            'first_name'=>'required',
            'last_name'=>'required',
            'company'=>'required',
            'phone'=>'required'
        ];
    
        if(!$this->validate($rules))
        {
            $response['errors'] = $this->validator->getErrors();
            $errorCode = 401;
            $response['response'] = false;
            return $this->response->setJSON($response)->setStatusCode($errorCode);
        }
    
            $json_data = $this->request->getJSON();
            $email = trim($json_data->email);

            if(!$this->userlibrary->checkUserAlreadyExists($email))
            {
                $uid = $this->generateUserId();
                $password = trim($json_data->password);
                $first_name = trim($json_data->first_name);
                $last_name = trim($json_data->last_name);
                $company = trim($json_data->company);
                $phone = trim($json_data->phone);

                $data = array(
                    'uid' =>$uid,
                    'ip_address'=>$this->request->getIPAddress(),
                    'username'=>$json_data->first_name.$json_data->last_name,
                    'password'=>password_hash($password,PASSWORD_DEFAULT),
                    'email'=>$email,
                    'created_on'=>time(),
                    'active'=>1,
                    'first_name'=>$first_name,
                    'last_name'=>$last_name,
                    'company'=>$company,
                    'phone'=>$phone
                );

                $encryptedData = $this->encryptUserData($data);
               
                if($this->usermodel->registerUser($encryptedData))
                {
                    $response['message'] = "User registered successfully";
                    $response['response'] = true;
                    $errorCode = 200; 
                }
            }
            else
            {
                    $response['message'] = "User already exists in the database";
                    $response['response'] = false;
                    $errorCode = 401; 
            }

            return $this->response->setJSON($response)->setStatusCode($errorCode);
    
    } 
    

}


public function generate_token() {
	$token = hash('sha256', uniqid(rand(), true));
	return $token;
}

function blockUserMessage()
{
    $receivedData = session()->getFlashdata();
    $email = $receivedData['email'];
    $response['message'] = "Email-Id ".$email." has been temporarily blocked";
    $response['response'] = false;
    $errorCode = 401;
    return $this->response->setJSON($response)->setStatusCode($errorCode); 
}


public function login()
{
    if ($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';

        $rules = [
            'email'=>'required|valid_email',
            'password'=>'required',
        ];

        if(!$this->validate($rules))
        {
            $response['errors'] = $this->validator->getErrors();
            $errorCode = 401;
            $response['response'] = false;
            return $this->response->setJSON($response)->setStatusCode($errorCode);
        }

        $json_data = $this->request->getJSON();
        $email = trim($json_data->email);
        $password = trim($json_data->password);

       

        if($this->userlibrary->checkUserAlreadyExists($email))
        {
            $dbPassword = $this->userlibrary->checkUserAlreadyExists($email)->password;
    
            if (!password_verify($password, $dbPassword)) {
                $this->usermodel->increaseUsersInvalidLoginAttempts($this->request->getIPAddress(),$email,time());
                $response['message'] = "Invalid password";
                $response['response'] = false;
                $errorCode = 401;
                $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
                if($loginAttemptStatus)
                {
                    return redirect()->to('blockUserMessage')->with('email', $email);
                }
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            } 


            $userId = $this->usermodel->getUserId($email);
            if($this->userlibrary->userExistsInUsersToken($userId)){
                
                if($this->userlibrary->checkActiveStatus($userId)){
                       
                        $response['message']= "User ".$email." already logged in";
                        $response['token']=$this->userlibrary->checkActiveStatus($userId)->token;
                        $response['response'] = true;
                        $errorCode = 200;
                    }
                    else
                    {
                        $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
                        if($loginAttemptStatus)
                        {
                            return redirect()->to('blockUserMessage')->with('email', $email);
                        }

                        date_default_timezone_set('Asia/Kolkata');
                        $currentDate = date("Y:m:d H:i:s");
                        $this->usermodel->updateLastLoginInUsers($userId);
                        $response['message']= "Welcome back ".$email;
                        $response['token']= $this->generate_token();
                        $response['response'] = true;
                        $token_data = array(
                            'token' => $response['token'],
                            'login_active_status'=>1,
                            'updated_at'=>$currentDate,
                            'hit_time'=>$currentDate
                        );
                        $updated_id = $this->usermodel->updateToken($token_data,$userId);
                        $errorCode = 200;
                    }
            }
            else
            {
                $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
                if($loginAttemptStatus)
                {
                    return redirect()->to('blockUserMessage')->with('email', $email);
                }
                    $user_details = $this->usermodel->getUserDetails($userId);
                    $this->usermodel->updateLastLoginInUsers($userId);
					$response['user']= "Welcome - : ".$this->dataHandler->retrieveAndDecrypt($user_details->email);
					$response['message']="User logged in successfully";
					$response['token']= $this->generate_token();
					$response['response'] = true;

                    date_default_timezone_set('Asia/Kolkata');
                    $currentDate = date("Y:m:d H:i:s");

					$token_data = array(
						'uid' => $user_details->uid,
						'token' => $response['token'],
						'login_active_status'=>1,
                        'created_at'=>$currentDate,
                        'hit_time'=>$currentDate,
					);

					$inserted_id = $this->usermodel->insertToken($token_data);
					$errorCode = 200;
            }
        }
        else
        {
            $this->usermodel->increaseUsersInvalidLoginAttempts($this->request->getIPAddress(),$email,time());
            $response['message'] = "Invalid email-id";
            $response['response'] = false;
            $errorCode = 401; 
        }

        $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
        if($loginAttemptStatus)
        {
            return redirect()->to('blockUserMessage')->with('email', $email);
        }
        $this->usermodel->clearInvalidLoginAttempts($email);
        return $this->response->setJSON($response)->setStatusCode($errorCode);
    }
   
}



public function logout()
{
    $response = [];
	$errorCode = '';

    $token = $this->request->getHeader('token');

    if($token!='')
    {
        date_default_timezone_set('Asia/Kolkata');
        $currentDate = date("Y:m:d H:i:s");
		$data = array(
			'token'=>'',
            'hit_time'=>null,
			'login_active_status'=>0,
            'updated_at'=>$currentDate
		);
		if($this->usermodel->destroyToken($token->getValue(),$data)==1){
			$response['message']= "Logout succesfully";
			$response['response'] = true;
			$errorCode = 200;
		}
		else
        {
			$response['message']= "Invalid token";
			$response['response'] = false;
			$errorCode = 401;
		}  
	}
	else
    {
		$response['message']= "No token found";
		$response['response'] = false;
		$errorCode = 401;
	}

    return $this->response->setJSON($response)->setStatusCode($errorCode);
   
}


public function decryptDataRow($data)
{
        $arr['id'] = $data->id;
        $arr['uid'] = $data->uid;
		$arr['email'] = $this->dataHandler->retrieveAndDecrypt($data->email);
        $arr['firstname'] = $this->dataHandler->retrieveAndDecrypt($data->first_name);
        $arr['lastname'] = $this->dataHandler->retrieveAndDecrypt($data->last_name);
		$arr['company'] = $this->dataHandler->retrieveAndDecrypt($data->company);
        $arr['phone'] = $this->dataHandler->retrieveAndDecrypt($data->phone);
    return $arr;
}

public function get_user_data()
{
    $response = [];
	$errorCode = '';

    $token = $this->request->getHeader('token');

    if($token!='')
    {
        $userdata = $this->userlibrary->verifyTokenIsValid($token->getValue());
        if($userdata)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
            $result = $this->usermodel->getUserDetails($userdata->uid);

            if(!$checkTimeoutStatus)
            {
                return redirect()->route('logout');
            }
            $decryptedUserData = $this->decryptDataRow($result);
            $response['message']= "User details";
            $response['data']= $decryptedUserData;
            $response['response']=true;
            $errorCode = 200;
        }
        else
        {
            $response['message']= "Invalid user token";
            $response['response']=false;
            $errorCode = 401;
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
		$errorCode = 401;
    }

    return $this->response->setJSON($response)->setStatusCode($errorCode);

}

public function testcode()
{
    // echo "calling testcode";die;
    echo $this->dataHandler->retrieveAndDecrypt('blE6TiTGYJ241aPpWaMLzsAhw9u0fcUOi3i0gJxX0CU=');
    die;
}



}
