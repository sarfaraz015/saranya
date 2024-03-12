<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\ResponseInterface;
use App\Models\UserModel;
use App\Libraries\UserLibrary;
use App\Libraries\SecureDataHandler;
use Config\Tester;
use App\Libraries\Lib_log;
// use CodeIgniter\HTTP\Client;

class UserController extends BaseController
{

    public $usermodel;
    public $userlibrary;
    public $dataHandler;

    public $tester;

    public function __construct()
    {
           $testlib = new Lib_log();
           $secret_key = $_ENV['ENCRYPTION_KEY'];
           $salt = $_ENV['SALT'];
           $this->usermodel = new UserModel();
           $this->userlibrary = new UserLibrary();
           $this->dataHandler = new SecureDataHandler($secret_key, $salt);
           $this->tester = new Tester();
    }
    public function index()
    {
        echo "Calling index from UserController";
    }

    public function test()
    {
        return $this->response->setJSON(["message"=>"Calling Test api from Usercontroller"])->setStatusCode(200);
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


// final
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
    $response = [];
    $errorCode = '';
    $receivedData = session()->getFlashdata();
    $email = $receivedData['email'];
    $status = $this->userlibrary->checkTemperorlyBlockedUserAndActivate($email);
    
   if(!$status)
   {
        $response['message'] = "Email-Id ".$email." has been temporarily blocked";
        $response['response'] = false;
        $errorCode = 401; 
   }
   else
   {
        $response['message'] = "Your Email-ID is activated please go to login page and login again";
        $response['response'] = true;
        $errorCode = 200; 
   }
 
   return $this->response->setJSON($response)->setStatusCode($errorCode);
}


// final
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
    
            if (!password_verify($password, $dbPassword)) 
            {
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
                        // $this->userlibrary->storeLogs(debug_backtrace(),$userId,$token=null);
                        $response['message']= "Welcome back ".$email;
                        $response['token']= $this->generate_token();
                        $response['response'] = true;
                        $token_data = array(
                            'token' => $response['token'],
                            'login_active_status'=>1,
                            // 'updated_at'=>$currentDate,
                            'hit_time'=>$currentDate
                        );
                        $this->userlibrary->storeLogs(debug_backtrace(),$userId,$token=null,$json_data,$response);
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
                    // $this->userlibrary->storeLogs(debug_backtrace(),$userId,$token=null);
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
                        'created_on'=>$currentDate,
                        'hit_time'=>$currentDate,
					);
                    $this->userlibrary->storeLogs(debug_backtrace(),$userId,$token=null,$json_data,$response);
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


public function generateOTP()
{
   $currentDate = time();
   return substr($currentDate,-4);
}



public function forgot_password()
{
    if ($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';

        $rules = [
            'email'=>'required|valid_email',
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

        if($this->userlibrary->checkUserAlreadyExists($email))
        {
            $otp = $this->generateOTP();
            $userId = $this->usermodel->getUserId($email);
            $this->usermodel->deactivateOldOTP($userId);
            date_default_timezone_set('Asia/Kolkata');
            $currentDate = date("Y:m:d H:i:s");

            $data = array(
                'uid'=>$userId,
                'email'=>$email,
                'otp'=>$otp,
                'otp_active_status'=>1,
                'created_on'=>$currentDate
            );

            if($this->usermodel->insertOTP($data))
            {
                $response['message'] = "OTP generated successfully";
				$response['otp'] = $otp;
				$errorCode = 200;
                if($this->userlibrary->sendOTPEmail($email,$otp))
                {
                    $response['mail_status'] = "Mail sent successfully";
                    $response['response'] = true;
                }
                else
                {
                    $response['mail_status'] = "Mail failed";
                    $response['response'] = false;
                }
            }
        }
        else
        {
            $response['message'] = "Invalid email-id";
            $response['response'] = false;
            $errorCode = 401; 
        }
        return $this->response->setJSON($response)->setStatusCode($errorCode);
    }    

}


public function resetPassword($user_id,$newPassword,$otp)
{
    $OTPTimeOutStatus = '';
    
    if($this->userlibrary->checkTimeOutForOTP($user_id,$otp))
    {
        $updated_data = array(
            'password'=>$newPassword
        );
        $this->usermodel->updateNewPassword($updated_data,$user_id);
        $OTPTimeOutStatus = 1;
    }
    else
    {
        $OTPTimeOutStatus = 0;
    }
	
    return $OTPTimeOutStatus;
}


public function reset_password()
{
    if($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';
        $rules = [
            'otp'=>'required',
            'new_password'=>'required',
            'confirm_password'=>'required|matches[new_password]',
        ];

        if(!$this->validate($rules))
        {
            $response['errors'] = $this->validator->getErrors();
            $errorCode = 401;
            $response['response'] = false;
            return $this->response->setJSON($response)->setStatusCode($errorCode);
        }

        $json_data = $this->request->getJSON();
        $otp = trim($json_data->otp);
        $new_password = trim($json_data->new_password);

           if($user_id = isset($this->userlibrary->verifyOTP($otp)->uid)?$this->userlibrary->verifyOTP($otp)->uid:0)
		   {
                $this->usermodel->deactivateOTPOnResetPassword($user_id,$otp);
                if($this->resetPassword($user_id,password_hash($new_password,PASSWORD_DEFAULT),$otp))
                {
                    $response['message']="Password updated successfully";
					$response['response']=true;
					$errorCode = 200; 
                }
                else
                {
                    $response['message']="Password updation failed";
                    $response['error']="OTP expired";
					$response['response']=false;
					$errorCode = 401;
                }
           }
           else
           {
                $response['message']="Invalid OTP";
                $response['response']=false;
                $errorCode = 401;
           }

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
            // 'updated_at'=>$currentDate
		);
        $this->userlibrary->storeLogs(debug_backtrace(),$userId=null,$token->getValue(),null,$response);
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


public function testerToken()
{
	$response = [];
	$error_code = '';
	$users = $this->tester->getTestersData();
    
	$token = $this->request->getHeader('Authorization');
	$email = $this->request->getHeader('testerEmail');

	if($token!='')
	{
			if($email!='')
			{
				if(array_key_exists($email->getValue(),$users))
				{
					if('Bearer '.$users[$email->getValue()]==$token->getValue())
					{
						$response['message']="success";
						$response['response'] = true;
					}
					else
					{
						$response['message']="Invalid tester token";
						$response['response'] = false;
					}
                }
                else
                {
                        $response['message']="Invalid tester email-id";
                        $response['response'] = false;
                }
			}
			else
			{
				$response['message']="No tester email-id found";
				$response['response'] = false;
			}
	}
	else
	{
		$response['message']="No tester token found";
		$response['response'] = false;
	}

	return $response;
}

public function get_user_data()
{
    $byPass = false;
    $tester_token = '';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken())->setStatusCode(401);
            }
            else
            {
                    $byPass = true;
                    $tester_token = $this->request->getHeader('Authorization')->getValue();
            }
      }

    $response = [];
	$errorCode = '';

    $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');

    if($token!='')
    {
        $uid = '';
        if($byPass)
        {
            $uid = $this->usermodel->getUserId($this->request->getHeader('testerEmail')->getValue());
        }
        else
        {
            $userdata = $this->userlibrary->verifyTokenIsValid($token->getValue());
            $uid = $userdata?$userdata->uid:'';
        }

        if($uid)
        {
            $checkTimeoutStatus = true;
            if(!$byPass)
            {
                $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
            }
            
            $result = $this->usermodel->getUserDetails($uid);

            if(!$checkTimeoutStatus)
            {
                return redirect()->route('logout');
            }
            // $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,null,$response);
            $decryptedUserData = $this->decryptDataRow($result);
            $response['message']= "User details";
            $response['data']= $decryptedUserData;
            $response['response']=true;
            $errorCode = 200;
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,null,$response);
        }
        else
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $errorCode = 401;
            }
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
    echo $this->dataHandler->retrieveAndDecrypt('blE6TiTGYJ241aPpWaMLzsAhw9u0fcUOi3i0gJxX0CU=');
    die;
}


public function generate_tester_token()
{
    if ($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';

        $rules = [
            'password_length'=>'required|numeric|greater_than_equal_to[8]',
            'alphabets'=>'required|in_list[true,false]',
            'numbers'=>'required|in_list[true,false]',
            'symbols'=>'required|in_list[true,false]',
        ];

        if(!$this->validate($rules))
        {
            $response['errors'] = $this->validator->getErrors();
            $errorCode = 401;
            $response['response'] = false;
            return $this->response->setJSON($response)->setStatusCode($errorCode);
        }

        $json_data = $this->request->getJSON();
        $length = trim($json_data->password_length);
        $alphabets = trim($json_data->alphabets);
        $numbers = trim($json_data->numbers);
        $symbols = trim($json_data->symbols);

        $tester_token = $this->userlibrary->getTesterToken($length,$numbers,$alphabets,$symbols);
        $errorCode = 200;
        $response['message'] = "Tester token created successfully";
        $response['response'] = true;
        $response['tester_token'] = $tester_token;
        return $this->response->setJSON($response)->setStatusCode($errorCode);
    }
	
}


public function contactLog(){
    $userLogs = $this->userlibrary->storeLogs(debug_backtrace());
    print_r($userLogs);die;
}

public function aboutLog(){
    $userLogs = $this->userlibrary->storeLogs(debug_backtrace());
    print_r($userLogs);die;
}


public function settingLog(){
    $userLogs = $this->userlibrary->storeLogs(debug_backtrace());
    print_r($userLogs);die;
}



public function tom($par1=null,$par2=null)
{
    //  print_r("calling tom");die;
    echo $par1 ." / ". $par2;die;
}

public function testingCode()
{
    //  echo 'testingCode';die;
    $param1 = "H";
    $param2 = "M";
    // $this->tom($param1,$param2);
    $this->tom($param1);

}

public function testBlockTime()
{
    // echo 'testBlockTime';die;
}





public function testapi()
{ 
    $user_id = 16;
    if($this->userlibrary->chekApiHitTimings($user_id)['response'])
    {
        return $this->response->setJSON(["message"=>"Test API page"])->setStatusCode(200);
    }
    else
    {
        return $this->response->setJSON($this->userlibrary->chekApiHitTimings($user_id))->setStatusCode($this->userlibrary->chekApiHitTimings($user_id)['code']);
    }
}

public function about()
{    
    $user_id = 16;
    if($this->userlibrary->chekApiHitTimings($user_id)['response'])
    {
        return $this->response->setJSON(["message"=>"About page"])->setStatusCode(200);
    }
    else
    {
        return $this->response->setJSON($this->userlibrary->chekApiHitTimings($user_id))->setStatusCode($this->userlibrary->chekApiHitTimings($user_id)['code']);
    }
}

public function contact()
{ 
    $user_id = 16;
    if($this->userlibrary->chekApiHitTimings($user_id)['response'])
    {
        return $this->response->setJSON(["message"=>"Contact page"])->setStatusCode(200); 
    }
    else
    {
        return $this->response->setJSON($this->userlibrary->chekApiHitTimings($user_id))->setStatusCode($this->userlibrary->chekApiHitTimings($user_id)['code']);
    } 
}





}
