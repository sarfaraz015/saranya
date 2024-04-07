<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\ResponseInterface;
use App\Models\UserModel;
use App\Libraries\UserLibrary;
use App\Libraries\SecureDataHandler;
use Config\Tester;
// use App\Libraries\Lib_log;
// use CodeIgniter\HTTP\Client;

class UserController extends BaseController
{

    public $usermodel;
    public $userlibrary;
    public $dataHandler;

    public $tester;

    public function __construct()
    {
        //    $testlib = new Lib_log();
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


 ################################### INNER METHODS #############################   
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
           'phone'=>$phone_encrypt,
           'user_type'=>$data['user_type']
       );

       return $encryptedData;

}

public function encryptUserDataForUpdate($data)
{
       $username_encrypt = $this->dataHandler->encryptAndStore($data['username']);
       $email_encrypt = $this->dataHandler->encryptAndStore($data['email']);
       $first_name_encrypt = $this->dataHandler->encryptAndStore($data['first_name']);
       $last_name_encrypt = $this->dataHandler->encryptAndStore($data['last_name']);
       $company_encrypt = $this->dataHandler->encryptAndStore($data['company']);
       $phone_encrypt = $this->dataHandler->encryptAndStore($data['phone']);

       $encryptedData = array(
           'uid'=>$data['uid'],
           'username'=>$username_encrypt,
           'email'=>$email_encrypt,
           'first_name'=>$first_name_encrypt,
           'last_name'=>$last_name_encrypt,
           'company'=>$company_encrypt,
           'phone'=>$phone_encrypt,
           'profile_img'=>$data['profile_img']
       );

       return $encryptedData;

}


public function generate_token() 
{
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


public function generateOTP()
{
   $currentDate = time();
   return substr($currentDate,-4);
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

public function decryptDataRow($data)
{
        $arr['id'] = $data->id;
        $arr['uid'] = $data->uid;
		$arr['email'] = $this->dataHandler->retrieveAndDecrypt($data->email);
        $arr['first_name'] = $this->dataHandler->retrieveAndDecrypt($data->first_name);
        $arr['last_name'] = $this->dataHandler->retrieveAndDecrypt($data->last_name);
		$arr['company'] = $this->dataHandler->retrieveAndDecrypt($data->company);
        $arr['phone'] = $this->dataHandler->retrieveAndDecrypt($data->phone);
        $arr['profile_img'] = $data->profile_img;
    return $arr;
}

public function decryptDataResult($data)
{
      $finalArray = [];
       foreach($data as $key => $value){
        $arr['id'] = $value->id;
        $arr['uid'] = $value->uid;
		$arr['email'] = $this->dataHandler->retrieveAndDecrypt($value->email);
        $arr['first_name'] = $this->dataHandler->retrieveAndDecrypt($value->first_name);
        $arr['last_name'] = $this->dataHandler->retrieveAndDecrypt($value->last_name);
		$arr['company'] = $this->dataHandler->retrieveAndDecrypt($value->company);
        $arr['phone'] = $this->dataHandler->retrieveAndDecrypt($value->phone);
        array_push($finalArray,$arr);
       }

      return $finalArray;
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


####################################  USERS FUNCTION ############################

// Handled encryption
public function register()
{
    if ($this->request->getMethod() === 'post') 
    {
        $finalResponse = '';
        $response = [];
        $errorCode = '';
        
        $rules = [
            'email'=>'required|valid_email',
            'password'=>'required',
            'password_confirm'=>'required|matches[password]',
            'first_name'=>'required',
            'last_name'=>'required',
            'company'=>'required',
            'phone'=>'required',
            'user_type'=>'required'
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            unset($inputData->password);
            unset($inputData->password_confirm);
            $response['return_data'] = $inputData;

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
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
                $user_type = trim($json_data->user_type);

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
                    'phone'=>$phone,
                    'user_type'=>$user_type
                );

                if($this->userlibrary->registerUser($data))
                {
                    $setDefaultResponse = $this->userlibrary->setDefaultMenuUserAuthsPermissions($uid);
                    if($setDefaultResponse['response'])
                    {
                        $response['message'] = "User registered successfully";
                        $response['response'] = true;
                        $response['code'] = 200;
                        $response['result_data'] = [];
                        $response['return_data'] = []; 
                    }
                    else
                    {
                        $response['message'] = $setDefaultResponse['message'];
                        $response['response'] = $setDefaultResponse['response'];
                        $response['code'] = $setDefaultResponse['code'];
                        $response['result_data'] = $setDefaultResponse['result_data'];
                        $response['return_data'] = $setDefaultResponse['return_data']; 
                    }
                  
                }
                else
                {
                        $response['message'] = "Something went wrong while registration";
                        $response['response'] = false;
                        $response['code'] = 401;
                        $response['result_data'] = [];
                        $response['return_data'] = $data; 
                }
            }
            else
            {
                    $response['message'] = "User already exists in the database";
                    $response['response'] = false;
                    $response['code'] = 401;
                    $response['result_data'] = [];
                    $inputData = $this->request->getJSON();
                    unset($inputData->password);
                    unset($inputData->password_confirm);
                    $response['return_data'] = $inputData;
            }

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
    
    } 
    

}

// Done with encryption
public function login()
{
    if ($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';
        $finalResponse = '';
        $blockUserMessage = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'blockUserMessage';

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
                $this->userlibrary->addLoginAttemptsHistory($email,$this->request->getIPAddress(),$_SERVER['HTTP_USER_AGENT'],$is_success=0);
                $response['message'] = "Invalid password";
                $response['response'] = false;
                $response['code'] = 401;
                $response['result_data'] = [];
                $response['return_data'] = [
                    "email" => $json_data->email
                ];
                $finalResponse = $this->userlibrary->generateResponse($response);
                $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
                if($loginAttemptStatus)
                {
                    return redirect()->to($blockUserMessage)->with('email', $email);
                }
                return $this->response->setJSON($finalResponse);
            } 


            $userId = $this->usermodel->getUserId($email);
            if($this->userlibrary->userExistsInUsersToken($userId)){
                
                if($this->userlibrary->checkActiveStatus($userId)){
                       
                        $response['message']= "User ".$email." already logged in";
                        $response['response'] = true;
                        $response['code'] = 200;
                        $response['result_data'] = [
                            'token' => $this->userlibrary->checkActiveStatus($userId)->token,
                        ];
                        $response['return_data'] = [];
                    }
                    else
                    {
                        $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
                        if($loginAttemptStatus)
                        {
                            return redirect()->to($blockUserMessage)->with('email', $email);
                        }

                        date_default_timezone_set('Asia/Kolkata');
                        $currentDate = date("Y:m:d H:i:s");
                        $this->usermodel->updateLastLoginInUsers($userId);
                        $this->userlibrary->addLoginAttemptsHistory($email,$this->request->getIPAddress(),$_SERVER['HTTP_USER_AGENT'],$is_success=1);
                        $response['message']= "Welcome back ".$email;
                        $response['response'] = true;
                        $response['code'] = 200;
                        $generatedToken = $this->generate_token();
                        $response['result_data'] = [
                            'token' => $generatedToken,
                        ];
                        $response['return_data'] = [];

                        $token_data = array(
                            'token' => $generatedToken,
                            'login_active_status'=>1,
                            'hit_time'=>$currentDate,
                            'is_expired'=>0,
                        );
                        $this->userlibrary->storeLogs(debug_backtrace(),$userId,$token=null,$json_data,$response);
                        $updated_id = $this->usermodel->updateToken($token_data,$userId);
                    }
            }
            else
            {
                $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
                if($loginAttemptStatus)
                {
                    return redirect()->to($blockUserMessage)->with('email', $email);
                }
                    $user_details = $this->usermodel->getUserDetails($userId);
                    $this->usermodel->updateLastLoginInUsers($userId);
                    $this->userlibrary->addLoginAttemptsHistory($email,$this->request->getIPAddress(),$_SERVER['HTTP_USER_AGENT'],$is_success=1);
					$response['message']= "Welcome - : ".$this->userlibrary->decryptValue($user_details->email);
                    $generatedToken = $this->generate_token();
					$response['response'] = true;
                    $response['code'] = 200;
                    $response['result_data'] = [
                        'token' => $generatedToken,
                    ];
                    $response['return_data'] = [];

                    date_default_timezone_set('Asia/Kolkata');
                    $currentDate = date("Y:m:d H:i:s");

					$token_data = array(
						'uid' => $user_details->uid,
						'token' => $generatedToken,
						'login_active_status'=>1,
                        'created_on'=>$currentDate,
                        'hit_time'=>$currentDate,
                        'is_expired'=>0,
					);
                    $this->userlibrary->storeLogs(debug_backtrace(),$userId,$token=null,$json_data,$response);
					$inserted_id = $this->usermodel->insertToken($token_data);
            }
        }
        else
        {
            $this->usermodel->increaseUsersInvalidLoginAttempts($this->request->getIPAddress(),$email,time());
            $response['message'] = "Invalid email-id";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [
                    "email" => $json_data->email
            ];
        }

        $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
        if($loginAttemptStatus)
        {
            return redirect()->to($blockUserMessage)->with('email', $email);
        }
        $this->usermodel->clearInvalidLoginAttempts($email);
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }
   
}

// Done with encryption
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
                'email'=>$this->userlibrary->encryptValue($email),
                'otp'=>$otp,
                'otp_active_status'=>1,
                'created_on'=>$currentDate
            );

            if($this->usermodel->insertOTP($data))
            {
                $response['message'] = "OTP generated successfully";
				$otp = $otp;
                $response['code'] = 200;
                $mail_status = '';
                $emailResponse = '';
                if($this->userlibrary->sendOTPEmail($email,$otp))
                {
                    $mail_status = "Mail sent successfully";
                    $emailResponse = true;
                }
                else
                {
                    $mail_status = "Mail failed";
                    $emailResponse = false;
                }
                $response['response'] = 200; 
                $response['result_data'] = [
                     'email_status' => $mail_status,
                     'email_response'=> $emailResponse,
                     'otp'=>$otp
                ];
                $response['return_data'] = [];
            }
        }
        else
        {
            $response['message'] = "Invalid email-id";
            $response['response'] = false;
            $response['code'] = 401; 
            $response['result_data'] = [];
            $response['return_data'] = [];
        }
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }    

}


// Done with encryption
public function reset_password()
{
    if($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';
        $finalResponse = '';
        $rules = [
            'otp'=>'required',
            'new_password'=>'required',
            'confirm_password'=>'required|matches[new_password]',
        ];

        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['code'] = 200;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = [
                "data"=>$this->request->getJSON()
            ];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
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
                    $response['code'] = 200;
                    $response['result_data'] = [];
                    $response['return_data'] = [];
                }
                else
                {
                    $response['message']="Password updation failed";
                    $response['error']="OTP expired";
					$response['response']=false;
                    $response['code'] = 401;
                    $response['result_data'] = [];
                    $response['return_data'] = [];
                }
           }
           else
           {
                $response['message']="Invalid OTP";
                $response['response']=false;
                $response['code'] = 401;
                $response['result_data'] = [];
                $response['return_data'] = [
                    "data"=>$this->request->getJSON()
                ];
           }
           $finalResponse = $this->userlibrary->generateResponse($response);
           return $this->response->setJSON($finalResponse);
    }

}


// Done with encryption
public function logout()
{
    $response = [];
	$errorCode = '';
    $finalResponse = '';

    $token = $this->request->getHeader('token');

    if($token!='')
    {
        date_default_timezone_set('Asia/Kolkata');
        $currentDate = date("Y:m:d H:i:s");
		$data = array(
			// 'token'=>'',
            'hit_time'=>null,
			'login_active_status'=>0,
            'is_expired'=>1
		);
        $this->userlibrary->storeLogs(debug_backtrace(),$userId=null,$token->getValue(),null,$response);
		if($this->usermodel->destroyToken($token->getValue(),$data)==1){
			$response['message']= "Logout succesfully";
			$response['response'] = true;
            $response['code'] = 200;
            $response['result_data'] = [];
            $response['return_data'] = [];
		}
		else
        {
			$response['message']= "Invalid token";
			$response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
		}  
	}
	else
    {
		$response['message']= "No token found";
		$response['response'] = false;
        $response['code'] = 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
	}

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);
}


// Done with encryption
public function get_user_data()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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
            $decryptedUserData = $this->userlibrary->decryptRow($result,['username','email','first_name','last_name','company','phone']);
            $response['message']= "Single user details";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $decryptedUserData;
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}


// Not in use : 
// public function get_all_users_xxxx()
// {
//     $byPass = false;
//     $tester_token = '';
//     $finalResponse = '';
 
//       if($this->request->getHeader('testerEmail')!=''){
//             $response = $this->testerToken();
//             if(!$this->testerToken()['response'])
//             {
//                 return $this->response->setJSON($this->testerToken());
//             }
//             else
//             {
//                     $byPass = true;
//                     $tester_token = $this->request->getHeader('Authorization')->getValue();
//             }
//       }

//       $response = [];
//       $errorCode = '';
  
//       $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
  
//       if($token!='')
//       {
//           $uid = '';
//           if($byPass)
//           {
//               $uid = $this->usermodel->getUserId($this->request->getHeader('testerEmail')->getValue());
//           }
//           else
//           {
//               $userdata = $this->userlibrary->verifyTokenIsValid($token->getValue());
//               $uid = $userdata?$userdata->uid:'';
//           }
  
//           if($uid)
//           {
//               $checkTimeoutStatus = true;
//               if(!$byPass)
//               {
//                   $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
//               }
              
//               $result = $this->usermodel->getAllUserDetails();
  
//               if(!$checkTimeoutStatus)
//               {
//                   return redirect()->route('logout');
//               }
//               $decryptedUserData = $this->decryptDataResult($result);
//               $response['message']= "All users details";
//               $response['result_data']= $decryptedUserData;
//               $response['return_data'] = [];
//               $response['response']=true;
//               $response['code']=true;
//               $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,null,$response);
//           }
//           else
//           {
//               if($byPass)
//               {
//                   $response['message']= "Tester user not registered in our database";
//                   $response['response']=false;
//                   $errorCode = 401;
//               }
//               else
//               {
//                 $response['message']= "Invalid user token";
//                 $response['response']=false;
//                 $response['code']= 401;
//                 $response['result_data'] = [];
//                 $response['return_data'] = [];
//               }
//           }
//       }
//       else
//       {
//         $response['message']= "No user token found";
// 		$response['response'] = false;
//         $response['code']= 401;
//         $response['result_data'] = [];
//         $response['return_data'] = [];
//       }
  
//       $finalResponse = $this->userlibrary->generateResponse($response);
//       return $this->response->setJSON($finalResponse);
// }


// Not in use 
// public function update_user_xxxx()
// {
//     if ($this->request->getMethod() === 'post') 
//     {

//         $byPass = false;
//         $tester_token = '';
//          // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
//         $logoutUrl = $_ENV['app_baseURL'].'logout';
     
//           if($this->request->getHeader('testerEmail')!=''){
//                 $response = $this->testerToken();
//                 if(!$this->testerToken()['response'])
//                 {
//                     return $this->response->setJSON($this->testerToken())->setStatusCode(401);
//                 }
//                 else
//                 {
//                         $byPass = true;
//                         $tester_token = $this->request->getHeader('Authorization')->getValue();
//                 }
//           }


//         $response = [];
//         $errorCode = '';
//         $finalResponse = '';

//         $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
//         if($token=='')
//         {
//             $response['message']= "No user token";
//             $response['response'] = false;
//             $response['code'] = 401;
//             $response['result_data'] = [];
//             $response['return_data'] = [];
//             $finalResponse = $this->userlibrary->generateResponse($response);
//             return $this->response->setJSON($response);
//         }

//         $uid = '';
//         if($byPass)
//         {
//             $uid = $this->usermodel->getUserId($this->request->getHeader('testerEmail')->getValue());
//         }
//         else
//         {
//             $userdata = $this->userlibrary->verifyTokenIsValid($token->getValue());
//             $uid = $userdata?$userdata->uid:'';
//         }

//         if($uid=='')
//         {
//             if($byPass)
//             {
//                 $response['message']= "Tester user not registered in our database";
//                 $response['response']=false;
//                 $errorCode = 401;
//                 return $this->response->setJSON($response)->setStatusCode($errorCode);
//             }
//             else
//             {
//                 $response['message']= "Invalid user token";
//                 $response['response']=false;
//                 $response['code']= 401;
//                 $response['result_data'] = [];
//                 $response['return_data'] = [];
//                 $finalResponse = $this->userlibrary->generateResponse($response);
//                 return $this->response->setJSON($finalResponse);
//             } 
//         }
        
//         $checkTimeoutStatus = true;
//         if(!$byPass)
//         {
//             $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
//         }
        
//         if(!$checkTimeoutStatus)
//         {
//             return redirect()->to($logoutUrl);
//         }

//         $rules = [
//             'email'=>'required|valid_email',
//             'first_name'=>'required',
//             'last_name'=>'required',
//             'company'=>'required',
//             'phone'=>'required',
//             'profile_img'=>'required'
//         ];
    
//         if(!$this->validate($rules))
//         {
//             $response['message'] = $this->validator->getErrors();
//             $response['response'] = false;
//             $response['code'] = 401;
//             $response['result_data'] = [];
//             $inputData = $this->request->getJSON();
//             $response['return_data'] = $inputData;

//             $finalResponse = $this->userlibrary->generateResponse($response);
//             return $this->response->setJSON($finalResponse);
//         }
    
//         $json_data = $this->request->getJSON();

//         $data = array(
//             'uid'=>$uid,
//             'username'=>trim($json_data->first_name).trim($json_data->last_name),
//             'email'=>trim($json_data->email),
//             'first_name'=>trim($json_data->first_name),
//             'last_name'=>trim($json_data->last_name),
//             'company'=>trim($json_data->company),
//             'phone'=>trim($json_data->phone),
//             'profile_img'=>trim($json_data->profile_img)
//         );

//         $encryptedData = $this->encryptUserDataForUpdate($data);

//         $rowId = $this->userlibrary->insertUserDataInProfileChangeHistory($uid);
//         if($rowId)
//         {
//             $this->usermodel->updateUserData($encryptedData);
//             $response['message'] = "Profile updated successfully";
//             $response['code'] = 200;
//             $response['response'] = true;
//             $response['result_data'] = [];
//             $response['return_data'] = [];
//             $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
//         }
//         else
//         {
//             $response['message'] = "Profile Not updated : Reason (error in user profile history)";
//             $response['code'] = 401;
//             $response['response'] = false;
//             $response['result_data'] = [];
//             $response['return_data'] = $data;
//         }
        
//         $finalResponse = $this->userlibrary->generateResponse($response);
//         return $this->response->setJSON($finalResponse);
//     }

// }


// public function update_user_xxxx()
// {
//     if ($this->request->getMethod() === 'post') 
//     {

//         $byPass = false;
//         $tester_token = '';
//          // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
//         $logoutUrl = $_ENV['app_baseURL'].'logout';
     
//           if($this->request->getHeader('testerEmail')!=''){
//                 $response = $this->testerToken();
//                 if(!$this->testerToken()['response'])
//                 {
//                     return $this->response->setJSON($this->testerToken())->setStatusCode(401);
//                 }
//                 else
//                 {
//                         $byPass = true;
//                         $tester_token = $this->request->getHeader('Authorization')->getValue();
//                 }
//           }


//         $response = [];
//         $errorCode = '';
//         $finalResponse = '';

//         $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
//         if($token=='')
//         {
//             $response['message']= "No user token";
//             $response['response'] = false;
//             $response['code'] = 401;
//             $response['result_data'] = [];
//             $response['return_data'] = [];
//             $finalResponse = $this->userlibrary->generateResponse($response);
//             return $this->response->setJSON($response);
//         }

//         $uid = '';
//         if($byPass)
//         {
//             $uid = $this->usermodel->getUserId($this->request->getHeader('testerEmail')->getValue());
//         }
//         else
//         {
//             $userdata = $this->userlibrary->verifyTokenIsValid($token->getValue());
//             $uid = $userdata?$userdata->uid:'';
//         }

//         if($uid=='')
//         {
//             if($byPass)
//             {
//                 $response['message']= "Tester user not registered in our database";
//                 $response['response']=false;
//                 $errorCode = 401;
//                 return $this->response->setJSON($response)->setStatusCode($errorCode);
//             }
//             else
//             {
//                 $response['message']= "Invalid user token";
//                 $response['response']=false;
//                 $response['code']= 401;
//                 $response['result_data'] = [];
//                 $response['return_data'] = [];
//                 $finalResponse = $this->userlibrary->generateResponse($response);
//                 return $this->response->setJSON($finalResponse);
//             } 
//         }
        
//         $checkTimeoutStatus = true;
//         if(!$byPass)
//         {
//             $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
//         }
        
//         if(!$checkTimeoutStatus)
//         {
//             return redirect()->to($logoutUrl);
//         }

//         $rules = [
//             'username'=>'required',
//             'phone'=>'required',
//             'address_1'=>'required',
//             'address_2'=>'required',
//             'profile_img'=>'required'
//         ];
    
//         if(!$this->validate($rules))
//         {
//             $response['message'] = $this->validator->getErrors();
//             $response['response'] = false;
//             $response['code'] = 401;
//             $response['result_data'] = [];
//             $inputData = $this->request->getJSON();
//             $response['return_data'] = $inputData;

//             $finalResponse = $this->userlibrary->generateResponse($response);
//             return $this->response->setJSON($finalResponse);
//         }
    
//         $json_data = $this->request->getJSON();

//         $data = array(
//             'uid'=>$uid,
//             'username'=>trim($json_data->username),
//             'phone'=>trim($json_data->phone),
//             'address_1'=>trim($json_data->address_1),
//             'address_2'=>trim($json_data->address_2),
//             'profile_img'=>trim($json_data->profile_img)
//         );

//         $encryptedData = $this->userlibrary->encryptRowForSpecificColumns((object)$data,['username','phone']);

//         unset($encryptedData->address_1);
//         unset($encryptedData->address_2);

//         $rowId = $this->userlibrary->insertUserDataInProfileChangeHistory($uid);
//         if($rowId)
//         {
//             $this->usermodel->updateUserData((array)$encryptedData);
//             $response['message'] = "Profile updated successfully";
//             $response['code'] = 200;
//             $response['response'] = true;
//             $response['result_data'] = [];
//             $response['return_data'] = [];
//             $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
//         }
//         else
//         {
//             $response['message'] = "Profile Not updated : Reason (error in user profile history)";
//             $response['code'] = 401;
//             $response['response'] = false;
//             $response['result_data'] = [];
//             $response['return_data'] = $data;
//         }
        
//         $finalResponse = $this->userlibrary->generateResponse($response);
//         return $this->response->setJSON($finalResponse);
//     }

// }


// Not involve in encryption : 
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

// Done encryption
public function get_all_users()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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

              if(!$checkTimeoutStatus)
              {
                return redirect()->to($logoutUrl);
              }

              $rules = [
                'number_of_records'=>'required',
                'pagination_number'=>'required'
            ];
            
            if(!$this->validate($rules))
            {
                $response['message'] = $this->validator->getErrors();
                $response['response'] = false;
                $response['code'] = 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
        
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            }
            
            $json_data = $this->request->getJSON();
            $number_of_records = $json_data->number_of_records;
            $pagination_number = $json_data->pagination_number;
            $search = $json_data->search;
            $result = [];
            if($search!=null){
                $result = $this->userlibrary->getFilteredUsers($search,$number_of_records,$pagination_number);
            }
            else{
                $result = $this->userlibrary->getStandardRecords($number_of_records,$pagination_number);
            }
        
              $decryptedUserData = $this->userlibrary->decryptResult($result,['username','first_name','last_name','email','company','phone']);
            //   $decryptedUserData = $this->userlibrary->decryptMainMenu($result,['username','first_name','last_name','email','company','phone']);
              $response['message']= "All users details";
              $response['result_data']= $decryptedUserData;
              $response['return_data'] = [];
              $response['response']=true;
              $response['code']=true;
              $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$json_data,$response);
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
              }
          }
      }
      else
      {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
      }
  
      $finalResponse = $this->userlibrary->generateResponse($response);
      return $this->response->setJSON($finalResponse);
}


// Working code : 
// Done encryption with normal and auth9 users
public function get_main_menu()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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
            
            $result = $this->userlibrary->getMainManuData($uid);
       
            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            $response['message']= "Main manu module data";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $this->userlibrary->decryptResultArray($result,['name','description','icon_name','link']);
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}

// I think this function is not in use : 
public function upload_user_profile_img()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
         // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $rules = [
            'image_data'=>'required',
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            $response['return_data'] = [];

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }
    
        $json_data = $this->request->getJSON();
        $imageData = trim($json_data->image_data);
        $filteredImage = preg_replace("/data:image\/jpeg;base64,/", "", $imageData);

        $data = array(
            'uid'=>$uid,
            'profile_img'=>$filteredImage
        );

        $rowId = $this->userlibrary->insertUserDataInProfileChangeHistory($uid);
        if($rowId)
        {
            $this->usermodel->updateUserProfileImage($data);
            $response['message'] = "Profile photo updated successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "Profile photo Not updated : Reason (error in user profile history)";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// I think this function is not in use : 
public function get_user_profile_img()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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
            $decryptedUserData = $this->userlibrary->decryptRowForSpecificColumns($result,['first_name']);
            $response['message']= "User profile pic";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = array("first_name"=>$decryptedUserData->first_name,"profile_img"=>$decryptedUserData->profile_img);
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}


// Done encryption
public function create_user()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
         // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $rules = [
            'first_name'=>'required',
            'last_name'=>'required',
            'email'=>'required|valid_email',
            'address_1'=>'required',
            'address_2'=>'required',
            'company'=>'required',
            'state'=>'required',
            'city'=>'required',
            'user_type'=>'required',
            'lender_status'=>'required',
            'phone'=>'required'
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            $response['return_data'] = $inputData;

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }
    
        $json_data = $this->request->getJSON();

        $data = array(
            'uid'=>$this->generateUserId(),
            'ip_address'=>$this->request->getIPAddress(),
            'first_name'=>trim($json_data->first_name),
            'last_name'=>trim($json_data->last_name),
            'username'=>trim($json_data->first_name).' '.trim($json_data->last_name),
            'email'=>trim($json_data->email),
            'password'=>password_hash("12345",PASSWORD_DEFAULT),
            'company'=>trim($json_data->company),
            'created_on'=>time(),
            'created_by'=>$uid,
            'active'=>1,
            'address_1'=>trim($json_data->address_1),
            'address_2'=>trim($json_data->address_2),
            'state'=>trim($json_data->state),
            'city'=>trim($json_data->city),
            'user_type'=>trim($json_data->user_type),
            'lender_status'=>trim($json_data->lender_status),
            'phone'=>trim($json_data->phone)
        );
       
        $userResponse = $this->userlibrary->createUser($data);
        if($userResponse['response'])
        {
            $response['message'] = "User created successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = $userResponse['message'];
            $response['code'] = $userResponse['code'];
            $response['response'] = $userResponse['response'];
            $response['result_data'] = $userResponse['result_data'];
            unset($userResponse['return_data']['password']);
            $response['return_data'] = $userResponse['return_data'];
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// Done encryption
public function update_user()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
         // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $rules = [
            'username'=>'required',
            'phone'=>'required',
            // 'address_1'=>'required',
            // 'address_2'=>'required',
            // 'zip'=>'required',
            // 'city'=>'required',
            // 'state'=>'required',
            'company'=>'required',
            'profile_img'=>'required'
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            $response['return_data'] = $inputData;

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }
    
        $json_data = $this->request->getJSON();

        $data = array(
            'username'=>trim($json_data->username),
            'phone'=>trim($json_data->phone),
            // 'address_1'=>trim($json_data->address_1),
            // 'address_2'=>trim($json_data->address_2),
            // 'zip'=>trim($json_data->zip),
            // 'city'=>trim($json_data->city),
            // 'state'=>trim($json_data->state),
            'company'=>trim($json_data->company),
            'profile_img'=>trim($json_data->profile_img),
            'updated_by'=>$uid
        );

        $userResponse = $this->userlibrary->updateUser($data,$uid);

        if($userResponse['response'])
        {
            $response['message'] = "User data updated successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "User data not updated";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// Done encryption
public function create_auth_templete()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
         // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $rules = [
            'template_name'=>'required',
            'remarks'=>'required',
            'permissions'=>'required',
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            $response['return_data'] = $inputData;

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }
    
        $json_data = $this->request->getJSON();

        $data = array(
            'login_user_id'=>$uid,
            'template_name'=>$json_data->template_name,
            'remarks'=>$json_data->remarks,
            'permissions'=>$json_data->permissions
        );
        
        $userResponse = $this->userlibrary->createAuthTemplete($data);
        if($userResponse['response'])
        {
            $response['message'] = "User template created successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = $userResponse['message'];
            $response['code'] = $userResponse['code'];
            $response['response'] = $userResponse['response'];
            $response['result_data'] = $userResponse['result_data'];
            $response['return_data'] = $userResponse['return_data'];
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// I think function not in use : 
public function get_all_users_auth_templates()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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
            
            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }

            $result = $this->userlibrary->getUsersAuthTemplates();

            $response['message']= "Users templates";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $result;
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}

// Done encryption
public function get_main_menu_auth()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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
            
            $result = $this->userlibrary->getMainManuDataAuth($uid);

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            $response['message']= "Main manu auth";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $this->userlibrary->decryptResultArray($result,['name','description','icon_name','link']);
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}

// Done encryption
public function get_users_list()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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
            
            $result = $this->userlibrary->getUsersList();

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            $response['message']= "get all users";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $result;
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}


// Done encryption
public function get_templates_list()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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
            
            $result = $this->userlibrary->getallTemplatesList();

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            $response['message']= "get all templates list";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $result;
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}

// Done encryption
public function get_template()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
         // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $rules = [
            'template_code'=>'required',
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            $response['return_data'] = $inputData;

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }
    
        $json_data = $this->request->getJSON();

        $data = array(
            'template_code'=>trim($json_data->template_code)
        );
        
        $userResponse = $this->userlibrary->getSingleTemplate($data);
        if($userResponse)
        {
            $response['message'] = "Template data";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = $this->userlibrary->decryptResultArray($userResponse,['name','remarks']);
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "No template data";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// No encryption involve : 
public function save_user_menu_authentication()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
         // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $rules = [
            'user_id'=>'required',
            'permissions'=>'required'
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            $response['return_data'] = $inputData;

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }
    
        $json_data = $this->request->getJSON();

        $data = array(
            'login_user_id'=>$uid,
            'user_id'=>$json_data->user_id,
            'permissions'=>$json_data->permissions
        );
        
        $userResponse = $this->userlibrary->saveUserMenuAuthentication($data);
        if($userResponse['response'])
        {
            $response['message'] = "Auth permission assigned successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = $userResponse['message'];
            $response['code'] = $userResponse['code'];
            $response['response'] = $userResponse['response'];
            $response['result_data'] = $userResponse['result_data'];
            $response['return_data'] = $userResponse['return_data'];
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}

// No encryption involve : 
public function get_active_users()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            
            $count = $this->usermodel->getActiveUsersCount();

            $response['message']= "get active users";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = ["name"=>"Active Users","count"=>$count];
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}


// Pending : Not correct data in the table
public function get_all_visual_metrics()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            
            $resultData = $this->userlibrary->getVisualMetric();

            $response['message']= "All visual metric data";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $resultData;
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}


// No encryption involve : 
public function update_user_analyticals()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
        //  $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $json_data = $this->request->getJSON();
        if(empty($json_data) || !is_array($json_data))
        {
            $response['message'] = "Invalid input";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }

        $data = array(
            'login_user_id'=>$uid,
        );
        
        $userResponse = $this->userlibrary->updateUserAnalytics($json_data,$data);
        if($userResponse['response'])
        {
            $response['message'] = "User analytics updated successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = $userResponse['message'];
            $response['code'] = $userResponse['code'];
            $response['response'] = $userResponse['response'];
            $response['result_data'] = $userResponse['result_data'];
            $response['return_data'] = $userResponse['return_data'];
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// Pending : Still do not have fair idea
public function get_user_analytical_view()
{
    if ($this->request->getMethod() === 'post') 
    {

        $byPass = false;
        $tester_token = '';
        //  $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
        $logoutUrl = $_ENV['app_baseURL'].'logout';
     
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
        $finalResponse = '';

        $token = $tester_token!=''?$tester_token:$this->request->getHeader('token');
        if($token=='')
        {
            $response['message']= "No user token";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($response);
        }

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

        if($uid=='')
        {
            if($byPass)
            {
                $response['message']= "Tester user not registered in our database";
                $response['response']=false;
                $errorCode = 401;
                return $this->response->setJSON($response)->setStatusCode($errorCode);
            }
            else
            {
                $response['message']= "Invalid user token";
                $response['response']=false;
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
                $finalResponse = $this->userlibrary->generateResponse($response);
                return $this->response->setJSON($finalResponse);
            } 
        }
        
        $checkTimeoutStatus = true;
        if(!$byPass)
        {
            $checkTimeoutStatus = $this->userlibrary->checkTimeOut($userId=null,$token->getValue());
        }
        
        if(!$checkTimeoutStatus)
        {
            return redirect()->to($logoutUrl);
        }

        $rules = [
            'user_id'=>'required',
            'menu_code'=>'required'
        ];
    
        if(!$this->validate($rules))
        {
            $response['message'] = $this->validator->getErrors();
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $inputData = $this->request->getJSON();
            $response['return_data'] = $inputData;

            $finalResponse = $this->userlibrary->generateResponse($response);
            return $this->response->setJSON($finalResponse);
        }
    
        $json_data = $this->request->getJSON();

        $data = array(
            'user_id'=>$json_data->user_id,
            'menu_code'=>$json_data->menu_code
        );
        
        $userResponse = $this->userlibrary->getUserAnalyticalView($data);
        
            $response['message'] = "User analytical report";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = $userResponse;
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
     
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// Done encryption
public function get_main_menu_list()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            
            $resultData = $this->userlibrary->getMainMenuList();
            $response['message']= "Get main menu list";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $this->userlibrary->decryptResultArray($resultData,['name']);
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}


public function get_himalaya_master_data_count()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            
            $count = $this->usermodel->getHimalayaMasterDataCount();

            $response['message']= "get himalaya data";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] =  ["name"=>"Himalaya","count"=>$count];
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}

// Done encryption
public function get_user_dashboard()
{
    $byPass = false;
    $tester_token = '';
    $finalResponse = '';
    // $logoutUrl = $_ENV['app_baseURL'].'public'.DIRECTORY_SEPARATOR.'logout';
    $logoutUrl = $_ENV['app_baseURL'].'logout';
 
      if($this->request->getHeader('testerEmail')!=''){
            $response = $this->testerToken();
            if(!$this->testerToken()['response'])
            {
                return $this->response->setJSON($this->testerToken());
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

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            
            $resultData = $this->userlibrary->getUsersDashboard($uid);
            $response['message']= "Get user dashboard data";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $resultData;
            $response['return_data'] = [];
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
                $response['code']= 401;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    else
    {
        $response['message']= "No user token found";
		$response['response'] = false;
        $response['code']= 401;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);

}


// Currently working on this : 
public function get_user_types_list()
{
    $result = $this->usermodel->getUserTypesList();
   
    $response['message'] = "User type list";
    $response['code'] = 200;
    $response['response'] = true;
    $response['result_data'] = $result;
    $response['return_data'] = [];
    $finalResponse = $this->userlibrary->generateResponse($response);
    return $this->response->setJSON($finalResponse);
}



################################ TESTING METHODS #######################

public function encrypt_menu_main_modules_table()
{
     $result = $this->usermodel->getAllMenuMainModulesTableData();
    $encryptedResult = $this->userlibrary->encryptResult($result,['name','description','icon_name','link']);
    $this->usermodel->updateMenuMainModulesTableBatch($encryptedResult);
    die;
}


public function decrypt_menu_main_modules_table()
{
     $result = $this->usermodel->getAllMenuMainModulesTableData();
    $decryptedResult = $this->userlibrary->decryptResult($result,['name','description','icon_name','link']);
    $this->usermodel->updateMenuMainModulesTableBatch($decryptedResult);
    die;
}

public function encrypt_menu_sub_modules_table()
{
     $result = $this->usermodel->getAllMenuSubModulesTableData();
    $encryptedResult = $this->userlibrary->encryptResult($result,['name','description','icon_name']);
    $this->usermodel->updateMenuSubModulesTableBatch($encryptedResult);
    die;
}

public function decrypt_menu_sub_modules_table()
{
     $result = $this->usermodel->getAllMenuSubModulesTableData();
    $decryptedResult = $this->userlibrary->decryptResult($result,['name','description','icon_name']);
    $this->usermodel->updateMenuSubModulesTableBatch($decryptedResult);
    die;
}


// Working code 
public function decodeAuthLevel_xxxxx($data)
{
    $finalArray = [];
    foreach($data as $key => $value)
    {
        $arr=[];
        if($value->level == 0){
            $arr['view'] = false;
            $arr['add'] = false;
            $arr['update'] = false;
            $arr['delete'] = false;
        }
        else if($value->level == 1){
            $arr['view'] = true;
            $arr['add'] = false;
            $arr['update'] = false;
            $arr['delete'] = false;
        }
        else if($value->level == 4){
            $arr['view'] = true;
            $arr['add'] = true;
            $arr['update'] = false;
            $arr['delete'] = false;
        }
        else if($value->level == 5){
            $arr['view'] = true;
            $arr['add'] = true;
            $arr['update'] = true;
            $arr['delete'] = false;
        }
        else if($value->level == 9){
            $arr['view'] = true;
            $arr['add'] = true;
            $arr['update'] = true;
            $arr['delete'] = true;
        }

        $value = (array)$value;
        $value['permissions'] = $arr;
        $value = (object)$value;
        array_push($finalArray,$value);
    }

    echo json_encode($finalArray);
    die;

}

public function get_users_auth_template_list_test()
{
    // echo "get_users_auth_template_list_test";die;
    $result = $this->usermodel->get_users_auth_template_lists();
    $this->decodeAuthLevel($result);
    die;
}

public function get_main_menu_for_test()
{
       $testerTokenEmailHeader = $this->request->getHeader('testerEmail'); 
       $testerTokenAuthorizationHeader = $this->request->getHeader('Authorization'); 
    //    print_r($testerTokenHeader);die;
       $result = $this->userlibrary->verify_testertoken_sessiontoken_checktimeout($testerTokenEmailHeader,$testerTokenAuthorizationHeader);

        if(isset($result['label']) == "testerToken")
        {
                if($result['response']){
                      echo $result['data']['token'];
                }
                else{
                    print_r($result['data']['errors']);
                }

        }
        else
        {
            //   print_r($result['data']['errors']);
            echo "normal user";
        }

        die;
}

public function testcode()
{
    echo $this->dataHandler->retrieveAndDecrypt('blE6TiTGYJ241aPpWaMLzsAhw9u0fcUOi3i0gJxX0CU=');
    die;
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

public function test_get_users()
{
    $token = $this->request->getHeader('token')->getValue();

    if($this->userlibrary->verifyTokenIsValid($token))
    {
         echo "You are alive";
    }
    else
    {
         echo "You are logged out";
    }
   die;
}

public function checkQueryBuilder()
{
    $this->userlibrary->checkQueryBuilder();
}

public function getAllUsersForTest()
{
    $result = $this->userlibrary->getAllUsersForTest();
    return $this->response->setJSON($result);
}


public function getUploadView()
{
     return view('upload');
}

// Working code : 
public function uploadImg2()
{
    $imageFile = $this->request->getFile('file');
    $decodedImageData = '';
    if($imageFile->isValid() && !$imageFile->hasMoved())
    {
        $imageData = base64_encode(file_get_contents($imageFile->getTempName()));
        $decodedImageData = base64_decode($imageData);
    }

    return view('upload',['data' =>$decodedImageData]);
}

// Image upload for JSON data from front end
public function uploadImg()
{
    $imageFile = $this->request->getFile('file');
    $decodedImageData = '';

    if($imageFile->isValid() && !$imageFile->hasMoved())
    {
         $imageData = "data:image/jpeg;base64,/9j/4QCGRXhpZgAATU0AKgAAAAgABQEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAIAAAITAAMAAAABAAEAAIKYAAIAAAAjAAAAWgAAAAAAAABIAAAAAQAAAEgAAAABKGMpIEJsdWVyaW5nbWVkaWEgfCBEcmVhbXN0aW1lLmNvbQAA/+0ASlBob3Rvc2hvcCAzLjAAOEJJTQQEAAAAAAAuHAJ0ACIoYykgQmx1ZXJpbmdtZWRpYSB8IERyZWFtc3RpbWUuY29tHAIAAAIABP/hDHVodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvADw/eHBhY2tldCBiZWdpbj0n77u/JyBpZD0nVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkJz8+Cjx4OnhtcG1ldGEgeG1sbnM6eD0nYWRvYmU6bnM6bWV0YS8nIHg6eG1wdGs9J0ltYWdlOjpFeGlmVG9vbCAxMC44MCc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpwbHVzPSdodHRwOi8vbnMudXNlcGx1cy5vcmcvbGRmL3htcC8xLjAvJz4KICA8cGx1czpMaWNlbnNvcj4KICAgPHJkZjpTZXE+CiAgICA8cmRmOmxpIHJkZjpwYXJzZVR5cGU9J1Jlc291cmNlJz4KICAgICA8cGx1czpMaWNlbnNvclVSTD5odHRwczovL3d3dy5kcmVhbXN0aW1lLmNvbTwvcGx1czpMaWNlbnNvclVSTD4KICAgIDwvcmRmOmxpPgogICA8L3JkZjpTZXE+CiAgPC9wbHVzOkxpY2Vuc29yPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczp4bXBSaWdodHM9J2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9yaWdodHMvJz4KICA8eG1wUmlnaHRzOldlYlN0YXRlbWVudD5odHRwczovL3d3dy5kcmVhbXN0aW1lLmNvbS9hYm91dC1zdG9jay1pbWFnZS1saWNlbnNlczwveG1wUmlnaHRzOldlYlN0YXRlbWVudD4KIDwvcmRmOkRlc2NyaXB0aW9uPgo8L3JkZjpSREY+CjwveDp4bXBtZXRhPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAo8P3hwYWNrZXQgZW5kPSd3Jz8+/9sAQwAIBgYHBgUIBwcHCQkICgwUDQwLCwwZEhMPFB0aHx4dGhwcICQuJyAiLCMcHCg3KSwwMTQ0NB8nOT04MjwuMzQy/9sAQwEJCQkMCwwYDQ0YMiEcITIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy/8IAEQgDhAMBAwEiAAIRAQMRAf/EABsAAQACAwEBAAAAAAAAAAAAAAADBAECBQYH/8QAGgEBAAMB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AAAAEPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPrTakaZA39vvNfPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPOL4SnIcAkEyl3uYF0FNCefdPPPPPPPPPPPPPPPPPPPPPPPPPOAe9VbacAhkyX//AP8AtNeIAFwN3z888888888888888888888/+KL8ZJIFaaDFAz3/AP8A/IGAAAAXGxDzzzzzzzzzzzzzzzzzzy50Cf8AToi+6NeneWM8/wD7TXiTmFWSObt/PPPPPPPPPPPPPPPPPOo0tvobPnf/AO17nPf/AP8A8P8AfTDC0tRpjxzzzzzzzzzzzzzzzzz7qOlTnTnjP/8A9258Jm1CABAMMIBAAQt3f888888888888888ta6nseAXdgcQcoJLLRqSAyvjP82sspJVhw8888888888888887DBlLAL9oiecxtAom1qWOlqS24RQ288IfP88888888888888/KgG68c1R/pn6In1Nu8I3vlhlBAQVE28s9B888888888888886GoboU/B8ge0O+sNeRi1bJ1VJ+1cFA+uz8a88888888888888LC/kp46y2Qp14aY2v38QfOkrK6yNdyn+1hy8888888888888s2q+d6viRvaVpNXzEw7xqQ3WTMgJfkAswl8M8888888888888tvkRupVqAjg0ovf/AE6TVXSvxr77D8PiBrFPf/PPPPPPPPPPPPGDOh4qIw1ZEbYJoN+lrLHfvvjy6Xv3vn/jYPPPPPP9d/PPPPOX5FD6wc4wFBZAqQQMX2PvvvugtYMvvvr3NzFPPPPNbIPPPPOy/Kxb1QSyWbXnkdR5dZv/AL77755HarP777ukr7zzz4oYu3/zzzyxWa5C70dya8yz6ktD/wC+++++ClUIjd++/O9W888shct+d8888gEp6DUNR8WDM+/+Xyue+++++uoV/wC2s/viP3vPP3E/fe9vPPPC2CfzKrd/7zfvjPRxpDdvvvvudjDkUsHfvF/PPKgtPvcN/PPPCXzvOzXufmdfvgXoNOCn/vvvvuRELq0nvvXfPPOhFdphPPPPPABFPPXJrLnvvvl+TCIgn/vvqkvjyCaPvvuVvPPP1ayQ1PPPPPDE3f3PPOB1PvvuX/QXaB/vvvr8vfvjPvvu/fPPPhP7cdfPPPPPGt59vI551Pvvr2wkngnvvvvv4tPvvvvvldfPPLcXq4G9fPPPPLz01fGDFLfvvvBgh9SPvvuNIPvusfvvqCvPPO/QPdD3KfPPPPPPP9PGM71tvsQQQWhPvvvvnH5NGtfvqy/vPPKVeEWmE5lvPPPPPPP9/wC37Vf60lEUb7rrrrqA1RMPr7/17zzzyuT5V/8AzOW88888888oWeMb72u1ThDhpMv9rDEQKIj7ue88888oe+G9/wAnPPPPPPPPPPANvPKHNzddLZcd83n98Y6QPV2pPPPPPOHPiux/PPPPPPPPPPPPCNFvOOEf/vvvvvrm1suX+j3PPPPPNuaaW+tfPPPPPPPPPPPPPPLG12a6LDMP9NPNO8JklHfPPPPPIsXvqv3fPPPPPPPPPPPPPPPPPLfDDfPP8d9fcZlf3/PPPPPPKo72l6ufPPPPPPPPPPPPPPPPPPPPPPPPPPPfPvfZogFdkdNPPFpHJfhaPPPPPPPPPPPPPPPPPPPPPPPPPOx6c/8A75lf4nr6+8x/obyf54Xzzzzzzzzzzzzzzzzzzzzzzzz/AC/+8PI48++7H9++29CUw+q+1888888888888888888888888+YDR8++++++v6Yvvo+buufuo9888888888888888888888888Kuut22++++++eG97F++/Pp9+8888888888888888888888888o+++ai9++++++aGf2++1ac318888888888888888888888888j3+++fq1+++++p3ee+6N7l188888888888888888888888888ZV++++/29++++iAs++GG88888888888888888888888888888tJ/wDvuvcevvvvBh/vvvfvPPPPPPPPPPPPPPPPPPPPPPPPPPPPPg3/AORjChxX+dPT6mHqzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzwABALmX4k8G97kXg/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzyBJrt7n4u777JnGdXzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz2EWRe257rI3gU/6fzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzy8sFFDD6w37hZ377rbzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz4ioEP3fHMN/7765bzzzzzzzzzzzzzzzzzzzzzzzzzzz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";
        
         $newString = preg_replace("/data:image\/jpeg;base64,/", "", $imageData);

         $decodedImageData = base64_decode($newString);
    }

    return view('upload',['data' =>$decodedImageData]);
}




}
