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
           'phone'=>$phone_encrypt
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
           'phone'=>$phone_encrypt
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
            'phone'=>'required'
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
                    $response['code'] = 200;
                    $response['result_data'] = [];
                    $response['return_data'] = []; 
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

public function login()
{
    if ($this->request->getMethod() === 'post') 
    {
        $response = [];
        $errorCode = '';
        $finalResponse = '';

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
                $response['code'] = 401;
                $response['result_data'] = [];
                $response['return_data'] = [
                    "email" => $json_data->email
                ];
                $finalResponse = $this->userlibrary->generateResponse($response);
                $loginAttemptStatus = $this->userlibrary->checkLoginAttemptsExceed($email);
                if($loginAttemptStatus)
                {
                    return redirect()->to('blockUserMessage')->with('email', $email);
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
                            return redirect()->to('blockUserMessage')->with('email', $email);
                        }

                        date_default_timezone_set('Asia/Kolkata');
                        $currentDate = date("Y:m:d H:i:s");
                        $this->usermodel->updateLastLoginInUsers($userId);
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
                    return redirect()->to('blockUserMessage')->with('email', $email);
                }
                    $user_details = $this->usermodel->getUserDetails($userId);
                    $this->usermodel->updateLastLoginInUsers($userId);
					$response['message']= "Welcome - : ".$this->dataHandler->retrieveAndDecrypt($user_details->email);
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
            return redirect()->to('blockUserMessage')->with('email', $email);
        }
        $this->usermodel->clearInvalidLoginAttempts($email);
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }
   
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
            $decryptedUserData = $this->decryptDataRow($result);
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
// public function get_all_users()
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
            'email'=>'required|valid_email',
            'first_name'=>'required',
            'last_name'=>'required',
            'company'=>'required',
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
            'uid'=>$uid,
            'username'=>trim($json_data->first_name).trim($json_data->last_name),
            'email'=>trim($json_data->email),
            'first_name'=>trim($json_data->first_name),
            'last_name'=>trim($json_data->last_name),
            'company'=>trim($json_data->company),
            'phone'=>trim($json_data->phone)
        );

        $encryptedData = $this->encryptUserDataForUpdate($data);

        $rowId = $this->userlibrary->insertUserDataInProfileChangeHistory($uid);
        if($rowId)
        {
            $this->usermodel->updateUserData($encryptedData);
            $response['message'] = "Profile updated successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "Profile Not updated : Reason (error in user profile history)";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

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


public function get_all_users()
{
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
              if(!$checkTimeoutStatus)
              {
                return redirect()->to($logoutUrl);
              }
              $decryptedUserData = $this->decryptDataResult($result);
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



################################ TESTING METHODS #######################


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




}
