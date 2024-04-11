<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\ResponseInterface;
use App\Models\UserModel;
use App\Libraries\UserLibrary;
use App\Libraries\SecureDataHandler;
use Config\Tester;
use App\Libraries\Lib_log;

class ApiController extends BaseController
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
    public function testApiController()
    {
        echo "calling index from ApiController";die;
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



// Done encrption
public function create_api()
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
            'apiSource'=>'required',
            'requestType'=>'required',
            'apiUrl'=>'required',
            'endpoint'=>'required',
            'description'=>'required',
            'request'=>'required',
            'response_success'=>'required',
            'response_error'=>'required',
            'header_request'=>'required'
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
            'code'=>$this->userlibrary->generateStringCode(),
            'is_internal'=>trim($json_data->internal)!=''?trim($json_data->internal):false,
            'source_code'=>trim($json_data->apiSource),
            'request_type_code'=>trim($json_data->requestType),
            'api_url'=>trim($json_data->apiUrl),
            'api_endpoint'=>trim($json_data->endpoint),
            'description'=>trim($json_data->description),
            'request'=>json_encode($json_data->request),
            'response_success'=>json_encode($json_data->response_success),
            'response_error'=>json_encode($json_data->response_error),
            'header_request'=>json_encode($json_data->header_request),
            'created_by'=>$uid,
            'updated_by'=>$uid
        );
        
        $rowId = $this->userlibrary->insertApiUrlEndPoints($data);

        if($rowId)
        {
            $response['message'] = "Api created successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "Api not created";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// Done encrption
public function get_all_apis()
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
                $result = $this->userlibrary->getFilteredApis($search,$number_of_records,$pagination_number);
            }
            else{
                $result = $this->userlibrary->getStandardRecordsFromApiUrlEndpoints($number_of_records,$pagination_number);
            }
              if(!$checkTimeoutStatus)
              {
                return redirect()->to($logoutUrl);
              }
              $response['message']= "get apis";
              $response['result_data']= $this->userlibrary->decryptResult($result,['api_url','api_endpoint','description','request','response_success','header_request','response_error']);
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


// Done encrption
public function update_api()
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
            'code'=>'required',
            'apiSource'=>'required',
            'requestType'=>'required',
            'apiUrl'=>'required',
            'endpoint'=>'required',
            'description'=>'required',
            'request'=>'required',
            'response_success'=>'required',
            'response_error'=>'required',
            'header_request'=>'required'
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

        $code = trim($json_data->code);
        $data = array(
            'is_internal'=>trim($json_data->internal)!=''?trim($json_data->internal):false,
            'source_code'=>trim($json_data->apiSource),
            'request_type_code'=>trim($json_data->requestType),
            'api_url'=>trim($json_data->apiUrl),
            'api_endpoint'=>trim($json_data->endpoint),
            'description'=>trim($json_data->description),
            'request'=>json_encode($json_data->request),
            'response_success'=>json_encode($json_data->response_success),
            'response_error'=>json_encode($json_data->response_error),
            'header_request'=>json_encode($json_data->header_request),
            'created_by'=>$uid,
            'updated_by'=>$uid
        );
        
        $result = $this->userlibrary->updateApiUrlEndPoints($code,$data);

        if($result)
        {
            $response['message'] = "Api updated successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "Api not created";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// Done encrption
public function get_address_book_list()
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
            
            $result = $this->userlibrary->getAddressBookList();

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            $response['message']= "get all address book list";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $this->userlibrary->decryptResult($result,['name']);
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

// Done encrption
public function get_api_request_type_list()
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
            
            $result = $this->userlibrary->getApiRequestTypeList();

            if(!$checkTimeoutStatus)
            {
                return redirect()->to($logoutUrl);
            }
            $response['message']= "get all api request type list";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $this->userlibrary->decryptResult($result,['api_request_type']);
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

// Done encrption
public function get_api_by_id()
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
            'code'=>'required',
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
            'code'=>trim($json_data->code)
        );
        
        $userResponse = $this->userlibrary->getApiById($data['code']);
        if($userResponse)
        {
            $response['message'] = "Api data";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = $this->userlibrary->decryptRow($userResponse,['api_url','api_endpoint','description','request','response_success','header_request','response_error']);
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "No Api data";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}


// No encryption involves 
public function delete_api()
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
            'code'=>'required',
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
            'code'=>trim($json_data->code)
        );
        
        $userResponse = $this->userlibrary->deleteApi($data['code']);
        if($userResponse)
        {
            $response['message'] = "Api deleted Successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = $userResponse;
            $response['return_data'] = [];
            $this->userlibrary->storeLogs(debug_backtrace(),$uid,$token,$data,$response);
        }
        else
        {
            $response['message'] = "Something went wrong";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
        }
        
        $finalResponse = $this->userlibrary->generateResponse($response);
        return $this->response->setJSON($finalResponse);
    }

}

// No encryption involes
public function total_api_count()
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
            
            $count = $this->usermodel->getTotalApiCount();

            $response['message']= "Total api count";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $count;
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


// No encryption involes
public function total_depreciated_api_count()
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
            
            $count = $this->usermodel->getDepreciatedApiCount();

            $response['message']= "Total depreciated api";
            $response['code']= 200;
            $response['response']=true;
            $response['result_data'] = $count;
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







}
