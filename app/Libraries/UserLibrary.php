<?php
namespace App\Libraries;
use App\Libraries\SecureDataHandler;
use App\Models\UserModel;
use Config\Tester;
// use App\Libraries\Lib_log;

class UserLibrary{

      public $db;
      public $dataHandler;
	  public $usermodel;
      public $tester;
      public $environment;
      public $enableEncryptDecryptInDevEnv;

public function __construct()
{
    // $testlib = new Lib_log();
	$this->usermodel = new UserModel();
	$this->db = \Config\Database::connect();
	$secret_key = $_ENV['ENCRYPTION_KEY'];
	$salt = $_ENV['SALT'];
	$this->dataHandler = new SecureDataHandler($secret_key, $salt);
    $this->tester = new Tester();
    $this->environment = $_ENV['CI_ENVIRONMENT'];
    $this->enableEncryptDecryptInDevEnv = $_ENV['ENABLE_ECRYPT_DECRYPT_INDEV_ENV'];
}


// ####################### ENCRYPTION AND DECRYPTION FUNCTIONS ###################

// Not dynamic : Not in use
// Used No where
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

// Not dynamic : Not in use
// Used No where
public function decryptDataResult($data)
{
      $finalArray = [];
       foreach($data as $key => $value){
        $arr['id'] = $value->id;
        $arr['uid'] = $value->uid;
		$arr['email'] = $this->dataHandler->retrieveAndDecrypt($value->email);
        $arr['username'] = $this->dataHandler->retrieveAndDecrypt($value->username);
        $arr['first_name'] = $this->dataHandler->retrieveAndDecrypt($value->first_name);
        $arr['last_name'] = $this->dataHandler->retrieveAndDecrypt($value->last_name);
		$arr['company'] = $this->dataHandler->retrieveAndDecrypt($value->company);
        $arr['phone'] = $this->dataHandler->retrieveAndDecrypt($value->phone);
        array_push($finalArray,$arr);
       }

      return $finalArray;
}

// Not in use : 
// Used No where
// public function encryptRowForSpecificColumns($data,$columns)
// {
//         foreach($data as $key => $value)
//         {
//                 if(in_array($key,$columns))
//                 {  
//                     $data->$key  = $this->dataHandler->encryptAndStore($value);
//                 }
//         }
//    return $data;
// }

// Not in use : 
// Used No where
// public function encryptRowForSpecificColumns($data,$columns)
// {
//     $environment = $_ENV['CI_ENVIRONMENT'];

//     if($environment == 'development')
//     {
//         return $data;
//     }
//      if(is_array($data))
//      {
//         foreach($data as $key => $value)
//         {
//                 if(in_array($key,$columns))
//                 {  
//                     $data[$key]  = $this->dataHandler->encryptAndStore($value);
//                 }
//         }
//      }
//      else
//      {
//         foreach($data as $key => $value)
//         {
//                 if(in_array($key,$columns))
//                 {  
//                     $data->$key  = $this->dataHandler->encryptAndStore($value);
//                 }
//         }
//      }
      
//    return $data;
// }

// Not in use : 
// Used No where
public function decryptRowForSpecificColumns($data,$columns)
{
        foreach($data as $key => $value)
        {
                if(in_array($key,$columns))
                {  
                    $data->$key  = $this->dataHandler->retrieveAndDecrypt($value);
                }
        }
   return $data;
}

// Not in use : 
// Used No where
public function decryptResultForSpecificColumns($data,$columnsArray)
{
     foreach($data as $key => $userObj){
        foreach($userObj as $field => $value2){
            if(in_array($field,$columnsArray)){
                 $userObj->$field = $this->dataHandler->retrieveAndDecrypt($value2);  
            }
        }
     }

    return $data;
}

// Method in use :
public function encryptRow($data,$columns)
{
    if($this->environment == 'development' && $this->enableEncryptDecryptInDevEnv=='false')
    {
        return $data;
    }
    
     if(is_array($data))
     {
        foreach($data as $key => $value)
        {
                if(in_array($key,$columns))
                {  
                    $data[$key]  = $this->dataHandler->encryptAndStore($value);
                }
        }
     }
     else
     {
        foreach($data as $key => $value)
        {
                if(in_array($key,$columns))
                {  
                    $data->$key  = $this->dataHandler->encryptAndStore($value);
                }
        }
     }
    //  print_r($data);die;
   return $data;
}

// Method in use : 
public function encryptResult($data,$columnsArray)
{
    if($this->environment == 'development' && $this->enableEncryptDecryptInDevEnv=='false')
    {
        return $data;
    }

     foreach($data as $key => $userObj){
        foreach($userObj as $field => $value2){
            if(in_array($field,$columnsArray)){
                 $userObj->$field = $this->dataHandler->encryptAndStore($value2);  
            }
        }
     }

    return $data;
}

// Method in use : 
public function encryptValue($value)
{
    if($this->environment=='development' && $this->enableEncryptDecryptInDevEnv=='false'){
        return $value;
    }
    $value = $this->dataHandler->encryptAndStore($value);
    return $value;
}

// Method in use : 
public function decryptValue($value)
{
    if($this->environment=='development' && $this->enableEncryptDecryptInDevEnv=='false'){
        return $value;
    }
    $value = $this->dataHandler->retrieveAndDecrypt($value);
    return $value;
}

// Method in use : 
public function decryptRow($data,$columns)
{
    if($this->environment == 'development' && $this->enableEncryptDecryptInDevEnv=='false')
    {
        return $data;
    }
     if(is_array($data))
     {
        foreach($data as $key => $value)
        {
                if(in_array($key,$columns))
                {  
                    $data[$key]  = $this->dataHandler->retrieveAndDecrypt($value);
                }
        }
     }
     else
     {
        foreach($data as $key => $value)
        {
                if(in_array($key,$columns))
                {  
                    $data->$key  = $this->dataHandler->retrieveAndDecrypt($value);
                }
        }
     }
      
   return $data;
}


// Old method
// public function decryptResult($data,$columnsArray)
// {
//     if($this->environment == 'development')
//     {
//         return $data;
//     }

//      foreach($data as $key => $userObj){
//         foreach($userObj as $field => $value2){
//             if(in_array($field,$columnsArray)){
//                  $userObj->$field = $this->dataHandler->retrieveAndDecrypt($value2);  
//             }
//         }
//      }

//     return $data;
// }

// Method in use : 
public function decryptResult($data,$columnsArray,$flag=true)
{
    if($this->environment == 'development' && $this->enableEncryptDecryptInDevEnv=='false')
    {
        return $data;
    }

    if($flag)
    {
        foreach($data as $key => $userObj){
            foreach($userObj as $field => $value2){
                if(in_array($field,$columnsArray)){
                    if($value2!= "")
                    {
                        $userObj->$field = $this->dataHandler->retrieveAndDecrypt($value2);
                    }
                    else
                    {
                        $userObj->$field = $value2;
                    }  
                }
            }
         }
         return $data;
    }
    else{
        return $data;
    }
     
}


// This function we will use when we have nested array:means array inside array and object inside array
// Method in use :
public function decryptResultArray($data,$columnsArray,$flag=true)
{
    if($this->environment == 'development' && $this->enableEncryptDecryptInDevEnv=='false')
    {
        return $data;
    }

    $finalArray = [];
    if($flag)
    {
        foreach($data as $key => $userObj)
        {
            if(is_array($userObj))
            {
                foreach($userObj as $field => $value2){
                    if(in_array($field,$columnsArray)){
                        $userObj[$field] = $this->dataHandler->retrieveAndDecrypt($value2);  
                    }
                    else
                    {
                        $userObj[$field] = $value2; 
                    }
                } 
                array_push($finalArray,$userObj); 
            }
            else
            {
                foreach($userObj as $field => $value2){
                    if(in_array($field,$columnsArray)){
                        $userObj->$field = $this->dataHandler->retrieveAndDecrypt($value2);  
                    }
                    else
                    {
                        $userObj->$field = $value2; 
                    }
                } 
                array_push($finalArray,$userObj);
            }
                 

        }
    }
    else
    {
        $finalArray = $data;
    }
   
    return $finalArray;

}


// ######################### END OF ENCRYPTION AND DECRYPTION FUNCTIONS ################

public function checkUserAlreadyExists($email)
{
	$q = "SELECT * FROM users WHERE `email` ='{$this->encryptValue($email)}'";
	$query = $this->db->query($q); 
	return $query->getRow();
}

public function userExistsInUsersToken($userId)
{
	$q = "SELECT * FROM users_session_tokens WHERE `uid` = {$userId}";
	$query = $this->db->query($q); 
	return $query->getRow();
}

public function checkActiveStatus($userId)
{
    $query = $this->db->table('users_session_tokens')
                ->select('*')
                ->where('uid', $userId)
				->where('login_active_status',1)
                ->get();

    $row = $query->getRow();
    return $row; 
}


public function checkTimeOut($user_id,$token)
{
	date_default_timezone_set('Asia/Kolkata');
	$currentDate = date("Y:m:d H:i:s");
	$userTimeOutStatus = '';

			$row = $this->usermodel->checkUserTimeout($token);
			$lastHitDate = $row->hit_time;

			$currentDate = strtotime($currentDate);
			$lastHitDate = strtotime($lastHitDate);

			$diff = abs($currentDate - $lastHitDate);
			
			if($diff > 60*5)
			{
				$userTimeOutStatus = 0;	
			}
			else
			{
				$userTimeOutStatus = 1;
				$data = ['hit_time'=>date("Y:m:d H:i:s")];
				 $this->usermodel->resetUsersTimeout($token,$data);
			}
		return $userTimeOutStatus;
}

public function verifyTokenIsValid($token)
{
        $row = $this->db->table('users_session_tokens')
                ->select('*')
                ->where('token', $token)
                ->where('is_expired',0)
                ->get()
                ->getRow();     			  
        return $row;
}

public function checkLoginAttemptsExceed($email)
{
	$status = false;
	$q = "SELECT * FROM login_attempts WHERE `login` = '{$email}'";
	$result = $this->db->query($q)
					->getResult();
    if(count($result) > 2)
	{
		$status = true;
	}
	return $status;
}

public function sendOTPEmail($email,$otp)
{
        $emailService = \Config\Services::email();
        $emailService->setTo($email);
        $emailService->setSubject('Password reset verification');
        $message = "<b>Verification code : {$otp} <br><br> Thanks for using lambda infinity</b>";
        $emailService->setMessage($message);
        
        if ($emailService->send()) 
        {
                return 1;
        } 
        else 
        {
            return 0;
        }
}

public function verifyOTP($otp)
{
	$q = "SELECT * FROM users_otp WHERE otp='{$otp}' AND otp_active_status=1";
	$query = $this->db->query($q);
	return $query->getRow();
}


public function checkTimeOutForOTP($user_id,$otp)
{
	date_default_timezone_set('Asia/Kolkata');
	$currentDate = date("Y:m:d H:i:s");
	$OTPTimeOutStatus = '';

			$row = $this->usermodel->checkOTPTimeout($user_id,$otp);
			$created_at = $row->created_on;

			$currentDate = strtotime($currentDate);
			$created_at = strtotime($created_at);

			$diff = abs($currentDate - $created_at);
			
			if($diff > 60*2)
			{
				$OTPTimeOutStatus = 0;	
			}
			else
			{
				$OTPTimeOutStatus = 1;
			}
		return $OTPTimeOutStatus;
}


public function getTesterToken($length,$numbers,$alphabets,$symbols)
{
		$finalKey = '';
		$bytes = random_bytes($length);

        $numbersKeys = bin2hex($bytes);
		$alphabetsKeys = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		$symbolsKeys = "@#$%^&*_+=?|";

		$numbersFinalKey = $numbers=="true"?$numbersKeys:'';
		$alphabetsFinalKey = $alphabets=="true"?$alphabetsKeys:'';
		$symbolsFinalKey = $symbols=="true"?$symbolsKeys:'';
		
		$finalKey = $numbersFinalKey.$alphabetsFinalKey.$symbolsFinalKey;

		if($numbers=="false" && $alphabets=="false" && $symbols=="false")
		{
			  $finalKey = $numbersKeys.$alphabetsKeys.$symbolsKeys;
		}

		$tester_token = substr(str_shuffle($finalKey),0,$length);
		return $tester_token;
}


public function checkTemperorlyBlockedUserAndActivate($email)
{
	$lastAttemptRecord = $this->usermodel->getLastAttemptRecord($email);	  
	$lastAttemptDate = $lastAttemptRecord->time;

	date_default_timezone_set('Asia/Kolkata');
    $currentDate = date("Y:m:d H:i:s");
 
    $lastEpocDate = strtotime("+1 minutes", $lastAttemptDate);
    $finalDate = date('Y:m:d H:i:s', $lastEpocDate);

	if(strtotime($currentDate) > strtotime($finalDate))
	{
		$this->usermodel->clearInvalidLoginAttempts($email);
		return true;
	}
	else
	{
		return false;
	}

}

// Done with encryption
public function storeLogs($fun,$uid=null,$token=null,$request=null,$response=null)
{
    $logResult = [];
    $logResult['called_class'] = $fun[0]['class'];
    $logResult['called_method'] = $fun[0]['function'];
    
    $currentURL = current_url();
    $logResult['called_api'] = preg_replace('/\/index.php/','', $currentURL);

	$logResult['ip_address'] = $_SERVER['REMOTE_ADDR'];
	$logResult['user_agent'] = $_SERVER['HTTP_USER_AGENT'];

	date_default_timezone_set('Asia/Kolkata');
	$currentDateTime = date("Y:m:d H:i:s");
	$logResult['hit_date_time'] = $currentDateTime;
	// $arr['access_key'] = "67hthyd777==ljdsbsdjf";
	// $arr['screte_key'] = "fvdshchsjcasjdhadjhsadkask";

	$row = '';
    if($uid!=null)
	{
		$row = $this->usermodel->getToken($uid);
	}
	else
	{
		if($this->usermodel->verifyToken($token))
		{
			$row = $this->usermodel->getUidFromUsersTokens($token);
		}
		else
		{
			return; 
		}
	  	
	}
	$arr['token'] = $row==''?$row:$row->token;
	$logResult['uid'] = $uid!=null?$uid:$row->uid;
	$logResult['user_input_data'] = json_encode($request);
    $logResult['user_response_data'] = json_encode($response);

    $requestSize =  $logResult['user_input_data']!=''?strlen($logResult['user_input_data'])."Bytes":(0)." Bytes";
    $responseSize = $logResult['user_response_data']!=''?strlen($logResult['user_response_data'])."Bytes":(0)." Bytes";

    $logResult['request_size'] = $requestSize;
    $logResult['response_size'] = $responseSize;
  
    $logResult = $this->encryptRow($logResult,['called_class','called_method','called_api','user_agent','user_input_data','user_response_data']);
	$this->usermodel->storeUserLogHistory($logResult);
    return $logResult;
}



public function chekApiHitTimings($user_id)
{
    $response = [];
    $errorCode = 200;
    $currentURL = current_url();

    $apiURL = preg_replace('/\/index.php/','', $currentURL);
    $ip_address = $_SERVER['REMOTE_ADDR'];
	$user_agent = $_SERVER['HTTP_USER_AGENT'];
    // $user_id = $this->request->getHeader('userid')->getValue();
    // $user_id = 16;
    
    date_default_timezone_set('Asia/Kolkata');
    $current_hit = date("Y:m:d H:i:s");

    $api_logs = $this->usermodel->getApiLogs($user_id,$apiURL);

    $last_hit = isset($api_logs->current_hit)?$api_logs->current_hit:null;

    $data = array(
        'user_id'=>$user_id,
        'ip_address'=>$ip_address,
        'api_url'=>$apiURL,
        'user_agent'=>$user_agent,
        'last_hit'=>$last_hit,
        'current_hit'=>$current_hit,
        'hit_count'=>0
    );

     // echo "Lasthit : ".$last_hit." / Currenthit : ".$current_hit;
      
    $hit_count = isset($api_logs->hit_count)?$api_logs->hit_count:0;

    if($hit_count < 3)
    {
            if(strtotime($last_hit) == strtotime($current_hit))
            {
                $data['hit_count'] = $hit_count+1;
                $this->usermodel->updateApiLogs($user_id,$apiURL,$data);
            }
            else
            {
                if($this->usermodel->checkUserIdAndApiURL($user_id,$apiURL))
                {
                    $this->usermodel->updateApiLogs($user_id,$apiURL,$data);
                }
                else
                {
                    $this->usermodel->insertApiLogs($data);
                }
            }
            $errorCode = 200;
            $response['response'] = true;
            $response['code'] = 200;
            $response['message'] = "Api hit count is less than 3";
    }
    else
    {
        $userHitData = $this->usermodel->timeCheckerToReleaseUser($user_id,$apiURL);

        date_default_timezone_set('Asia/Kolkata');
        $currentDateTime = date("Y:m:d H:i:s");
        
        $currentHitFromDB = $userHitData->current_hit;
    
        $timeOfReleaseEpoc = strtotime("+1 minutes", strtotime($currentHitFromDB));
        $timeOfRelease =  date('Y:m:d H:i:s', $timeOfReleaseEpoc);

        if(strtotime($currentDateTime) > strtotime($timeOfRelease))
        {
            $data['hit_count'] = 0;
			$this->usermodel->releaseUserApis($user_id,$data);
            $errorCode = 200;
            $response['response'] = true;
            $response['code'] = 200;
            $response['message'] = "User is released";
        }
        else
        {
            $errorCode = 400;
            $response['response'] = false;
            $response['code'] = 400;
            $response['message'] = "User has been blocked for 1 minute due to continues reloading of the page";
        }
    }
    
    $overall_hit_count = isset($this->usermodel->checkAnyApiHasMaxCountForUser($user_id)->hit_count)?$this->usermodel->checkAnyApiHasMaxCountForUser($user_id)->hit_count:0;
    if($overall_hit_count >=3)
    {
        $errorCode = 400;
        $response['response'] = false;
        $response['code'] = 400;
        $response['message'] = "User has been blocked for 1 minute due to continues reloading of the page...";
    }
    
    return $response;

}


public function generateResponse($data)
{
    $response['success'] = true;
    $response['status'] = 200;

    $content = [];
    $content['result'] = $data['response'];
    $content['message'] = $data['message'];
    $content['result_data'] = $data['result_data'];
    $content['return_data'] = $data['return_data'];
    
    $response['content'] = $content;

    return $response;
}


// Working method :  Not in use

// public function getFilteredUsers($searchCriteria, $numberOfRecords, $paginationNumber)
// {
//     $query = $this->db->table('users');
//     $query->where($searchCriteria[0]->column_name, $this->dataHandler->encryptAndStore($searchCriteria[0]->key));
//     foreach ($searchCriteria as $index => $criteria) {
//         if($index!=0)
//         {
//             $key = $criteria->key;
//             $columnName = $criteria->column_name;
//             $type = $criteria->type;
    
    
//             switch ($searchCriteria[$index-1]->type) {
//                 case 'and':
//                     $query->where($columnName, $this->dataHandler->encryptAndStore($key));
//                     break;
//                 case 'or':
//                     $query->orWhere($columnName, $this->dataHandler->encryptAndStore($key));
//                     break;
//                 case 'end':
//                     $query->like($columnName, $this->dataHandler->encryptAndStore($key), 'after');
//                     break;
//                 default:
//                     break;
//             }
//         }
//     }

//         $offset = ($paginationNumber - 1) * $numberOfRecords;
//         $query->limit($numberOfRecords, $offset);

//       $result = $query->get()->getResult();
//     //   $decryptedData = $this->decryptDataResult($result);
   
//     // $sql = $query->getCompiledSelect();
//     return $result;
// }


// With operators : In use 
// Done encryption
public function getFilteredUsers($searchCriteria, $numberOfRecords, $paginationNumber)
{
    $query = $this->db->table('users');
    $query->where($searchCriteria[0]->column_name.$searchCriteria[0]->operator, $this->encryptValue($searchCriteria[0]->key));
    foreach ($searchCriteria as $index => $criteria) {
        if($index!=0)
        {
            $key = $criteria->key;
            $columnName = $criteria->column_name;
            $type = $criteria->type;
            $operator = $criteria->operator;

            if($operator == 'like'){
                $query->like($columnName, $this->encryptValue($key));
            }
    
            if($operator!='like'){
                switch ($searchCriteria[$index-1]->type) {
                    case 'and':
                        $query->where($columnName.$operator, $this->encryptValue($key));
                        break;
                    case 'or':
                        $query->orWhere($columnName.$operator, $this->encryptValue($key));
                        break;
                    case 'end':
                        break;
                    default:
                        break;
                }
            }
            


        }
    }

        $offset = ($paginationNumber - 1) * $numberOfRecords;
        $query->limit($numberOfRecords, $offset);
      $result = $query->get()->getResult();
    return $result;
}

// Done encryption
public function getStandardRecords($numberOfRecords, $paginationNumber)
{
    $query = $this->db->table('users');
    $offset = ($paginationNumber - 1) * $numberOfRecords;
    $query->limit($numberOfRecords, $offset);
    $result = $query->get()->getResult();
    return $result;
}


public function checkQueryBuilder()
{
    // echo "checkQueryBuilder library";die;
    $query = $this->db->table('users');
    $query->where('first_name', 'sarfaraz');
    $query->orWhere('last_name', 'sarfaraz');
    $query->like('phone', '9980952926');
            //    $query->get();
    //   print_r($result);

    $offset = (1 - 1) * 10;
        $query->limit(25, $offset);

      $sql = $query->getCompiledSelect();
      print_r($sql);

      die;
}


public function getAllUsersForTest()
{
    $result = $this->db->table('users')
            ->get()->getResult();
    $decryptedData = $this->decryptDataResult($result);        
    return $decryptedData;
}

// Done encryption with normal and auth9 users
public function getMainManuData($uid)
{
    $usersResult = $this->db->table('users')
                    ->where('uid',$uid)    
                    ->get()
                    ->getRow();
   
    $menuMainModulesResult = '';
    if($usersResult->initial_auth_level == 9)
    {
        // Auth 9 User (Superadmin)
        $menuMainModulesResult = $this->db->table('menu_main_modules')
                                            ->select('menu_main_modules.*,sm.id as sub_id,sm.code as sub_code,sm.menu_main_code as sub_menu_main_code,sm.name as sub_name,sm.description as sub_description,sm.icon_name as sub_icon_name,sm.order_no as sub_order_no,sm.created_on as sub_created_on,sm.updated_on as sub_updated_on,sm.is_deleted as sub_is_deleted')
                                            ->join(' menu_sub_modules as sm', ' menu_main_modules.code = sm.menu_main_code','left')  
                                            ->where('menu_main_modules.is_deleted',0)
                                            ->orderBy('menu_main_modules.order_no')
                                            ->get()
                                            ->getResult();  
                                                                
        $mainMenuCodeArray = [];
        foreach($menuMainModulesResult as $key => $value)
        {
                array_push($mainMenuCodeArray,$value->code);
        }
        
        $mainMenuCodeArrayFiltered = array_unique($mainMenuCodeArray);

        $mainMenuArray = [];
        $tempIdArray = [];
        foreach($mainMenuCodeArrayFiltered as $key => $main_menu_code)
        {
            foreach($menuMainModulesResult as $key2 => $value2)
            {
                    if($main_menu_code == $value2->code){
                         
                        if(!in_array($main_menu_code,$tempIdArray))
                        {
                            $arr['id'] = $value2->id;
                            $arr['code'] = $value2->code;
                            $arr['name'] = $value2->name;
                            $arr['description'] = $value2->description;
                            $arr['icon_name'] = $value2->icon_name;
                            $arr['link'] = $value2->link;
                            $arr['order_no'] = $value2->order_no;
                            $arr['created_by'] = $value2->created_by;
                            $arr['updated_by'] = $value2->updated_by;
                            $arr['created_on'] = $value2->created_on;
                            $arr['updated_on'] = $value2->updated_on;
                            $arr['is_deleted'] = $value2->is_deleted;
                            

                            $subMenuArray = [];
                            foreach($menuMainModulesResult as $key3 => $value3)
                            {
                                    if($main_menu_code == $value3->sub_menu_main_code)
                                    {
                                           $arr2['sub_id'] = $value3->sub_id;
                                           $arr2['sub_code'] = $value3->sub_code;
                                           $arr2['sub_menu_main_code'] = $value3->sub_menu_main_code;
                                           $arr2['sub_name'] = $value3->sub_name;
                                           $arr2['sub_description'] = $value3->sub_description;
                                           $arr2['sub_icon_name'] = $value3->sub_icon_name;
                                           $arr2['sub_order_no'] = $value3->sub_order_no;
                                           $arr2['sub_created_on'] = $value3->sub_created_on;
                                           $arr2['sub_updated_on'] = $value3->sub_updated_on;
                                           $arr2['sub_is_deleted'] = $value3->sub_is_deleted;
                                           array_push($subMenuArray,$arr2);
                                    }
                            }

                            $arr['sub_menu'] = $this->decryptResultArray($subMenuArray,['sub_name','sub_description','sub_icon_name']);
                            array_push($mainMenuArray,$arr);
                            array_push($tempIdArray,$main_menu_code);

                        }
                           
                    }
            }  
        }

        $menuMainModulesResult = $mainMenuArray; 
    }
    else
    {
        // Auth 0 user (Normal User)
        $usersAuthResult = $this->db->table('menu_user_auths') 
                                    ->where('user_id',$uid)  
                                    ->where('level!=',0)
                                    ->get()
                                    ->getResult();   
        $mainMenuCodeArray = array_column($usersAuthResult, 'main_menu_code');
     
        $defaultMenu = $this->db->table('menu_main_modules') 
                                    ->whereIn('link',[$this->encryptValue('main-dashboard.html'),$this->encryptValue('settings.html')])
                                    ->get()
                                    ->getResult(); 
        $defaultMenuArray = array_column($defaultMenu, 'code');
        // print_r($defaultMenuArray);die;

        $finalCodeArray = array_merge($mainMenuCodeArray,$defaultMenuArray);
        $finalCodeArrayUnique = array_unique($finalCodeArray);
        // print_r($finalCodeArrayUnique);die;
        $menuMainModulesResult = $this->db->table('menu_main_modules') 
                                            ->where('menu_main_modules.is_deleted',0)
                                            ->whereIn('code',$finalCodeArrayUnique) 
                                            ->orderBy('menu_main_modules.order_no')
                                            ->get()
                                            ->getResult();                                    
    } 
    // print_r($menuMainModulesResult);die;
    return $menuMainModulesResult;
}



public function insertUserDataInProfileChangeHistory($uid)
{
    $userData = $this->db->table('users')
                            ->where('uid',$uid)    
                            ->get()
                            ->getRow();   
    
    unset($userData->id);
    unset($userData->password);
    unset($userData->initial_auth_level);
    unset($userData->activation_selector);
    unset($userData->activation_code);
    unset($userData->forgotten_password_selector);
    unset($userData->forgotten_password_code);
    unset($userData->forgotten_password_time);
    unset($userData->remember_selector);
    unset($userData->remember_code);
    unset($userData->ip_address);
    unset($userData->last_login);
    unset($userData->active);
    unset($userData->user_type);
    
    $userArray = (array)$userData;
    $userArray['user_id'] = $userArray['uid'];
    $userArray['code'] = $this->generateStringCode();
    unset($userArray['uid']);
    $userObj = (object)$userArray;

    $rowId = $this->usermodel->insertUserDataInProfileChangeHistory($userObj);
    return $rowId;
}


public function checkCreatedUserExistsInUsersTable($email)
{
    $usersResult = $this->db->table('users')
    ->where('email',$this->encryptValue($email))    
    ->get()
    ->getRow();
  
     if($usersResult)
     {
         return 1;
     }
     else
     {
        return 0;
     }

}

public function checkCompanyCityExists($company,$city)
{
        $addressBookRow = $this->db->table('address_book')
        ->where('name',$this->encryptValue($company)) 
        ->where('city',$this->encryptValue($city))    
        ->get()
        ->getRow();
        if($addressBookRow){
            return 1;
        }
        else{
            return 0;
        }
}

public function generateStringCode()
{
    $finalKey = '';
		$bytes = random_bytes(6);

        $numbersKeys = bin2hex($bytes);
		$alphabetsKeys = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		$finalKey = $numbersKeys.$alphabetsKeys;
		$code = substr(str_shuffle($finalKey),0,6);
	return $code;
}

public function setDefaultMenuUserAuthsPermissions($user_id)
{
     $response = [];
     $defaultMainMenuData = $this->usermodel->getDefaultMenuMainModules();

     $finalArray = [];
     foreach($defaultMainMenuData as $key => $value)
     {
          $arr = [];
          $arr['code'] = $this->generateStringCode();
          $arr['user_id'] = $user_id;
          $arr['main_menu_code'] = $value->code;
          $arr['sub_menu_code'] = null;   
          $arr['level'] = 9;  
          $arr['created_by'] = $user_id; 
          $arr['updated_by'] = $user_id; 
          array_push($finalArray,$arr);
     }

      $status = $this->usermodel->insertMenuUserAuths($finalArray);
         
      if($status)
      {
            $response['response'] = true;
      }
      else
      {
            $response['message'] = "Something went wrong with deafault permissions";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = []; 
      }
    return $response;
}

public function setDefaultMenuUserAuthsPermissionsForCreateUser($user_id,$create_by)
{
     $response = [];
     $defaultMainMenuData = $this->usermodel->getDefaultMenuMainModules();

     $finalArray = [];
     foreach($defaultMainMenuData as $key => $value)
     {
          $arr = [];
          $arr['code'] = $this->generateStringCode();
          $arr['user_id'] = $user_id;
          $arr['main_menu_code'] = $value->code;
          $arr['sub_menu_code'] = null;   
          $arr['level'] = 9;  
          $arr['created_by'] = $create_by; 
          $arr['updated_by'] = $create_by; 
          array_push($finalArray,$arr);
     }

      $status = $this->usermodel->insertMenuUserAuths($finalArray);
         
      if($status)
      {
            $response['response'] = true;
      }
      else
      {
            $response['message'] = "Something went wrong with deafault permissions";
            $response['response'] = false;
            $response['code'] = 401;
            $response['result_data'] = [];
            $response['return_data'] = []; 
      }
    return $response;
}

public function createUser($data)
{
    // echo "reached";die;
    $response = [];
    if($this->checkCreatedUserExistsInUsersTable($data['email']))
    {
            $response['message'] = "User already exists in the database";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
            return $response;    
    }
    // echo "reached";die;
    if($this->checkCompanyCityExists($data['company'],$data['city']))
    {
            $response['message'] = "Company and city already exists";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
            return $response; 
    }
    // echo "reached";die;
    $encryptedData = $this->encryptRow((object)$data,['username','email','phone','company','first_name','last_name']);
        $usersTableData = [
            'uid'=>$encryptedData->uid,
            'ip_address'=>$encryptedData->ip_address,
            'first_name'=>$encryptedData->first_name,
            'last_name'=>$encryptedData->last_name,
            'username'=>$encryptedData->username,
            'email'=>$encryptedData->email,
            'phone'=>$encryptedData->phone,
            'password'=>$encryptedData->password,
            'created_on'=>$encryptedData->created_on,
            'created_by'=>$encryptedData->created_by,
            'company'=>$encryptedData->company,
            'active'=>$encryptedData->active
        ];
    
        $addressBookCode = $this->generateStringCode();
        $userAddressMapperCode = $this->generateStringCode();
        $userAddressBookConnectCode = $this->generateStringCode();

            $addressBookData = [
                'code'=>$addressBookCode,
                'type_of_connect'=>$data['user_type'],
                'name'=>$data['company'],
                'address_1'=>$data['address_1'],
                'address_2'=>$data['address_2'],
                'city'=>$data['city'],
                'state'=>$data['state'],
                'created_by'=>$encryptedData->created_by,
                'status'=>$data['lender_status'] 
        ];
        //  echo "reached";die;
        $userAddressMapperData = [
            'code'=>$userAddressMapperCode,
            'user_id'=>$encryptedData->uid,
            'addressbook_code'=>$addressBookCode,
            'created_by'=>$encryptedData->created_by,
            'updated_by'=>$encryptedData->created_by
        ];

        $userAddressBookConnectData = [
            'code'=>$userAddressBookConnectCode,
            'address_code'=>$addressBookCode,
            'email'=>$data['email'],
            'phone'=>$data['phone'],
            'created_by'=>$encryptedData->created_by,
            'updated_by'=>$encryptedData->created_by
        ];

        if($this->usermodel->registerUserData($usersTableData))
        {
            $adressBookRecoredId = $this->usermodel->insertIntoAddressBook($this->encryptRow($addressBookData,['name','address_1','address_2','city','state']));
            $userAddressMapperRecord = $this->usermodel->insertIntoUserAddressMapper($userAddressMapperData);
            $userAddressBookConnectRecordId = $this->usermodel->insertIntoUserAddressBookConnect($this->encryptRow($userAddressBookConnectData,['email','phone']));
            $this->setDefaultMenuUserAuthsPermissionsForCreateUser($encryptedData->uid,$encryptedData->created_by);
            $response['message'] = "User created successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
        }
        else
        {
            $response['message'] = "User creation failed";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = [];
        }
         
    return $response;
}



// Not in use
// public function updateUser($data,$userId)
// {
//         $response = [];
//         $encryptedData = $this->encryptRowForSpecificColumns((object)$data,['username','email','phone','company','first_name','last_name']);
       
//         $usersTableData = [
//             'uid'=>$userId,
//             'username'=>$encryptedData->username,
//             'phone'=>$encryptedData->phone,
//             'updated_by'=>$encryptedData->updated_by,
//             'company'=>$encryptedData->company,
//             // 'profile_img'=> preg_replace("/data:image\/jpeg;base64,/", "", $encryptedData->profile_img)
//             'profile_img'=> $encryptedData->profile_img
//         ];

//         $userData = $this->usermodel->getUserByUid($userId);
//         $code = $this->generateStringCode();
//         $codeForUserAddressMapper = $this->generateStringCode();

//         $addressBookData = [
//             'code'=>$code,
//             'type_of_connect'=>$userData->user_type,
//             'name'=>$data['company'],
//             'address_1'=>$data['address_1'],
//             'address_2'=>$data['address_2'],
//             'city'=>$data['city'],
//             'state'=>$data['state'],
//             'updated_by'=>$encryptedData->updated_by,
//             'status'=>"" 
//       ];

//       $addressBookDataToUpdate = [
//         'name'=>$data['company'],
//         'address_1'=>$data['address_1'],
//         'address_2'=>$data['address_2'],
//         'city'=>$data['city'],
//         'state'=>$data['state'],
//         'updated_by'=>$encryptedData->updated_by
//   ];

//       $userAddressMapperData = [
//         'code'=>$codeForUserAddressMapper,
//         'user_id'=>$userId,
//         'addressbook_code'=>$code,
//         'updated_by'=>$encryptedData->updated_by
//     ];

//         if($this->usermodel->checkUserExistsInUserAddressMapper($userId))
//         {
//             // UPADTE DATA
//             $addressBookCode = $this->usermodel->getAddressBookCode($userId); 
//             $this->insertUserDataInProfileChangeHistory($userId);
//             $this->usermodel->updateUserData($usersTableData);
//             $this->usermodel->updateIntoAddressBook($addressBookDataToUpdate,$addressBookCode); 
//             $response['response'] = true;
//         }
//         else 
//         {
//             // INSERT DATA 
//             if($this->checkCompanyCityExists($data['company'],$data['city']))
//             {
//                     $response['message'] = "Company and city already exists";
//                     $response['code'] = 401;
//                     $response['response'] = false;
//                     $response['result_data'] = [];
//                     $response['return_data'] = $data;
//                     return $response; 
//             }
//             $this->insertUserDataInProfileChangeHistory($userId);
//             $this->usermodel->updateUserData($usersTableData);
//             $adressBookRecoredId = $this->usermodel->insertIntoAddressBook($addressBookData);
//             $userAddressMapperRecord = $this->usermodel->insertIntoUserAddressMapper($userAddressMapperData);
//             $response['response'] = true;
//         }

//      return $response;   

// }


// Done encryption
public function updateUser($data,$userId)
{
        $response = [];
        $encryptedData = $this->encryptRow((object)$data,['username','email','phone','company','first_name','last_name']);
       
        $usersTableData = [
            'uid'=>$userId,
            'username'=>$encryptedData->username,
            'phone'=>$encryptedData->phone,
            'updated_by'=>$encryptedData->updated_by,
            'company'=>$encryptedData->company,
            // 'profile_img'=> preg_replace("/data:image\/jpeg;base64,/", "", $encryptedData->profile_img)
            'profile_img'=> $encryptedData->profile_img
        ];

            $this->insertUserDataInProfileChangeHistory($userId);
            $this->usermodel->updateUserData($usersTableData);
            $response['response'] = true;
            return $response;   
}



// Working method Not in use
public function setAuthLevelTest($permissions)
{
    $arr = [];
    foreach($permissions as $key => $value)
    {      
            if(!is_array($value))
            {
                if($value->view==true && $value->add==true && $value->update==true && $value->delete==true)
                {
                    $arr[$key] = 9;
                }
                else if($value->view==true && $value->add==true && $value->update==true)
                {
                    $arr[$key] = 5;
                }
                else if($value->view==true && $value->add==true)
                {
                    $arr[$key] = 4;
                }
                else if($value->view==true)
                {
                    $arr[$key] = 1;
                }
                else
                {
                    $arr[$key] = 0;
                }
            }
    }

     print_r($arr);

}

public function setAuthLevel($row)
{      
    $level = '';
    if($row->view==true && $row->add==true && $row->update==true && $row->delete==true)
    {
        $level = 9;
    }
    else if($row->view==true && $row->add==true && $row->update==true)
    {
        $level = 5;
    }
    else if($row->view==true && $row->add==true)
    {
        $level = 4;
    }
    else if($row->view==true)
    {
        $level = 1;
    }
    else
    {
        $level = 0;
    }

    return $level;
}

public function createAuthTemplete($data)
{
    $response = [];
    $usersAuthTemplateNamesCode = $this->generateStringCode();
    $usersAuthTemplateNames = [
        'code'=>$usersAuthTemplateNamesCode,
        'name'=>$data['template_name'],
        'remarks'=>$data['remarks'],
        'created_by'=>$data['login_user_id']
    ];

    $permissions = $data['permissions'];

    $finalusersAuthTemplateListsArray = [];
    foreach($permissions as $mainMenuCode => $value)
    {
        $arr=[];
    
        if(is_array($value))
        {
            $arr=[];
            foreach($value as $key2 => $value2){
                foreach($value2 as $key3 => $value3){
                        $arr['code'] = $this->generateStringCode();
                        $arr['template_code'] = $usersAuthTemplateNamesCode;
                        $arr['main_menu_code'] = $mainMenuCode;
                        $arr['sub_menu_code'] = $key3;
                        $arr['level'] = 9;
                        $arr['created_by'] = $data['login_user_id'];
                        $arr['level'] = $this->setAuthLevel($value3);
                        array_push($finalusersAuthTemplateListsArray,$arr);
                }
            }
        }
        else
        {
            $arr['code'] = $this->generateStringCode();
            $arr['template_code'] = $usersAuthTemplateNamesCode;
            $arr['main_menu_code'] = $mainMenuCode;
            $arr['sub_menu_code'] = null;
            $arr['level'] = 9;
            $arr['created_by'] = $data['login_user_id'];
            $arr['level'] = $this->setAuthLevel($value);
            array_push($finalusersAuthTemplateListsArray,$arr);
        }
    }
    $rowId = $this->usermodel->insertUserAuthTemplateNames($this->encryptRow($usersAuthTemplateNames,['name','remarks']));
    if($rowId)
    {
        $response['message'] = "User template created successfully lib";
        $response['code'] = 200;
        $response['response'] = true;
        $response['result_data'] = [];
        $response['return_data'] = [];
        $this->usermodel->insertUserAuthTemplateLists($finalusersAuthTemplateListsArray);
    }
    else
    {
        $response['message'] = "User template creation failed";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    return $response;
}

public function decodeAuthLevel($level)
{
        $arr=[];
        if($level == 0){
            $arr['view'] = false;
            $arr['add'] = false;
            $arr['update'] = false;
            $arr['delete'] = false;
        }
        else if($level == 1){
            $arr['view'] = true;
            $arr['add'] = false;
            $arr['update'] = false;
            $arr['delete'] = false;
        }
        else if($level == 4){
            $arr['view'] = true;
            $arr['add'] = true;
            $arr['update'] = false;
            $arr['delete'] = false;
        }
        else if($level == 5){
            $arr['view'] = true;
            $arr['add'] = true;
            $arr['update'] = true;
            $arr['delete'] = false;
        }
        else if($level == 9){
            $arr['view'] = true;
            $arr['add'] = true;
            $arr['update'] = true;
            $arr['delete'] = true;
        }

     return $arr;
}


public function getUsersAuthTemplates()
{
     $usersAuthTemplateData = $this->usermodel->getUsersAuthTemplatesData();
     $finalArray = [];
     $tempCodesArray = [];

    foreach($usersAuthTemplateData as $key => $value)
    {
        if(!in_array($value->code,$tempCodesArray))
        {
            $arr['id'] = $value->id;
            $arr['code'] = $value->code;
            $arr['name'] = $value->name;
            $arr['remarks'] = $value->remarks;
          

            $templateList = [];
            foreach($usersAuthTemplateData as $key2 => $value2)
            {
                if($value->code == $value2->code)
                {
                    $arr2['tl_id'] = $value2->tl_id;
                    $arr2['tl_code'] = $value2->tl_code;
                    $arr2['tl_template_code'] = $value2->tl_template_code;
                    $arr2['tl_main_menu_code'] = $value2->tl_main_menu_code;
                    $arr2['tl_main_menu_name'] = $value2->tl_main_menu_name;
                    $arr2['tl_sub_menu_code'] = $value2->tl_sub_menu_code;
                    $arr2['tl_sub_menu_name'] = $value2->tl_sub_menu_name;
                    $arr2['tl_level'] = $value2->tl_level;
                    $arr2['permissions'] = $this->decodeAuthLevel($value2->tl_level);
                    array_push($templateList,$arr2);
                }
            }

            $arr['template_list'] = $templateList;
            array_push($tempCodesArray,$value->code);
            array_push($finalArray,$arr);
        }
       
    }

    return $finalArray;
}


// Done encryption
public function getMainManuDataAuth($uid)
{
    $usersResult = $this->db->table('users')
                    ->where('uid',$uid)    
                    ->get()
                    ->getRow();
   
    $menuMainModulesResult = '';
    // if($usersResult->initial_auth_level == 9)
    // {
        $menuMainModulesResult = $this->db->table('menu_main_modules')
                                            ->select('menu_main_modules.*,sm.id as sub_id,sm.code as sub_code,sm.menu_main_code as sub_menu_main_code,sm.name as sub_name,sm.description as sub_description,sm.icon_name as sub_icon_name,sm.order_no as sub_order_no,sm.created_on as sub_created_on,sm.updated_on as sub_updated_on,sm.is_deleted as sub_is_deleted')
                                            ->join(' menu_sub_modules as sm', ' menu_main_modules.code = sm.menu_main_code','left')  
                                            ->orderBy('menu_main_modules.order_no')
                                            ->get()
                                            ->getResult();  
                                                                
        $mainMenuCodeArray = [];
        foreach($menuMainModulesResult as $key => $value)
        {
                array_push($mainMenuCodeArray,$value->code);
        }
        
        $mainMenuCodeArrayFiltered = array_unique($mainMenuCodeArray);

        $mainMenuArray = [];
        $tempIdArray = [];
        foreach($mainMenuCodeArrayFiltered as $key => $main_menu_code)
        {
            foreach($menuMainModulesResult as $key2 => $value2)
            {
                    if($main_menu_code == $value2->code){
                         
                        if(!in_array($main_menu_code,$tempIdArray))
                        {
                            $arr['id'] = $value2->id;
                            $arr['code'] = $value2->code;
                            $arr['name'] = $value2->name;
                            $arr['description'] = $value2->description;
                            $arr['icon_name'] = $value2->icon_name;
                            $arr['link'] = $value2->link;
                            $arr['order_no'] = $value2->order_no;
                            $arr['created_by'] = $value2->created_by;
                            $arr['updated_by'] = $value2->updated_by;
                            $arr['created_on'] = $value2->created_on;
                            $arr['updated_on'] = $value2->updated_on;
                            $arr['is_deleted'] = $value2->is_deleted;
                            

                            $subMenuArray = [];
                            foreach($menuMainModulesResult as $key3 => $value3)
                            {
                                    if($main_menu_code == $value3->sub_menu_main_code)
                                    {
                                           $arr2['sub_id'] = $value3->sub_id;
                                           $arr2['sub_code'] = $value3->sub_code;
                                           $arr2['sub_menu_main_code'] = $value3->sub_menu_main_code;
                                           $arr2['sub_name'] = $value3->sub_name;
                                           $arr2['sub_description'] = $value3->sub_description;
                                           $arr2['sub_icon_name'] = $value3->sub_icon_name;
                                           $arr2['sub_order_no'] = $value3->sub_order_no;
                                           $arr2['sub_created_on'] = $value3->sub_created_on;
                                           $arr2['sub_updated_on'] = $value3->sub_updated_on;
                                           $arr2['sub_is_deleted'] = $value3->sub_is_deleted;
                                           array_push($subMenuArray,$arr2);
                                    }
                            }

                            $arr['sub_menu'] = $this->decryptResultArray($subMenuArray,['sub_name','sub_description','sub_icon_name']);
                            array_push($mainMenuArray,$arr);
                            array_push($tempIdArray,$main_menu_code);

                        }
                           
                    }
            }  
        }

        $menuMainModulesResult = $mainMenuArray; 
    // }
    // else
    // {
    //     $usersAuthResult = $this->db->table('menu_user_auths') 
    //                                 ->where('user_id',$uid)  
    //                                 ->get()
    //                                 ->getRow(); 
    //     $mainMenuCode =  $usersAuthResult->main_menu_code;  
        
    //     $menuMainModulesResult = $this->db->table('menu_main_modules') 
    //                                         ->where('code',$mainMenuCode) 
    //                                         ->orderBy('menu_main_modules.order_no')
    //                                         ->get()
    //                                         ->getResult();
    // } 
    
    // die;
    return $menuMainModulesResult;
}


public function getSpecificColumnsFromResult($data,$columnsArray)
{
     foreach($data as $key => $value){
        foreach($value as $key2 => $value2){
                if(!in_array($key2,$columnsArray)){
                      unset($value->$key2);
                }
        }
     }
    return $data;
}

public function getUsersList()
{
    $usersData = $this->usermodel->getUsersListsData();
    $decryptedData = $this->decryptResult($usersData,['first_name','last_name','email','phone']);
    $finalData = $this->getSpecificColumnsFromResult($decryptedData,['id','uid','first_name','last_name','email']);
    return $finalData;
}

public function getallTemplatesList()
{
    $templateData = $this->usermodel->getTemplatesListData();
    $templateData = $this->decryptResult($templateData,['name']);
    $finalData = $this->getSpecificColumnsFromResult($templateData,['id','code','name']);
    return $finalData;
}

// Done encryption
public function getSingleTemplate($data)
{
    $usersAuthTemplateData = $this->usermodel->getSingleTemplateData($data['template_code']);

    $finalArray = [];
    $tempCodesArray = [];

   foreach($usersAuthTemplateData as $key => $value)
   {
       if(!in_array($value->code,$tempCodesArray))
       {
           $arr['id'] = $value->id;
           $arr['code'] = $value->code;
           $arr['name'] = $value->name;
           $arr['remarks'] = $value->remarks;
         

           $templateList = [];
           foreach($usersAuthTemplateData as $key2 => $value2)
           {
               if($value->code == $value2->code)
               {
                   $arr2['tl_id'] = $value2->tl_id;
                   $arr2['tl_code'] = $value2->tl_code;
                   $arr2['tl_template_code'] = $value2->tl_template_code;
                   $arr2['tl_main_menu_code'] = $value2->tl_main_menu_code;
                   $arr2['tl_main_menu_name'] = $value2->tl_main_menu_name;
                   $arr2['tl_sub_menu_code'] = $value2->tl_sub_menu_code;
                   $arr2['tl_sub_menu_name'] = $value2->tl_sub_menu_name;
                   $arr2['tl_level'] = $value2->tl_level;
                   $arr2['permissions'] = $this->decodeAuthLevel($value2->tl_level);
                   array_push($templateList,$arr2);
               }
           }

           $arr['template_list'] = $this->decryptResultArray($templateList,['tl_main_menu_name','tl_sub_menu_name']);
           array_push($tempCodesArray,$value->code);
           array_push($finalArray,$arr);
       }
      
   }

   return $finalArray;
}


// Working method but only insertion of records
// public function saveUserMenuAuthentication_xxxxx($data)
// {
//     $response = [];
//     $menuUserAuthCode = $this->generateStringCode();
//     $permissions = $data['permissions'];

//     $finalMenuUserAuthsArray = [];
//     foreach($permissions as $mainMenuCode => $value)
//     {
//         $arr=[];
    
//         if(is_array($value))
//         {
//             $arr=[];
//             foreach($value as $key2 => $value2){
//                 foreach($value2 as $key3 => $value3){
//                         $arr['code'] = $this->generateStringCode();
//                         $arr['user_id'] = $data['user_id'];
//                         $arr['main_menu_code'] = $mainMenuCode;
//                         $arr['sub_menu_code'] = $key3;
//                         $arr['created_by'] = $data['login_user_id'];
//                         $arr['updated_by'] = $data['login_user_id'];
//                         $arr['level'] = $this->setAuthLevel($value3);
//                         array_push($finalMenuUserAuthsArray,$arr);
//                 }
//             }
//         }
//         else
//         {
//             $arr['code'] = $this->generateStringCode();
//             $arr['user_id'] = $data['user_id'];
//             $arr['main_menu_code'] = $mainMenuCode;
//             $arr['sub_menu_code'] = null;
//             $arr['created_by'] = $data['login_user_id'];
//             $arr['updated_by'] = $data['login_user_id'];
//             $arr['level'] = $this->setAuthLevel($value);
//             array_push($finalMenuUserAuthsArray,$arr);
//         }
//     }

//        if($this->usermodel->insertMenuUserAuths($finalMenuUserAuthsArray))
//        {
//             $response['message'] = "User auth permisssions set successfully";
//             $response['code'] = 200;
//             $response['response'] = true;
//             $response['result_data'] = [];
//             $response['return_data'] = [];
//        }
//        else
//        {
//             $response['message'] = "User auth permisssions failed";
//             $response['code'] = 401;
//             $response['response'] = false;
//             $response['result_data'] = [];
//             $response['return_data'] = [];
//        }
    
   
//        return $response;
  
// }


// Working method : 
public function saveUserMenuAuthentication($data)
{
    $response = [];
    $user_id = $data['user_id'];
    $permissions = $data['permissions'];

    $menuUserAuthsData = $this->usermodel->getMenuUserAuthsById($user_id);

    $mainMenuCodeArray = [];
    $subMenuCodeArray = [];

      foreach($menuUserAuthsData as $key => $value)
      {
            if($value->sub_menu_code!=''){
                array_push($subMenuCodeArray,$value->sub_menu_code);
            }
            array_push($mainMenuCodeArray,$value->main_menu_code);
      }

      $mainMenuCodeFilteredArray = array_unique($mainMenuCodeArray);
      $subMenuCodeFilteredArray = array_unique($subMenuCodeArray);
    
    $updateDataArray = [];
    $insertDataArray = [];

    foreach($permissions as $mainMenuCode => $value)
    {
        $arr = [];
         if(!is_array($value))
         {
            if(in_array($mainMenuCode,$mainMenuCodeFilteredArray))
            {
                 $arr['user_id'] = $user_id;
                 $arr['main_menu_code'] = $mainMenuCode;
                 $arr['sub_menu_code'] = null;
                 $arr['level'] = $this->setAuthLevel($value);
                 $arr['updated_by'] = $data['login_user_id'];
                 array_push($updateDataArray,$arr);
            }
            else
            {
                $arr['code'] = $this->generateStringCode();
                $arr['user_id'] = $data['user_id'];
                $arr['main_menu_code'] = $mainMenuCode;
                $arr['sub_menu_code'] = null;
                $arr['created_by'] = $data['login_user_id'];
                $arr['updated_by'] = $data['login_user_id'];
                $arr['level'] = $this->setAuthLevel($value);
                array_push($insertDataArray,$arr);
            }
         }
         else
         {
                foreach($value as $key2 =>$value2)
                {
                    foreach($value2 as $subMenuCode => $value3)
                    {
                            if(in_array($subMenuCode,$subMenuCodeFilteredArray))
                            {
                                $arr['user_id'] = $user_id;
                                $arr['main_menu_code'] = $mainMenuCode;
                                $arr['sub_menu_code'] = $subMenuCode;
                                $arr['level'] = $this->setAuthLevel($value3);
                                $arr['updated_by'] = $data['login_user_id'];
                                array_push($updateDataArray,$arr);   
                            }
                            else
                            {
                                $arr['code'] = $this->generateStringCode();
                                $arr['user_id'] = $data['user_id'];
                                $arr['main_menu_code'] = $mainMenuCode;
                                $arr['sub_menu_code'] = $subMenuCode;
                                $arr['created_by'] = $data['login_user_id'];
                                $arr['updated_by'] = $data['login_user_id'];
                                $arr['level'] = $this->setAuthLevel($value3);
                                array_push($insertDataArray,$arr);
                            }
                    }
                }
               
         }
          

    }

    $status = $this->usermodel->setMenuUserAuthsPermissions($insertDataArray,$updateDataArray);

       if($status)
       {
            $response['message'] = "User auth permisssions set successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = [];
       }
       else
       {
            $response['message'] = "User auth permisssions failed";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = [];
       }

       return $response;
}


public function getFilteredApis($searchCriteria, $numberOfRecords, $paginationNumber)
{
    $query = $this->db->table('api_url_endpoints');
    $query->where($searchCriteria[0]->column_name.$searchCriteria[0]->operator, $this->encryptValue($searchCriteria[0]->key));
    foreach ($searchCriteria as $index => $criteria) {
        if($index!=0)
        {
            $key = $criteria->key;
            $columnName = $criteria->column_name;
            $type = $criteria->type;
            $operator = $criteria->operator;

            if($operator == 'like'){
                $query->like($columnName, $this->encryptValue($key));
            }
    
            if($operator!='like'){
                switch ($searchCriteria[$index-1]->type) {
                    case 'and':
                        $query->where($columnName.$operator, $this->encryptValue($key));
                        break;
                    case 'or':
                        $query->orWhere($columnName.$operator, $this->encryptValue($key));
                        break;
                    case 'end':
                        break;
                    default:
                        break;
                }
            }
            


        }
    }

        $offset = ($paginationNumber - 1) * $numberOfRecords;
        $query->where('is_deleted',0);
        $query->limit($numberOfRecords, $offset);
        $result = $query->get()->getResult();
        return $result;
}

public function getStandardRecordsFromApiUrlEndpoints($numberOfRecords, $paginationNumber)
{
    $query = $this->db->table('api_url_endpoints');
    $result = $query->where('is_deleted',0)->limit(6)->get()->getResult();
    return $result;
}


public function getAddressBookList()
{
    $templateData = $this->usermodel->getAddressBookListData();
    $finalData = $this->getSpecificColumnsFromResult($templateData,['id','code','name']);
    return $finalData;
}

public function getApiRequestTypeList()
{
    $templateData = $this->usermodel->getApiRequestTypeListData();
    $finalData = $this->getSpecificColumnsFromResult($templateData,['id','code','api_request_type']);
    return $finalData;
}


public function getApiById($code)
{
    $apiData = $this->usermodel->getApiByIdData($code);
    return $apiData;
}


public function deleteApi($code)
{
    $apiData = $this->usermodel->deleteApiData($code);
    return $apiData;
}


public function getVisualMetric()
{
    $visualMetricData = $this->usermodel->getVisualMetricData();
    foreach($visualMetricData as $key => $value)
    {
         
            $value->data_set = json_decode($this->decryptValue($value->data_set));
    }
    return $visualMetricData;
}


// public function updateUserAnalytics_xxx($inputData,$data)
// {
//     $response = [];
//     $finalArray = [];
//     foreach($inputData as $key => $value)
//     {
//         $arr = [];
//         $arr['code'] = $this->generateStringCode();
//         $arr['user_id'] = $value->user_id;
//         $arr['menu_code'] = $value->menu_code;
//         $arr['visual_code'] = $value->analytical_code;
//         $arr['created_by'] = $data['login_user_id'];
//         $arr['updated_by'] = $data['login_user_id'];
//         $arr['is_enabled'] = $value->status;
//         array_push($finalArray,$arr);
//     }

//     if($this->usermodel->insertVisualMetricsMenuModules($finalArray))
//     {
//         $response['response'] = true;
//     }
//     else
//     {
//         $response['message'] = "Error in updating user analyticals";
//         $response['code'] = 401;
//         $response['response'] = false;
//         $response['result_data'] = [];
//         $response['return_data'] = [];
//     }

//     return $response;

// }


public function updateUserAnalytics($inputData,$data)
{
    $response = [];
    foreach($inputData as $key => $value)
    {
        $visualMetricsMenuStatus = $this->usermodel->checkMenuCodeExistsForVisualCode($value->user_id,$value->analytical_code,$value->menu_code);
        if($visualMetricsMenuStatus)
        {
            $response['message'] = "Menu permission already exists";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = [];
            return $response;
        }
        else
        {
            $arr = [];
            $arr['code'] = $this->generateStringCode();
            $arr['user_id'] = $value->user_id;
            $arr['menu_code'] = $value->menu_code;
            $arr['visual_code'] = $value->analytical_code;
            $arr['created_by'] = $data['login_user_id'];
            $arr['updated_by'] = $data['login_user_id'];
            $arr['is_enabled'] = $value->status;

            if($this->usermodel->insertVisualMetricsMenuModules($arr))
            {
                $response['response'] = true;
            }
            else
            {
                $response['message'] = "Error in updating user analyticals";
                $response['code'] = 401;
                $response['response'] = false;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
        }
    }
    
    return $response;

}



// Done encryption
public function getUserAnalyticalView($data)
{
     $visualMetricMenuModulesData = $this->usermodel->getVisualMetricsMenuModulesData($data);
    $visualCodeArray = array_column($visualMetricMenuModulesData,'visual_code');
    $visualMetricsData = $this->usermodel->getVisualMetricsData($visualCodeArray);
  
     foreach($visualMetricMenuModulesData as $key => $value)
     {
            foreach($visualMetricsData as $key2 => $value2){
                if($value->visual_code == $value2->code){
                    $value->data_set = json_decode($this->decryptValue($value2->data_set));
                }
            }
           
     }

   return $visualMetricMenuModulesData;
}


public function getMainMenuList()
{
    $mainMenuListData = $this->usermodel->getMainMenuListData();
    return $mainMenuListData;
}

public function getUsersDashboard($userId)
{
    $mainMenuCount = $this->usermodel->getMenuMainModulesCount();
    $menuUserAuthCount = $this->usermodel->getMenuUserAuthsCount($userId);
    
    $usersData = $this->usermodel->getUserByUid($userId);
    if($usersData->initial_auth_level == 9)
    {
        $result = $this->getVisualMetric();
        return $result;
    }
    else if($mainMenuCount == $menuUserAuthCount)
    {
        $result = $this->getVisualMetric();
        return $result;
    }
    else
    {
          unset($usersData->password);
          unset($usersData->activation_selector);
          unset($usersData->forgotten_password_selector);
          unset($usersData->forgotten_password_code);
          unset($usersData->forgotten_password_time);
          unset($usersData->remember_selector);
          unset($usersData->remember_code);
          unset($usersData->activation_code);
        
          $lastLoginAttemptsHistoryData = $this->usermodel->getUsersLastLoginAttemptsHistoryData($usersData->email);
          $usersData->last_login_details = $this->decryptResultArray($lastLoginAttemptsHistoryData,['login_user_id','browser_details']);
          return $usersData;
    }
}


public function registerUser($data)
{
            $flag = false;
            $addressBookCode = $this->generateStringCode();
            $userAddressMapperCode = $this->generateStringCode();
            $userAddressBookConnectCode = $this->generateStringCode();

            $addressBookData = [
                'code'=>$addressBookCode,
                'type_of_connect'=>$data['user_type'],
                'name'=>$data['company'],
                'created_by'=>$data['uid'],
                'updated_by'=>$data['uid'],
                'status'=>'' 
        ];

        $userAddressMapperData = [
            'code'=>$userAddressMapperCode,
            'user_id'=>$data['uid'],
            'addressbook_code'=>$addressBookCode,
            'created_by'=>$data['uid'],
            'updated_by'=>$data['uid']
        ];


        $userAddressBookConnectData = [
            'code'=>$userAddressBookConnectCode,
            'address_code'=>$addressBookCode,
            'email'=>$data['email'],
            'phone'=>$data['phone'],
            'created_by'=>$data['uid'],
            'updated_by'=>$data['uid']
        ];

         
         $encryptedUserData = $this->encryptRow($data,['username','email','first_name','last_name','company','phone']);
         if($this->usermodel->registerUserData($encryptedUserData))
         {
            $adressBookRecoredId = $this->usermodel->insertIntoAddressBook($this->encryptRow($addressBookData,['name']));
            $userAddressMapperRecordId = $this->usermodel->insertIntoUserAddressMapper($userAddressMapperData);
            $userAddressBookConnectRecordId = $this->usermodel->insertIntoUserAddressBookConnect($this->encryptRow($userAddressBookConnectData,['email','phone']));
            $flag = true;
         }
       
   return $flag;
   
}


public function addLoginAttemptsHistory($email,$ipAddress,$userAgent,$isSuccess)
{
        $data = array(
                'login_user_id'=>$email,
                'ip_address'=>$ipAddress,
                'browser_details'=>$userAgent,
                'is_success'=>$isSuccess
        );
        $data = $this->encryptRow($data,['login_user_id','browser_details']);
        $query = $this->db->table('login_attempts_history');
        return $query->insert($data);
}


// Done encrption
public function insertApiUrlEndPoints($data)
{
        $encryptData = $this->encryptRow($data,['api_url','api_endpoint','description','request','response_success','header_request','response_error']);
        $this->db->table('api_url_endpoints')
        ->insert($encryptData);
        $insertedID = $this->db->insertID();
        return $insertedID; 
}


public function updateApiUrlEndPoints($code,$data)
{
    $encryptData = $this->encryptRow($data,['api_url','api_endpoint','description','request','response_success','header_request','response_error']);
        $this->db->table('api_url_endpoints')
        ->where('code',$code)
        ->update($encryptData); 
        return true;
}


public function getUserAuths($userId)
{
        $userAuthsData = $this->usermodel->getUserAuthsData($userId); 
        
        foreach($userAuthsData as $key => $value)
        {
            $value->level = $this->decodeAuthLevel($value->level);;
        }

        $finalData = $this->decryptResult($userAuthsData,['main_menu_name','sub_menu_name']);
        return $finalData;
}



public function getUserAllAnalyticalViews($data)
{
    $mainMenuData = $this->usermodel->getMainMenuListData();
    $mainMenuArrayForCheck = array_column($mainMenuData,'code','name');
    $mainMenuArray = array_flip($mainMenuArrayForCheck);

    $visualMetricData = $this->usermodel->getVisualMetricData();
    $visualMetricArrayForCheck = array_column($visualMetricData,'code','visual_name');
    $visualMetricArray = array_flip($visualMetricArrayForCheck);

    $visualMetricMenuModulesData = $this->usermodel->getVisualMetricsMenuModulesDataByUid($data);
  
     foreach($visualMetricMenuModulesData as $key => $value)
     {
        if(in_array($value->menu_code,$mainMenuArrayForCheck))
        {
            $value->menu_main_name = $this->decryptValue($mainMenuArray[$value->menu_code]);
        }
        if(in_array($value->visual_code,$visualMetricArrayForCheck))
        {
            $value->visual_name = $this->decryptValue($visualMetricArray[$value->visual_code]);
        }    
        $value->user_name = $this->decryptValue($value->user_name);      
     }

   return $visualMetricMenuModulesData;
}


public function changeUsersVisualMetricStatus($userId,$menuCode,$analyticalCode,$data)
{
    $response = [];
    $updateData = array(
        'updated_by'=>$data['logged_in_user'],
        'is_enabled'=>$data['status']
    );
    $result = $this->usermodel->changeUsersVisualMetricStatus($userId,$menuCode,$analyticalCode,$updateData);
    if($result)
    {
        $response['response'] = true;
    }
    else
    {
        $response['message'] = "Failed in changing status";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    return $response;
}


public function getProjectAccessToken()
{
		$finalKey = '';
		$bytes = random_bytes(32);

        $numbersKeys = bin2hex($bytes);
		$alphabetsKeys = "abcdefghijklmnopqrstuvwxyz";
		
		$finalKey = $numbersKeys.$alphabetsKeys;

		$accessToken = substr(str_shuffle($finalKey),0,40);
		return $accessToken;
}

public function getUserAccessToken()
{
		$finalKey = '';
		$bytes = random_bytes(32);

        $numbersKeys = bin2hex($bytes);
		$alphabetsKeys = "abcdefghijklmnopqrstuvwxyz";
		
		$finalKey = $numbersKeys.$alphabetsKeys;

		$accessToken = substr(str_shuffle($finalKey),0,38).'ur';
		return $accessToken;
}


public function generateProjectAccessKey($projectCode,$data)
{
    $response = [];

    if($this->usermodel->checkProjectAccessKeyExists($projectCode)){
        $response['message'] = "Project access key already exists";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
        return $response;
    }
 
    $projectAccessKey = $this->getProjectAccessToken();
    $data['access_token'] = $projectAccessKey;
    
    $status = $this->usermodel->updateIntoProjects($projectCode,$data);
    if($status)
    {
        $response['message'] = "Project access key generated successfully";
        $response['code'] = 200;
        $response['response'] = true;
        $response['result_data'] = ["project_access_key"=>$projectAccessKey];
        $response['return_data'] = [];
    }
    else
    {
        $response['message'] = "Project access key generation failed";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    return $response;
    
}

public function generateUserAccessKey($data)
{
    $response = [];

    if($this->usermodel->checkUserAccessTokenExistsForProject($data['user_id'],$data['project_code']))
    {
        $response['message'] = "User access token already exists for this user for project";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
        return $response;
    }

    $code = $this->generateStringCode();
    $getUserAccessToken = $this->getUserAccessToken();
    $data['code'] = $code;
    $data['access_token'] = $getUserAccessToken;

    $status = $this->usermodel->insertIntoUserProjAccessToken($data);
   
    if($status)
    {
        $response['message'] = "User access key generated successfully";
        $response['code'] = 200;
        $response['response'] = true;
        $response['result_data'] = ["user_access_key"=>$getUserAccessToken];
        $response['return_data'] = [];
    }
    else
    {
        $response['message'] = "User access key generation failed";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    return $response;

}


public function getAllProjectsList()
{
    $projectsData = $this->usermodel->getAllProjectsList();
    $decryptedData = $this->decryptResult($projectsData,['name','remarks']);
    $finalData = $this->getSpecificColumnsFromResult($decryptedData,['id','code','name','remarks']);
    return $finalData;
}

public function createProject($data)
{
    $response = [];

    if($this->usermodel->checkProjectExists($data['name']))
    {
        $response['message'] = "Project already exists";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
        return $response;
    }

    $code = $this->generateStringCode();
    $data['code'] = $code;

    $status = $this->usermodel->insertIntoProjects($data);
    if($status)
    {
        $response['message'] = "Project created successfully";
        $response['code'] = 200;
        $response['response'] = true;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    else
    {
        $response['message'] = "Project creation fail";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    return $response;
}


public function userAssignApi($data)
{
      $response = [];
      $userProjAccessTokenData = $this->usermodel->getUserProjAccessTokenData($data['user_id'],$data['project_code']);

      $userProjAccessTokenCode = $userProjAccessTokenData->code;
  
     $status = $this->usermodel->checkApiAlreadyAssigned($userProjAccessTokenCode,$data['api_code']);

     if($status){
        $response['message'] = "Api is already assigned to the user";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
        return $response;
     }

    $insertData = array(
        'code'=>$this->generateStringCode(),
        'user_mapper_api_code'=>$userProjAccessTokenCode,
        'api_code'=>$data['api_code'],
        'created_by'=>$data['created_by'],
        'updated_by'=>$data['updated_by']
    );

     $rowId = $this->usermodel->insertIntoUserMapperApis($insertData);
     
    if($rowId){
        $response['message'] = "Api assigned successfully";
        $response['code'] = 200;
        $response['response'] = true;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    else{
        $response['message'] = "Api assigned failed";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }
    
    return $response;
}


public function validateAccessKeys($projectAccessKey,$userAccessKey)
{
    $response = [];
    $result = $this->usermodel->validateProjectAccessKey($projectAccessKey);

    if($result)
    {
         $allAccessKeys = $this->usermodel->getAllUsersAccessKeysForProject($result->code);
        $allAccessKeysArray = array_column($allAccessKeys,'access_token');

        if(in_array($userAccessKey,$allAccessKeysArray))
        {
            $response['message'] = "Project and user keys are validated successfully";
            $response['code'] = 200;
            $response['response'] = true;
            $response['result_data'] = [];
            $response['return_data'] = []; 
        }
        else
        {
            $response['message'] = "Invalid user access key";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = [];
        }
    }
    else
    {
        $response['message'] = "Invalid project access key";
        $response['code'] = 401;
        $response['response'] = false;
        $response['result_data'] = [];
        $response['return_data'] = [];
    }

    return $response;
}


public function getUserIdByToken($token)
{
    $finalArray = [];
    $uid = '';
    $result = $this->usermodel->getUserIdByTokenFromUsersSessionTokens($token);

    if($result)
    {
        $finalArray['uid'] = $result->uid;
        $finalArray['byPass'] = false;
    }
    else
    {
        $result = $this->usermodel->getUserIdByTokenFromUserProjAccessToken($token);
        $finalArray['uid'] = $result->user_id;
        $finalArray['byPass'] = true;
    }

    // print_r($finalArray);die;
    return $finalArray;
}



// ######################## TESTING AREA ######################



public function testerTokenVerification($testerTokenEmailHeader,$testerTokenAuthorizationHeader)
{
    // print_r($testerTokenHeader);

    // die;
	$response = [];
	$error_code = '';
	$users = $this->tester->getTestersData();
    
	// $token = $this->request->getHeader('Authorization');
	// $email = $this->request->getHeader('testerEmail');
    $token = $testerTokenAuthorizationHeader;
    $email = $testerTokenEmailHeader;

    // print_r($email);die;

	if($token!='')
	{
			if($email!='')
			{
				if(array_key_exists($email->getValue(),$users))
				{
					if('Bearer '.$users[$email->getValue()]==$token->getValue())
					{
						$response['message']="Tester token validated successfully";
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


public function verify_testertoken_sessiontoken_checktimeout($testerTokenEmailHeader,$testerTokenAuthorizationHeader)
{
    // echo "verify_testertoken_sessiontoken_checktimeout";die;
       $finalResponse = [];
      if($testerTokenEmailHeader!='')
      {
            $finalResponse['label'] = "testerToken";
           $testTokenResponse = $this->testerTokenVerification($testerTokenEmailHeader,$testerTokenAuthorizationHeader);
           if($testTokenResponse['response'])
           {
               $finalResponse['response'] = true;
               $finalResponse['data'] = array("token"=>$testerTokenEmailHeader->getValue());
           }
           else
           {
                $finalResponse['response'] = false;
                $finalResponse['data'] = array("errors"=>$testTokenResponse);
           }
      }


    
    //   print_r($finalResponse);
    //   die;
    return $finalResponse;
}


public function filteredUserExists($email)
{
    // echo "filteredUserExists";die;
    $this->usermodel->filteredUserExists($this->encryptValue($email));
}



}
