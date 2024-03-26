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

public function __construct()
{
    // $testlib = new Lib_log();
	$this->usermodel = new UserModel();
	$this->db = \Config\Database::connect();
	$secret_key = $_ENV['ENCRYPTION_KEY'];
	$salt = $_ENV['SALT'];
	$this->dataHandler = new SecureDataHandler($secret_key, $salt);
    $this->tester = new Tester();
}

public function checkUserAlreadyExists($email)
{
	$q = "SELECT * FROM users WHERE `email` ='{$this->dataHandler->encryptAndStore($email)}'";
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
public function getFilteredUsers($searchCriteria, $numberOfRecords, $paginationNumber)
{
    $query = $this->db->table('users');
    $query->where($searchCriteria[0]->column_name.$searchCriteria[0]->operator, $this->dataHandler->encryptAndStore($searchCriteria[0]->key));
    foreach ($searchCriteria as $index => $criteria) {
        if($index!=0)
        {
            $key = $criteria->key;
            $columnName = $criteria->column_name;
            $type = $criteria->type;
            $operator = $criteria->operator;

            if($operator == 'like'){
                $query->like($columnName, $this->dataHandler->encryptAndStore($key));
            }
    
            if($operator!='like'){
                switch ($searchCriteria[$index-1]->type) {
                    case 'and':
                        $query->where($columnName.$operator, $this->dataHandler->encryptAndStore($key));
                        break;
                    case 'or':
                        $query->orWhere($columnName.$operator, $this->dataHandler->encryptAndStore($key));
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


public function getMainManuData($uid)
{
    $usersResult = $this->db->table('users')
                    ->where('uid',$uid)    
                    ->get()
                    ->getRow();
   
    $menuMainModulesResult = '';
    if($usersResult->initial_auth_level == 9)
    {
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

                            $arr['sub_menu'] = $subMenuArray;
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
        $usersAuthResult = $this->db->table('menu_user_auths') 
                                    ->where('user_id',$uid)  
                                    ->get()
                                    ->getRow(); 
        $mainMenuCode =  $usersAuthResult->main_menu_code;  
        
        $menuMainModulesResult = $this->db->table('menu_main_modules') 
                                            ->where('code',$mainMenuCode) 
                                            ->orderBy('menu_main_modules.order_no')
                                            ->get()
                                            ->getResult();
    } 
    
    return $menuMainModulesResult;
}


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

public function encryptRowForSpecificColumns($data,$columns)
{
        foreach($data as $key => $value)
        {
                if(in_array($key,$columns))
                {  
                    $data->$key  = $this->dataHandler->encryptAndStore($value);
                }
        }
   return $data;
}



public function insertUserDataInProfileChangeHistory($uid)
{
    $userData = $this->db->table('users')
                            ->where('uid',$uid)    
                            ->get()
                            ->getRow();   
    
    $columns = ['username','email','first_name','last_name','company','phone'];
    $decryptedUserData = $this->decryptRowForSpecificColumns($userData,$columns);

    unset($decryptedUserData->id);
    unset($decryptedUserData->password);
    unset($decryptedUserData->initial_auth_level);
    unset($decryptedUserData->activation_selector);
    unset($decryptedUserData->activation_code);
    unset($decryptedUserData->forgotten_password_selector);
    unset($decryptedUserData->forgotten_password_code);
    unset($decryptedUserData->forgotten_password_time);
    unset($decryptedUserData->remember_selector);
    unset($decryptedUserData->remember_code);
    unset($decryptedUserData->ip_address);
    unset($decryptedUserData->last_login);
    unset($decryptedUserData->active);
    
    $userArray = (array)$decryptedUserData;
    $userArray['user_id'] = $userArray['uid'];
    unset($userArray['uid']);
    $userObj = (object)$userArray;

    $rowId = $this->usermodel->insertUserDataInProfileChangeHistory($userObj);
    return $rowId;
}


public function checkCreatedUserExistsInUsersTable($email)
{
    $usersResult = $this->db->table('users')
    ->where('email',$this->dataHandler->encryptAndStore($email))    
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
        ->where('name',$company) 
        ->where('city',$city)    
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

public function createUser($data)
{
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

    if($this->checkCompanyCityExists($data['company'],$data['city']))
    {
            $response['message'] = "Company and city already exists";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = $data;
            return $response; 
    }

    $encryptedData = $this->encryptRowForSpecificColumns((object)$data,['username','email']);
    $usersTableData = [
        'uid'=>$encryptedData->uid,
        'ip_address'=>$encryptedData->ip_address,
        'username'=>$encryptedData->username,
        'email'=>$encryptedData->email,
        'password'=>$encryptedData->password,
        'created_on'=>$encryptedData->created_on,
        'created_by'=>$encryptedData->created_by,
        'company'=>$encryptedData->company,
        'active'=>$encryptedData->active
    ];
    
    $code = $this->generateStringCode();
    $addressBookData = [
        'code'=>$code,
        'type_of_connect'=>$data['user_type'],
        'name'=>$data['company'],
        'address_1'=>$data['address_1'],
        'address_2'=>$data['address_2'],
        'city'=>$data['city'],
        'state'=>$data['state'],
        'status'=>$data['lender_status'] 
  ];
    
  $userAddressMapperData = [
    'user_id'=>$encryptedData->uid,
    'addressbook_code'=>$code,
];
    
        if($this->usermodel->registerUser($usersTableData))
        {
            $adressBookRecoredId = $this->usermodel->insertIntoAddressBook($addressBookData);
            $userAddressMapperRecord = $this->usermodel->insertIntoUserAddressMapper($userAddressMapperData);
            $response['message'] = "User created successfully";
            $response['code'] = 401;
            $response['response'] = false;
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



// ######################## TESTING METHODS ######################

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



}
