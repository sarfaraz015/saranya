<?php
namespace App\Libraries;
use App\Libraries\SecureDataHandler;
use App\Models\UserModel;
// use App\Libraries\Lib_log;

class UserLibrary{

      public $db;
      public $dataHandler;
	  public $usermodel;

public function __construct()
{
    // $testlib = new Lib_log();
	$this->usermodel = new UserModel();
	$this->db = \Config\Database::connect();
	$secret_key = $_ENV['ENCRYPTION_KEY'];
	$salt = $_ENV['SALT'];
	$this->dataHandler = new SecureDataHandler($secret_key, $salt);
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
			
			if($diff > 60*1)
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



}
