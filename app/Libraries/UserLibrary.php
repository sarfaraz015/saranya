<?php
namespace App\Libraries;
use App\Libraries\SecureDataHandler;
use App\Models\UserModel;

class UserLibrary{

      public $db;
      public $dataHandler;
	  public $usermodel;

public function __construct()
{
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
	$q = "SELECT * FROM users_tokens WHERE `uid` = {$userId}";
	$query = $this->db->query($q); 
	return $query->getRow();
}

public function checkActiveStatus($userId)
{
    $query = $this->db->table('users_tokens')
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
        $row = $this->db->table('users_tokens')
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
			$created_at = $row->created_at;

			$currentDate = strtotime($currentDate);
			$created_at = strtotime($created_at);

			$diff = abs($currentDate - $created_at);
			
			if($diff > 60*1)
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


public function storeLogs($fun,$uid=null,$token=null)
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
	$arr['access_key'] = "67hthyd777==ljdsbsdjf";
	$arr['screte_key'] = "fvdshchsjcasjdhadjhsadkask";

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
	$logResult['user_input_data'] = json_encode($arr);

	$this->usermodel->storeUserLogHistory($logResult);
    return $logResult;
}





}
