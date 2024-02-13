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







}
