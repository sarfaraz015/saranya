<?php

namespace App\Models;

use CodeIgniter\Model;
use App\Libraries\SecureDataHandler;
// use App\Libraries\Lib_log;

class UserModel extends Model
{
    public $db;
    public $dataHandler;

public function __construct()
{
        // $testlib = new Lib_log();
        $this->db = \Config\Database::connect();
        $secret_key = $_ENV['ENCRYPTION_KEY'];
        $salt = $_ENV['SALT'];
        $this->dataHandler = new SecureDataHandler($secret_key, $salt);
}

public function checkUserIdExists($user_id)
{
        $q = "SELECT * FROM users WHERE `uid` ='{$user_id}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}

public function registerUser($data)
{
        $query = $this->db->table('users');
        return $query->insert($data);
}   
    
public function getUserId($email)
{
        $q = "SELECT * FROM users WHERE email='{$this->dataHandler->encryptAndStore($email)}'";
        $query = $this->db->query($q);  
        return $query->getRow()?$query->getRow()->uid:'';                
}

    
public function getUserDetails($userId)
{
        $query = $this->db->table('users')
                ->select('*')
                ->where('uid', $userId)
                ->get();

        $row = $query->getRow();
        return $row; 
}

public function getAllUserDetails()
{
        $query = $this->db->table('users')
                ->select('*')
                ->get();

        $result = $query->getResult();
        return $result; 
}

public function insertToken($data)
{
        $query = $this->db->table('users_session_tokens');
        return $query->insert($data);

}

public function updateToken($data,$userId)
{
        $id = $this->db->table('users_session_tokens')
        ->where('uid', $userId)
        ->update($data);
        return $id;      
}

public function verifyToken($token)
{
        $row = $this->db->table('users_session_tokens')
                ->select('*')
                ->where('token', $token)
                ->get()
                ->getRow();       
        return $row;
}


public function destroyToken($token,$data)
{
        if($this->verifyToken($token))
        {
                $this->db->table('users_session_tokens')
                ->where('token', $token)
                ->update($data);
                return 1;       
        }
        else
        {
                return 0;
        }
}

public function updateLastLoginInUsers($userId)
{
        $this->db->table('users')
        ->where('uid', $userId)
        ->update(['last_login'=>time()]);
}


public function checkUserTimeout($token)
{
        $q = "SELECT * FROM users_session_tokens WHERE token ='{$token}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}



public function resetUsersTimeout($token,$data)
{
        $this->db->table('users_session_tokens')
        ->where('token', $token)
        ->update($data);
}


public function getAttemptsNumber($email)
{
        $q = "SELECT * FROM login_attempts WHERE `login` = '{$email}'";
	$result = $this->db->query($q)
		  ->getResult();
        return count($result);
}

public function increaseUsersInvalidLoginAttempts($ipAddress,$email,$time)
{
        $data = [
                'ip_address'=>$ipAddress,
                'login'=>$email,
                'time'=>$time
        ];
        if($this->getAttemptsNumber($email) < 3)
        {
                $query = $this->db->table('login_attempts');
                return $query->insert($data);
        }
        return;
}

public function clearInvalidLoginAttempts($email)
{
        $this->db->table('login_attempts')
        ->where('login', $email)
        ->delete();
}

public function insertOTP($data)
{
        $this->db->table('users_otp')
                   ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID;         
}

public function updateNewPassword($data,$user_id)
{
        $this->db->table('users')
        ->where('uid', $user_id)
        ->update($data);
}

public function deactivateOTPOnResetPassword($user_id,$otp)
{
        date_default_timezone_set('Asia/Kolkata');
        $currentDate = date("Y:m:d H:i:s");
        $this->db->table('users_otp')
        ->where('otp', $otp)
        ->where('uid',$user_id)
        ->update([
                'otp_active_status'=>0,
                // 'updated_at'=>$currentDate
        ]);
}


public function deactivateOldOTP($user_id)
{
        date_default_timezone_set('Asia/Kolkata');
        $currentDate = date("Y:m:d H:i:s");
        $this->db->table('users_otp')
        ->where('uid',$user_id)
        ->update([
                'otp_active_status'=>0,
                // 'updated_on'=>$currentDate
        ]);
}



public function checkOTPTimeout($user_id,$otp)
{
        $q = "SELECT * FROM users_otp WHERE `uid` ='{$user_id}' AND otp = '{$otp}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}


public function getLastAttemptRecord($email)
{
        $q = "SELECT * FROM login_attempts WHERE `login` = '{$email}' ORDER BY id DESC";
	$result = $this->db->query($q)
		  ->getResult();
        $row = $result[0];  
        return $row;   
}

public function storeUserLogHistory($data)
{
        $this->db->table('users_log_history')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID;     
}


public function getToken($user_id)
{
        $q = "SELECT * FROM users_session_tokens WHERE `uid`='{$user_id}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}


public function getUidFromUsersTokens($token)
{
        $q = "SELECT * FROM users_session_tokens WHERE `token`='{$token}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}


public function checkUserIdIsAvailableInApiLogsTable($user_id)
{
        $q = "SELECT * FROM api_concurrent_request_log WHERE `user_id`='{$user_id}'";
        $query = $this->db->query($q); 
        return $query->getRow(); 
}

public function checkUserIdAndApiURL($user_id,$url)
{
        $q = "SELECT * FROM api_concurrent_request_log WHERE `user_id`='{$user_id}' AND `api_url`='{$url}'";
        $query = $this->db->query($q); 
        return $query->getRow(); 
}

public function getApiLogs($user_id,$apiURL)
{
        $q = "SELECT * FROM api_concurrent_request_log WHERE `user_id`='{$user_id}' AND `api_url`='{$apiURL}'";
        $query = $this->db->query($q);
        return $query->getRow();          
}

public function insertApiLogs($data)
{
        $this->db->table('api_concurrent_request_log')
                ->insert($data);
                $insertedID = $this->db->insertID();
                return $insertedID;  
}


public function updateApiLogs($user_id,$apiUrl,$data)
{
        $this->db->table('api_concurrent_request_log')
        ->where('user_id',$user_id)
        ->where('api_url',$apiUrl)
        ->update($data);
}


public function timeCheckerToReleaseUser($user_id,$apiURL)
{
        $q = "SELECT * FROM api_concurrent_request_log WHERE `user_id`='{$user_id}' AND `hit_count`>=3";
        $query = $this->db->query($q);
        return $query->getRow();  
}

public function releaseUserApis($user_id,$data)
{
        $this->db->table('api_concurrent_request_log')
        ->where('user_id',$user_id)
        ->update($data);  
}



// Function not in use : 
public function checkUsersMaxApiHitCount($user_id,$apiURL)
{
        $q = "SELECT * FROM api_concurrent_request_log WHERE `user_id`='{$user_id}' AND `api_url`='{$apiURL}'";
        $query = $this->db->query($q);
        return $query->getRow(); 
}


public function checkAnyApiHasMaxCountForUser($user_id)
{
        $q = "SELECT * FROM api_concurrent_request_log WHERE `user_id`='{$user_id}' AND `hit_count`>2";
        $query = $this->db->query($q);
        return $query->getRow(); 
}


public function updateUserData($data)
{
        $this->db->table('users')
        ->where('uid',$data['uid'])
        ->update($data);  
}

public function insertUserDataInProfileChangeHistory($data)
{
        $this->db->table('user_profile_change_history')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID;  
}


public function updateUserProfileImage($data)
{
        $this->db->table('users')
        ->where('uid',$data['uid'])
        ->update($data); 
}




}
