<?php

namespace App\Models;

use CodeIgniter\Model;
use App\Libraries\SecureDataHandler;

class UserModel extends Model
{
    public $db;
    public $dataHandler;

public function __construct()
{
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
        return $query->getRow()->uid;                
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

public function insertToken($data)
{
        $query = $this->db->table('users_tokens');
        return $query->insert($data);

}

public function updateToken($data,$userId)
{
        $id = $this->db->table('users_tokens')
        ->where('uid', $userId)
        ->update($data);
        return $id;      
}

public function verifyToken($token)
{
        $row = $this->db->table('users_tokens')
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
                $this->db->table('users_tokens')
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
        $q = "SELECT * FROM users_tokens WHERE token ='{$token}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}



public function resetUsersTimeout($token,$data)
{
        $this->db->table('users_tokens')
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
                'updated_at'=>$currentDate
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
                'updated_at'=>$currentDate
        ]);
}



public function checkOTPTimeout($user_id,$otp)
{
        $q = "SELECT * FROM users_otp WHERE `uid` ='{$user_id}' AND otp = '{$otp}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}


}
