<?php

namespace App\Models;

use CodeIgniter\Model;
use App\Libraries\SecureDataHandler;
// use App\Libraries\UserLibrary;
// use App\Libraries\Lib_log;

class UserModel extends Model
{
    public $db;
    public $dataHandler;
//     public $userlibrary;
     public $environment;
     public $enableEncryptDecryptInDevEnv;

public function __construct()
{
        // $testlib = new Lib_log();
        $this->db = \Config\Database::connect();
        $secret_key = $_ENV['ENCRYPTION_KEY'];
        $salt = $_ENV['SALT'];
        $this->dataHandler = new SecureDataHandler($secret_key, $salt);
        // $this->userlibrary = new UserLibrary();
        $this->environment = $_ENV['CI_ENVIRONMENT'];
        $this->enableEncryptDecryptInDevEnv = $_ENV['ENABLE_ECRYPT_DECRYPT_INDEV_ENV'];
        // echo $this->enableEncryptDecryptInDevEnv;
}

// ################## ENCRYPTION AND DECRYPTION FUNCTIONS ##################

// Not in use 
// use No where
// public function encryptRow($data,$columns)
// {
//     if($this->environment == 'development')
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


##################### END OF ENCRYPTION AND DECRYPTION FUNCTIONS ###########

public function checkUserIdExists($user_id)
{
        $q = "SELECT * FROM users WHERE `uid` ='{$user_id}'";
        $query = $this->db->query($q); 
        return $query->getRow();
}

public function registerUserData($data)
{
        $query = $this->db->table('users');
        return $query->insert($data);
}   
    
// Done encryption
public function getUserId($email)
{
        if($this->environment == 'development' && $this->enableEncryptDecryptInDevEnv=='false')
        {
                $q = "SELECT * FROM users WHERE email='{$email}'";
                $query = $this->db->query($q);  
                return $query->getRow()?$query->getRow()->uid:'';
        }

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

public function insertIntoAddressBook($data)
{
        $this->db->table('address_book')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID; 
}

public function insertIntoUserAddressMapper($data)
{
        $this->db->table('user_address_mapper')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID; 
}

public function insertUserAuthTemplateNames($data)
{
        $this->db->table('users_auth_template_names')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID;   
}

public function insertUserAuthTemplateLists($data)
{
        $this->db->table('users_auth_template_lists')
                 ->insertBatch($data);
}

public function get_users_auth_template_lists()
{
        $result = $this->db->table('users_auth_template_lists')  
                        ->get()
                        ->getResult();
        return $result;                                
}

public function getUsersAuthTemplatesData()
{
        $templateResult = $this->db->table('users_auth_template_names')
        ->select('users_auth_template_names.*,tl.id as tl_id,tl.code as tl_code,tl.template_code as tl_template_code,tl.main_menu_code as tl_main_menu_code,tl.sub_menu_code as tl_sub_menu_code,tl.level as tl_level,tl.created_on as tl_created_on,tl.updated_on as tl_updated_on,tl.is_deleted as tl_is_deleted,tl.created_by as tl_created_by,tl.updated_by as tl_updated_by,tl.reason_for_delete as tl_reason_for_delete,mm.name as tl_main_menu_name,ms.name as tl_sub_menu_name')
        ->join(' users_auth_template_lists as tl', ' users_auth_template_names.code = tl.template_code','left') 
        ->join(' menu_main_modules as mm', ' tl.main_menu_code = mm.code','left') 
        ->join(' menu_sub_modules as ms', ' tl.sub_menu_code = ms.code','left') 
        ->get()
        ->getResult(); 

        return $templateResult;  
}

public function getUsersListsData()
{
        $result = $this->db->table('users')  
        ->get()
        ->getResult();
        return $result; 
}


public function getTemplatesListData()
{
        $result = $this->db->table('users_auth_template_names')  
        ->get()
        ->getResult();
        return $result; 
}

public function getSingleTemplateData($templateCode)
{
        $templateResult = $this->db->table('users_auth_template_names')
        ->select('users_auth_template_names.*,tl.id as tl_id,tl.code as tl_code,tl.template_code as tl_template_code,tl.main_menu_code as tl_main_menu_code,tl.sub_menu_code as tl_sub_menu_code,tl.level as tl_level,tl.created_on as tl_created_on,tl.updated_on as tl_updated_on,tl.is_deleted as tl_is_deleted,tl.created_by as tl_created_by,tl.updated_by as tl_updated_by,tl.reason_for_delete as tl_reason_for_delete,mm.name as tl_main_menu_name,ms.name as tl_sub_menu_name')
        ->join(' users_auth_template_lists as tl', ' users_auth_template_names.code = tl.template_code','left') 
        ->join(' menu_main_modules as mm', ' tl.main_menu_code = mm.code','left') 
        ->join(' menu_sub_modules as ms', ' tl.sub_menu_code = ms.code','left') 
        ->where('users_auth_template_names.code',$templateCode)
        ->get()
        ->getResult(); 

        return $templateResult; 
}

public function checkUserExistsInUserAddressMapper($user_id)
{
        $result = $this->db->table('user_address_mapper') 
                        ->where('user_id',$user_id)
                        ->get()
                        ->getRow(); 
        if($result)
        {
             return 1;   
        }    
        else
        {
              return 0;    
        }
}

public function updateIntoAddressBook($data,$addressBookCode)
{
        $this->db->table('address_book')
        ->where('code',$addressBookCode)
        ->update($data); 
}

public function getAddressBookCode($userId)
{
        $result = $this->db->table('user_address_mapper') 
        ->where('user_id',$userId)
        ->get()
        ->getRow();
        return $result->addressbook_code;
}


public function insertMenuUserAuths($data)
{
        $this->db->table('menu_user_auths')
        ->insertBatch($data);   
        return true;  
}

public function getActiveUsersCount()
{
        $q = "SELECT count(*) FROM users WHERE `active`=1";
        $query = $this->db->query($q);
        $arr = (array)$query->getRow();
        $count = $arr['count(*)'];
        return $count;
}


public function getAddressBookListData()
{
        $result = $this->db->table('address_book')  
        ->get()
        ->getResult();
        return $result; 
}

public function getApiRequestTypeListData()
{
        $result = $this->db->table('api_request_type')  
        ->get()
        ->getResult();
        return $result; 
}



public function getMenuUserAuthsById($user_id)
{
        $result = $this->db->table('menu_user_auths')  
        ->where('user_id',$user_id)
        ->get()
        ->getResult();
        return $result; 
}

public function updateMutipleRecordsForMenuUserAuths($data)
{
        foreach($data as $key => $value)
        {
                $dataToUpdate = [];
                $dataToUpdate['level'] = $value['level'];
                $dataToUpdate['updated_by'] = $value['updated_by'];

                $query = $this->db->table('menu_user_auths');
                $query->where('user_id',$value['user_id']);
                $query->where('main_menu_code',$value['main_menu_code']);
                $query->where('sub_menu_code',$value['sub_menu_code']==''?'':$value['sub_menu_code']);
                $query->update($dataToUpdate); 
                // $sql = $query->getCompiledSelect();
                // print_r($sql);
        }

      return true;  
}


public function setMenuUserAuthsPermissions($insertData,$updateData)
{
        if(!empty($insertData))
        {
                $this->db->table('menu_user_auths')
                ->insertBatch($insertData);              
        }

        if(!empty($updateData))
        {
            $this->updateMutipleRecordsForMenuUserAuths($updateData);
        }

        return true;
}       


public function getDefaultMenuMainModules()
{
        $links = [];
        if($this->environment == 'development' && $this->enableEncryptDecryptInDevEnv=='false')
        {
           $links = ['main-dashboard.html','settings.html'];  
        }
        else
        {
                $links = [$this->dataHandler->encryptAndStore('main-dashboard.html'), $this->dataHandler->encryptAndStore('settings.html')];
        }
        
        $result = $this->db->table('menu_main_modules') 
        ->whereIn('link', $links)
        ->get()
        ->getResult();
        return $result; 
}

public function getApiByIdData($code)
{
        $result = $this->db->table('api_url_endpoints') 
        ->where('code',$code) 
        ->get()
        ->getRow();
        return $result; 
}

public function deleteApiData($code)
{
        $this->db->table('api_url_endpoints')
        ->where('code',$code)
        ->update(['is_deleted'=>1]); 
        return true;
}


public function getTotalApiCount()
{
        $q = "SELECT count(*) FROM api_url_endpoints";
        $query = $this->db->query($q);
        $arr = (array)$query->getRow();
        $count = $arr['count(*)'];
        return $count;
}

public function getDepreciatedApiCount()
{
        $q = "SELECT count(*) FROM api_url_endpoints where is_deleted=1";
        $query = $this->db->query($q);
        $arr = (array)$query->getRow();
        $count = $arr['count(*)'];
        return $count;
}

public function getVisualMetricData()
{
        $result = $this->db->table('visual_metrics') 
        ->get()
        ->getResult();
        return $result; 
}

// Not in use : 
// public function addLoginAttemptsHistory($email,$ipAddress,$userAgent,$isSuccess)
// {
//         $data = array(
//                 'login_user_id'=>$email,
//                 'ip_address'=>$ipAddress,
//                 'browser_details'=>$userAgent,
//                 'is_success'=>$isSuccess
//         );
//         $data = $this->encryptRow($data,['login_user_id']);
//         $query = $this->db->table('login_attempts_history');
//         return $query->insert($data);
// }


// Not in use but working method
// public function insertVisualMetricsMenuModules($data)
// {
//         $this->db->table('visual_metrics_menu_modules')
//         ->insertBatch($data);
//         return true;
// }

public function insertVisualMetricsMenuModules($data)
{
        $this->db->table('visual_metrics_menu_modules')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID;  
}


public function getVisualMetricsMenuModulesData($data)
{
        $result = $this->db->table(' visual_metrics_menu_modules') 
        ->where('user_id',$data['user_id'])
        ->where('menu_code',$data['menu_code'])
        ->get()
        ->getResult();
        return $result; 
}

public function getVisualMetricsData($visualCodeArray)
{
        $result = $this->db->table('visual_metrics') 
        ->whereIn('code', $visualCodeArray)
        ->get()
        ->getResult();
        return $result; 
}

public function getMainMenuListData()
{
        $result = $this->db->table('menu_main_modules') 
                        ->select("id,code,name")
                        ->get()
                        ->getResult();
        return $result; 
}


public function getUserByUid($userId)
{
        $result = $this->db->table('users') 
        ->where('uid',$userId)
        ->get()
        ->getRow();
        return $result;  
}

public function getUsersLastLoginAttemptsHistoryData($email)
{
        $result = $this->db->table('login_attempts_history') 
        ->where('login_user_id ',$email)
        ->orderBy('login_attempts_history.id','DESC')
        ->limit(5)
        ->get()
        ->getResult();
        return $result;
}


public function checkTableExist($table)
{
        $builder = $this->db->table('information_schema.tables');
        $builder->select('table_name');
        $builder->where('table_schema', $this->db->getDatabase());
        $builder->where('table_type', 'BASE TABLE');
        $query = $builder->get();

        $tables = $query->getResult();
        $tableArray = [];
        foreach($tables as $key => $value){
             array_push($tableArray,$value->table_name);
        }

        if(in_array($table,$tableArray)){
                return 1;
        }
        else{
                return 0;
        }
}


public function getHimalayaMasterDataCount()
{
        $count = 0;
        if($this->checkTableExist('raw_import_himalaya_master_data'))
        {
                $q = "SELECT count(*) FROM  raw_import_himalaya_master_data";
                $query = $this->db->query($q);
                $arr = (array)$query->getRow();
                $count = $arr['count(*)']; 
        }
       
        return $count;
}



public function getMenuMainModulesCount()
{
        $q = "SELECT count(*) FROM  menu_main_modules where is_deleted!=1";
        $query = $this->db->query($q);
        $arr = (array)$query->getRow();
        $count = $arr['count(*)'];
        return $count;  
}

public function getMenuUserAuthsCount($userId)
{
        $q = "SELECT count(*) FROM  menu_user_auths where user_id={$userId} and `level`>0";
        $query = $this->db->query($q);
        $arr = (array)$query->getRow();
        $count = $arr['count(*)'];
        return $count;   
}


public function getUserTypesList()
{
        $result = $this->db->table('user_types')
        ->select("id,code,short_name,remarks") 
        ->get()
        ->getResult();
        return $result;  
}


public function insertIntoUserAddressBookConnect($data)
{
        $this->db->table('address_book_connect')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID;  
}


public function getAllMenuMainModulesTableData()
{
        $result = $this->db->table('menu_main_modules')
        ->get()
        ->getResult();
        return $result; 
}

public function updateMenuMainModulesTableBatch($data)
{
        $this->db->table('menu_main_modules')
                 ->updateBatch($data, ['code']);
}

public function getAllMenuSubModulesTableData()
{
        $result = $this->db->table('menu_sub_modules')
        ->get()
        ->getResult();
        return $result; 
}

public function updateMenuSubModulesTableBatch($data)
{
        $this->db->table('menu_sub_modules')
        ->updateBatch($data, ['code']);
}

public function getAllUserTypesTableData()
{
        $result = $this->db->table('user_types')
        ->get()
        ->getResult();
        return $result; 
}

public function updateUserTypesTableBatch($data)
{
        $this->db->table('user_types')
        ->updateBatch($data, ['code']);
}

public function getAllVisualMetricsTableData()
{
        $result = $this->db->table('visual_metrics')
        ->get()
        ->getResult();
        return $result; 
}

public function updateVisualMetricsTableBatch($data)
{
        $this->db->table('visual_metrics')
        ->updateBatch($data, ['code']);  
}

public function getUserAuthsData($userId)
{
        $result = $this->db->table('menu_user_auths')
        ->select('menu_user_auths.*,mm.name as main_menu_name,sm.name as sub_menu_name')
        ->join('menu_main_modules as mm','menu_user_auths.main_menu_code=mm.code','left')
        ->join('menu_sub_modules as sm','menu_user_auths.sub_menu_code=sm.code','left')
        ->where('user_id',$userId)
        ->get()
        ->getResult();
        return $result;   
}



public function getVisualMetricsMenuModulesDataByUid($data)
{
        $result = $this->db->table('visual_metrics_menu_modules') 
         ->select('visual_metrics_menu_modules.*,u.username as user_name')
         ->join('users as u','visual_metrics_menu_modules.user_id=u.uid')
        ->where('user_id',$data['user_id'])
        ->get()
        ->getResult();
        return $result; 
}

public function checkMenuCodeExistsForVisualCode($userId,$visualCode,$mainMenuCode)
{
        $result = $this->db->table(' visual_metrics_menu_modules') 
        ->where('user_id',$userId)
        ->where('visual_code',$visualCode)
        ->where('menu_code',$mainMenuCode)
        ->get()
        ->getRow();
        if($result){
                return true;
        }
        else{
                return false;
        }
}

public function changeUsersVisualMetricStatus($userId,$menuCode,$analyticalCode,$data)
{
         $this->db->table('visual_metrics_menu_modules')
        ->where('user_id', $userId)
        ->where('menu_code', $menuCode)
        ->where('visual_code', $analyticalCode)
        ->update($data);
        return true; 
}

public function insertIntoProjects($data)
{
        $this->db->table('projects')
                   ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID; 
}

public function updateIntoProjects($projectCode,$data)
{
        $id = $this->db->table('projects')
        ->where('code', $projectCode)
        ->update($data);
        return $id; 
}

public function checkProjectExists($projectName)
{
        $result = $this->db->table('projects')
        ->where('name', $projectName)
        ->get()
        ->getRow();
        if($result)
        {
                return true;
        }
        else
        {
                return false;
        }
}


public function insertIntoUserProjAccessToken($data)
{
        $this->db->table('user_proj_access_token')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID; 
}

public function checkUserAccessTokenExistsForProject($userId,$projectId)
{
      $result = $this->db->table('user_proj_access_token')
        ->where('user_id', $userId)
        ->where('project_code', $projectId)
        ->get()
        ->getRow();
         
     if($result)
     {
        return true;
     }          
     else{
         return false;
     }
}

public function getProjectExpiryDate($projectId)
{
        $result = $this->db->table('projects')
        ->where('code', $projectId)
        ->get()
        ->getRow();
        return $result;
}



public function getAllProjectsList()
{
        $result = $this->db->table('projects')  
        ->get()
        ->getResult();
        return $result; 
}


public function checkProjectAccessKeyExists($projectCode)
{
        $result = $this->db->table('projects')  
        ->where('code',$projectCode)
        ->get()
        ->getRow();
        if($result->access_token==''){
                return false;
        }
        else{
                return true;
        }
}


public function getUserProjAccessTokenData($userId,$projectCode)
{
        $result = $this->db->table('user_proj_access_token') 
        ->where('user_id',$userId) 
        ->where('project_code',$projectCode)
        ->get()
        ->getRow();
       return $result;
}

public function insertIntoUserMapperApis($data)
{
        $this->db->table('user_mapper_apis')
        ->insert($data);
        $insertedID = $this->db->insertID();
        return $insertedID;
}

public function checkApiAlreadyAssigned($userProjAccessTokenCode,$apiCode)
{
        $result = $this->db->table('user_mapper_apis') 
        ->where('user_mapper_api_code',$userProjAccessTokenCode) 
        ->where('api_code',$apiCode)
        ->get()
        ->getRow();
        if($result){
                return true;
        }
        else{
                return false;   
        }
}


public function validateProjectAccessKey($projectAccessKey)
{
        $result = $this->db->table('projects')  
        ->where('access_token',$projectAccessKey)
        ->get()
        ->getRow();
       return $result;
}

public function getAllUsersAccessKeysForProject($projectCode)
{
        $result = $this->db->table('user_proj_access_token')  
        ->where('project_code',$projectCode)
        ->get()
        ->getResult();
       return $result;
}


public function getUserIdByTokenFromUsersSessionTokens($token)
{
        $result = $this->db->table('users_session_tokens')  
        ->where('token',$token)
        ->get()
        ->getRow();
        return $result; 
}

public function getUserIdByTokenFromUserProjAccessToken($token)
{
        $result = $this->db->table('user_proj_access_token')  
        ->where('access_token',$token)
        ->get()
        ->getRow();
        return $result; 
}



public function getAccessKeyUsersList()
{
        $result = $this->db->table('user_proj_access_token')  
        ->get()
        ->getResult();
        return $result; 
}

public function getUsersByIds($usersArray)
{
        $result = $this->db->table('users')  
        ->whereIn('uid',$usersArray)
        ->get()
        ->getResult();
        return $result;   
}

public function getApiList()
{
        $result = $this->db->table('api_url_endpoints')  
        ->get()
        ->getResult();
        return $result;  
}



############################ TESTING AREA #########################################


public function filteredUserExists($email)
{
        $result = $this->db->table('users')
                 ->where('email',$email)
                 ->get()
                 ->getRow();

        if($result){
                return true;
        }        
        else{
                return false;
        }
}



// #################### FOR ENCRYPTION AND DECRYPTION OD TABLES ##############


public function getAllUsersTableData()
{
        $result = $this->db->table('users')->get()->getResult();
        return $result; 
}

public function updateUsersTableBatch($data)
{
        $this->db->table('users')->updateBatch($data, ['uid']);   
}

###############################
public function getAddressBookTableData()
{
        $result = $this->db->table('address_book')->get()->getResult();
        return $result; 
}

public function updateAddressBookTableBatch($data)
{
        $this->db->table('address_book')->updateBatch($data, ['code']); 
}

#######################

public function getAddressBookConnectTableData()
{
        $result = $this->db->table('address_book_connect')->get()->getResult();
        return $result; 
}

public function updateAddressBookConnectTableBatch($data)
{
        $this->db->table('address_book_connect')->updateBatch($data, ['code']); 
}
// #########################


public function getApiRequestTypeTableData()
{
        $result = $this->db->table('api_request_type')->get()->getResult();
        return $result; 
}

public function updateApiRequestTypeTableBatch($data)
{
        $this->db->table('api_request_type')->updateBatch($data, ['code']); 
}

###########################

public function getApiUrlEndpointsTableData()
{
        $result = $this->db->table('api_url_endpoints')->get()->getResult();
        return $result; 
}

public function updateApiUrlEndpointsTableBatch($data)
{
        $this->db->table('api_url_endpoints')->updateBatch($data, ['code']); 
}

###########################


public function getLoginAttemptsHistoryTableData()
{
        $result = $this->db->table('login_attempts_history')->get()->getResult();
        return $result; 
}

public function updateLoginAttemptsHistoryTableBatch($data)
{
        $this->db->table('login_attempts_history')->updateBatch($data, ['id']); 
}

##################################


public function getUsersAuthTemplateNamesTableData()
{
        $result = $this->db->table('users_auth_template_names')->get()->getResult();
        return $result; 
}

public function updateUsersAuthTemplateNamesTableBatch($data)
{
        $this->db->table('users_auth_template_names')->updateBatch($data, ['code']); 
}

###################################

public function getUsersLoginHistoryTableData()
{
        $result = $this->db->table('users_log_history')->get()->getResult();
        return $result; 
}


public function updateUsersLoginHistoryTableBatch($data)
{
        $this->db->table('users_log_history')->updateBatch($data, ['id']); 
}

########################

public function getUsersOtpTableData()
{
        $result = $this->db->table('users_otp')->get()->getResult();
        return $result; 
}

public function updateUsersOtpTableBatch($data)
{
        $this->db->table('users_otp')->updateBatch($data, ['id']); 
}

#######################


public function getUserProfileChangeHistoryTableData()
{
        $result = $this->db->table('user_profile_change_history')->get()->getResult();
        return $result; 
}

public function updateUserProfileChangeHistoryTableBatch($data)
{
        $this->db->table('user_profile_change_history')->updateBatch($data, ['code']); 
}


}
