<?php 
// echo "Migartions file is running";
Class Migartions {

        public $successColor = "\033[0;32m"; 
        public $errorColor = "\033[0;31m"; 
        public $resetColor = "\033[0m"; 

        public function checkFileExistTest()
        {
                // valid path
                // $file = __DIR__.DIRECTORY_SEPARATOR.'composer.json';

                // valid path
                // $file = __DIR__.DIRECTORY_SEPARATOR.'.env2';
                $file = __DIR__.DIRECTORY_SEPARATOR.'public'.DIRECTORY_SEPARATOR.'index.php';

                        if (file_exists($file)){
                        echo $this->successColor . "The file {$file} exists" . $this->resetColor . PHP_EOL;
                        } else {
                        echo $this->errorColor . "The file {$file} does not exists" . $this->resetColor . PHP_EOL;
                        }
            
        }
      
       public function checkFolderPermissionsTest()
       {
          $folderPath = __DIR__.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'MyImages';

                if (file_exists($folderPath)){
                    chmod($folderPath, 0777);       
                echo $this->successColor . "The folder {$folderPath} permisssions changes to 0777 successfully" . $this->resetColor . PHP_EOL;
                } else {
                echo $this->errorColor . "The folder {$folderPath} does not exists" . $this->resetColor . PHP_EOL;
                }
       }


       public function checkFilesExist($fileArray)
       {
            $flag = true;
                foreach($fileArray as $key => $file)
                {
                        if(file_exists($file))
                        {
                             echo $this->successColor . "The file {$file} exists" . $this->resetColor . PHP_EOL;
                        } 
                        else
                        {
                             echo $this->errorColor . "The file {$file} does not exists" . $this->resetColor . PHP_EOL;
                              $flag = false;
                        }
                }
            return $flag;    
       }

       public function grantFoldersAccess($folderArray)
       {
                $flag = true;
                foreach($folderArray as $key => $folder)
                {
                        if(file_exists($folder))
                        {
                            chmod($folder, 0777); 
                            echo $this->successColor . "For folder {$folder} 0777 permission added succesfully" . $this->resetColor . PHP_EOL;
                        } 
                        else
                        {
                            echo $this->errorColor . "The folder {$folder} does not exists" . $this->resetColor . PHP_EOL;
                            $flag = false;
                        }
                }
                return $flag; 
       }


    //    NOT IN USE 
    //    public function runMigrationCommandToCreateTables()
    //    {
    //         $directory =  __DIR__;
    //         $command = 'php spark migrate'; 
            
    //         exec($command, $output, $returnVar);
    //         echo "Output:\n" . implode("\n", $output) . "\n";
    //         echo "Return code: $returnVar\n";

    //    }

    public function connection()
    {
        // $hostname = "mnserviceproviders.com";
        // $username = "usr_local_invoiceflow";
        // $password = "b5^^9o-gS6*n";
        // $database = "meramerchant_sf01";
        // $port = '3307';

        $hostname = "mnserviceproviders.com";
        $username = "build_usr_mminvoice_flow";
        $password = "0945m^FJiL";
        $database = "build_mminvoice_flow";
        $port = '3307';

            $conn = new mysqli($hostname, $username, $password, $database,$port);
            if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
            }
        return $conn;
    }

    public function updateMigratedTables($sqlArray)
    {
            $conn = $this->connection();
            $flag = true;
            if($conn){

                foreach($sqlArray as $key => $sql){
                    if ($conn->query($sql) === TRUE) {
                        echo $this->successColor . "{$sql} executed succesfully" . $this->resetColor . PHP_EOL;
                    } 
                    else {
                        $flag = false;
                        echo "Error creating table: " . $conn->error;
                    }
                }

                $conn->close();
            }

            return $flag;
    }


       public function runMigrations($fileArray,$folderArray,$sqlArray)
       {
            $flag = true;

            if($flag){
                $flag = $this->checkFilesExist($fileArray);
            }

            if($flag){
                $flag = $this->grantFoldersAccess($folderArray);
            }

            if($flag){
                $flag = $this->updateMigratedTables($sqlArray);
            }

            if($flag){
                echo $this->successColor . "Migrations.php executed successfully" . $this->resetColor . PHP_EOL;
            }


       }
       


}

$migartions = new Migartions();

$fileArray = [
        __DIR__.DIRECTORY_SEPARATOR.'composer.json',
        __DIR__.DIRECTORY_SEPARATOR.'.env',
];


$folderArray = [
    __DIR__.DIRECTORY_SEPARATOR.'app'.DIRECTORY_SEPARATOR.'MyImages',
];


$sqlArray = [

    "ALTER TABLE `users`
    ADD UNIQUE KEY `users_email_uniq` (`email`) USING BTREE,
    ADD UNIQUE KEY `users_uid_uniq` (`uid`) USING BTREE,
    ADD UNIQUE KEY `activation_selector` (`activation_selector`),
    ADD UNIQUE KEY `forgotten_password_selector` (`forgotten_password_selector`),
    ADD UNIQUE KEY `remember_selector` (`remember_selector`),
    ADD KEY `users_updated_by_ind` (`updated_by`) USING BTREE,
    ADD KEY `users_created_by_ind` (`created_by`) USING BTREE,
    ADD KEY `users_username_ind` (`username`) USING BTREE",

    "ALTER TABLE `users_session_tokens`
    ADD UNIQUE KEY `users_session_tokens_uid_uniq` (`uid`) USING BTREE,
    ADD UNIQUE KEY `users_session_tokens_token_uniq` (`token`) USING BTREE,
    ADD KEY `users_session_tokens_created_by_ind` (`created_by`) USING BTREE,
    ADD KEY `users_session_tokens_updated_by_ind` (`updated_by`) USING BTREE,
    ADD KEY `users_session_tokens_uid_ind` (`uid`) USING BTREE",

    "ALTER TABLE `users_otp`
    ADD KEY `users_otp_uid_ind` (`uid`) USING BTREE,
    ADD KEY `users_otp_email_ind` (`email`) USING BTREE,
    ADD KEY `users_otp_created_by_ind` (`created_by`) USING BTREE,
    ADD KEY `users_otp_updated_by_ind` (`updated_by`) USING BTREE",

    "ALTER TABLE `users_log_history`
    ADD KEY `users_log_history_uid_ind` (`uid`) USING BTREE,
    ADD KEY `users_log_history_called_api_ind` (`called_api`) USING BTREE,
    ADD KEY `users_log_history_called_method_ind` (`called_method`) USING BTREE,
    ADD KEY `users_log_history_called_class_ind` (`called_class`) USING BTREE",

    "ALTER TABLE `api_concurrent_request_log`
    ADD KEY `api_logs_user_id_ind` (`user_id`) USING BTREE,
    ADD KEY `api_logs_api_url_ind` (`api_url`) USING BTREE",

"ALTER TABLE `users` CHANGE `updated_on` `updated_on` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",

"ALTER TABLE `users_session_tokens` CHANGE `updated_on` `updated_on` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",

"ALTER TABLE `users_otp` CHANGE `updated_on` `updated_on` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",

"ALTER TABLE `users_otp` CHANGE `updated_on` `updated_on` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",

"ALTER TABLE `users_log_history` CHANGE `updated_on` `updated_on` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",

"ALTER TABLE `api_concurrent_request_log` CHANGE `updated_on` `updated_on` TIMESTAMP on update CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",



];


$migartions->runMigrations($fileArray,$folderArray,$sqlArray);


// $migartions->updateMigratedTables($sqlArray);

// $migartions->runMigrationCommandToCreateTables();
// $migartions->checkFolderPermissions();
// $migartions->checkFilePermissions();


// $migartions->checkFileExistTest();




?>