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
                $file = __DIR__.DIRECTORY_SEPARATOR.'.env2';

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
                        if (file_exists($file))
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


       public function runMigrations($fileArray)
       {
            $flag = true;

            if($flag){
                $flag = $this->checkFilesExist($fileArray);
            }

            if($flag){
                echo $this->successColor . "Proceed further" . $this->resetColor . PHP_EOL;
            }


       }
       





}

$migartions = new Migartions();

$fileArray = [
        __DIR__.DIRECTORY_SEPARATOR.'composer.json',
        __DIR__.DIRECTORY_SEPARATOR.'.env2',
];



$migartions->runMigrations($fileArray);




// $migartions->checkFolderPermissions();

// $migartions->checkFilePermissions();

// $migartions->checkFileExist();




?>