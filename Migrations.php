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


       public function runMigrationCommandToCreateTables()
       {
            $directory =  __DIR__;
            $command = 'php spark migrate'; 
            
            exec($command, $output, $returnVar);
            echo "Output:\n" . implode("\n", $output) . "\n";
            echo "Return code: $returnVar\n";

       }



       public function runMigrations($fileArray,$folderArray)
       {
            $flag = true;

            if($flag){
                $flag = $this->checkFilesExist($fileArray);
            }

            if($flag){
                $flag = $this->grantFoldersAccess($folderArray);
            }

            if($flag){
                $this->runMigrationCommandToCreateTables();
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



$migartions->runMigrations($fileArray,$folderArray);



// $migartions->runMigrationCommandToCreateTables();
// $migartions->checkFolderPermissions();
// $migartions->checkFilePermissions();
// $migartions->checkFileExist();




?>