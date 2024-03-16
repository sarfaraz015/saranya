<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\I18n\Time;
// use CodeIgniter\Files\File;

class TestController extends BaseController
{

    public function __construct(){
        helper("filesystem");
        // echo "From test controller";
    }



    public function datetime()
    {
        //    echo 'datetime';die;
        // helper('date');
        // echo now();
    
        
    
        // $myTime = new Time('+3 week');
        // echo $myTime;

        // $myTime = new Time();
        // echo $myTime;
        // $myTime = new Time('now', 'Asia/Kolkata', 'en_US');
        // $myTime = Time::now('Asia/Kolkata', 'en_US');

        // $myTime = Time::parse('next Tuesday', 'Asia/Kolkata', 'en_US');

        // $myTime = Time::today('Asia/Kolkata', 'en_US');

        // $myTime = Time::yesterday('America/Chicago', 'en_US');

        // $myTime = Time::tomorrow('Asia/Kolkata', 'en_US');

        // $today = Time::createFromDate(); 
        // echo $today;

        // $anniversary = Time::createFromDate(2018); 
        // echo $anniversary;

        // $date = Time::createFromDate(2018, 3, 15, 'America/Chicago', 'en_US');
        // echo $date;

        // $dinner = Time::createFromTime(18, 00, 00);
        // echo $dinner;

        // $time = Time::createFromFormat('j-M-Y', '15-Feb-2009', 'Asia/Kolkata');
       

        // $time = Time::createFromTimestamp(1709373428, 'Asia/Kolkata', 'en_US');
        //  echo $time;

      

        // $time = Time::parse('January 10, 2017 21:50:00', 'Asia/Kolkata');

        // echo $time;

        $time = Time::createFromTimestamp(1710213495, 'Asia/Kolkata', 'en_US');
        echo $time;
          die;
    }


   public function test_files()
   {
       

        $filePath = APPPATH.'.htaccess'; //working
        // $filePath = APPPATH.'..\composer.json';  //working
        // $filePath = APPPATH.'..\.env';  //working

        // echo $filePath;die;

        if (file_exists($filePath)) {
            echo 'The file exists.';
        } else {
            echo 'The file does not exist.';
        }

    die;
   }


  public function set_folder_permission_for_windows()
  {
   
    $folderPath = APPPATH.'MyChapters'; // Replace with your actual folder path

// Set read-only permissions using icacls command
    $command = "icacls \"$folderPath\" /inheritance:r /grant:r everyone:(OI)(CI)R";

    $output = null;
    $returnCode = null;
    exec($command, $output, $returnCode);

    if ($returnCode === 0) {
        echo 'Folder permissions set to read-only successfully.';
    } else {
        echo 'Failed to set folder permissions.';

        // Output additional information for debugging if needed
        echo '<pre>';
        print_r($output);
        echo '</pre>';
    }

die;

  }



public function grant_write_permission_to_folder_for_windows()
{
    // $folderPath = 'C:\\path\\to\\your\\folder'; // Replace with your actual folder path
    $folderPath = APPPATH.'MyPic';

    // Set write permissions using icacls command
    $command = "icacls \"$folderPath\" /inheritance:r /grant:r everyone:(OI)(CI)W";
    
    $output = null;
    $returnCode = null;
    exec($command, $output, $returnCode);
    
    if ($returnCode === 0) {
        echo 'Folder permissions set to write successfully.';
    } else {
        echo 'Failed to set folder permissions.';
    
        // Output additional information for debugging if needed
        echo '<pre>';
        print_r($output);
        echo '</pre>';
    }

    die;
}



public function read_write()
{
     $data = 'Some file data one file';
     // $filePath = APPPATH.'MyImg/fifth.txt';
     $filePath = APPPATH.'MyChapters2/one.txt';

         if (!write_file($filePath, $data)) {
             echo 'Unable to write the file';
         } else {
             echo 'File written!';
         }

  die;

}


public function set_folder_permission_php()
{
 
  $folderPath = APPPATH.'MyChapters2/one.txt'; 

//   $permissions = 0644; 

//   if (chmod($folderPath, $permissions)) {
//     //   mkdir($folderPath);
//     mkdir($folderPath, $permissions);
//       echo 'Folder permissions set to read-only successfully.';
//   } else {
//       echo 'Failed to set folder permissions.';
//   }

// if (!file_exists($folderPath) ) {
//     mkdir($folderPath);

//     if (chmod($folderPath, 0444)) {
//         echo 'Folder permissions set to 0444 successfully.';
//     } else {
//         echo 'Failed to set folder permissions.';
//     }
// }


die;

}



public function grant_write_permission_to_folder_php()
{
//    echo 'grant_write_permission_to_folder_php';die;

        $folderPath = APPPATH.'MyChapters';
        // $folderPath = 'path/to/your/folder'; // Replace with your actual folder path
        $permissions = 0777; // Read-only permissions for owner, group, and others
        // echo $folderPath;die;
        // Set folder permissions
        if (chmod($folderPath, $permissions)) {
            echo 'Folder permissions set to read-only successfully.';
        } else {
            echo 'Failed to set folder permissions.';
        }

      die;
}


public function set_permissions_for_file()
{
    // ############### set read permission (working code) ################

    // $file = APPPATH.'MyChapters2/test'; 
    // if (chmod($file, 0444)) {
    //     echo 'Folder permissions set to 0444 successfully.';
    // } else {
    //     echo 'Failed to set folder permissions.';
    // }

    ################ write in file (working code)##############

    // $data = 'Some file data one file';
    // $filePath = APPPATH.'MyChapters2/three.txt';

    //     if (!write_file($filePath, $data)) {
    //         echo 'Unable to write the file';
    //     } else {
    //         echo 'File written!';
    //     }


//#############(working code) Set full permissions (read, write, execute) for owner, group, and others #####
    $file = APPPATH.'MyChapters2/test'; 
    if (chmod($file, 0777)) {
        echo 'Folder permissions set to 0777 successfully.';
    } else {
        echo 'Failed to set folder permissions.';
    }

    die;

}


public function set_permissions_for_folder()
{
    $folderPath = APPPATH.'MyChapters2';

    chmod($folderPath, 0444);    
    echo "Folder permissions set to read-only for: $folderPath";
    die;
}

public function testBaseUrl()
{
    //  echo "testBaseUrl";die;
    helper('url');
    $baseUrl = base_url();
// echo " / From controller / :".$baseUrl;
    // echo SYSTEMPATH;
    echo " ############## ";
    // echo FCPATH;
    // echo ROOTPATH;

    echo "myfunction";
    die;

}





}
