<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\I18n\Time;

class TestController extends BaseController
{
    public function datetime()
    {
        //    echo 'datetime';die;
        // helper('date');
        // echo now();
    
        
    
        $myTime = new Time('+3 week');
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

        // die;
    }
}
