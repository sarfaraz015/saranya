<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use App\Libraries\UserLibrary;
use Config\Services;

class ValidateUserAuthentication implements FilterInterface
{
     public $userlibrary;
     public function __construct()
     {
            $this->userlibrary = new UserLibrary();
     }

    public function before(RequestInterface $request, $arguments = null)
    {
        $successFlag = false;
        $response = [];
        $projectAccessKeyHeader = $request->getHeader('projectAccessKey');
        $userAccessKeyHeader = $request->getHeader('userAccessKey');

        $tokenHeader = $request->getHeader('token');


        if($projectAccessKeyHeader || $userAccessKeyHeader)
        {
            // echo "Check Access keys";

            if($projectAccessKeyHeader && $userAccessKeyHeader)
            {
                if($projectAccessKeyHeader->getValue()=='')
                {
                  $response['message'] = "Project access key is blank";
                  $response['code'] = 401;
                  $response['response'] = false;
                  $response['result_data'] = [];
                  $response['return_data'] = [];
                }
                else if($userAccessKeyHeader->getValue()=='')
                {
                  $response['message'] = "User access key is blank";
                  $response['code'] = 401;
                  $response['response'] = false;
                  $response['result_data'] = [];
                  $response['return_data'] = [];
                }
                else
                { 
                       $resultData = $this->userlibrary->validateAccessKeys($projectAccessKeyHeader->getValue(),$userAccessKeyHeader->getValue());
  
                       if($resultData['response'])
                       {
                          // Success
                          $response['message'] = $resultData['message'];
                          $response['code'] = $resultData['code'];
                          $response['response'] = $resultData['response'];
                          $response['result_data'] = $resultData['result_data'];
                          $response['return_data'] = $resultData['result_data'];
                          $successFlag = true;
                       }
                       else
                       {
                          $response['message'] = $resultData['message'];
                          $response['code'] = $resultData['code'];
                          $response['response'] = $resultData['response'];
                          $response['result_data'] = $resultData['result_data'];
                          $response['return_data'] = $resultData['result_data'];
                       }
                }
            }
            else
            {
                $response['message'] = "Please provide both Project and User access keys or access only with token";
                $response['code'] = 401;
                $response['response'] = false;
                $response['result_data'] = [];
                $response['return_data'] = [];
            }
           
             
        }
        else if($tokenHeader)
        {
            // echo "Validate normal user token";

            if($tokenHeader->getValue()=='')
            {
              $response['message'] = "Token is blank";
              $response['code'] = 401;
              $response['response'] = false;
              $response['result_data'] = [];
              $response['return_data'] = [];
            }
            else
            {
                // echo "Proceed Token";die;
                $tokenResult = $this->userlibrary->verifyTokenIsValid($tokenHeader->getValue());
                if($tokenResult)
                {
                    $response['message'] = "Token verified successfully";
                    $response['code'] = 200;
                    $response['response'] = true;
                    $response['result_data'] = [];
                    $response['return_data'] = [];
                    $successFlag = true;
                }
                else
                {
                    $response['message'] = "Invalid token";
                    $response['code'] = 401;
                    $response['response'] = false;
                    $response['result_data'] = [];
                    $response['return_data'] = [];
                }
            }
        }
        else
        {
            $response['message'] = "No token found";
            $response['code'] = 401;
            $response['response'] = false;
            $response['result_data'] = [];
            $response['return_data'] = [];
        }

        if($successFlag)
        {
            return $request;
        }
        else
        {
            $finalResponse = $this->userlibrary->generateResponse($response);
            return Services::response()->setJSON($finalResponse);
        }

        // return $request;
       
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other after filters, short of
     * throwing an Exception or Error.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param array|null        $arguments
     *
     * @return ResponseInterface|void
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        return $response;
    }
}
