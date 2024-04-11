<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Services;
use App\Libraries\UserLibrary;

class LoginFilter implements FilterInterface
{
    public $userlibrary;
    public function __construct()
    {
           $this->userlibrary = new UserLibrary();
    }

    public function before(RequestInterface $request, $arguments = null)
    {
        $validator = Services::validation();
        $rules = [
            'email'=>'required|valid_email',
            'password'=>'required'
        ];

        $json_data = $request->getJSON();
        $data = [
            'email' => $json_data->email, 
            'password' => $json_data->password 
        ];

        $validator->setRules($rules);

        if (!$validator->run($data)) {
            $response = [
                'message' => $validator->getErrors(),
                'response' => false,
                'code' => 401,
                'result_data' => [],
                'return_data' => $data
            ];
            return Services::response()->setJSON($response)->setStatusCode(401);
        }

        // echo "checking for user exists";die;
        $userStatus = $this->userlibrary->filteredUserExists($json_data->email);
        
        if(!$userStatus)
        {
            return Services::response()->setJSON(['message'=>'User already exists in the database'])->setStatusCode(401);
        }


        return $request;
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
       
       
    }
}
