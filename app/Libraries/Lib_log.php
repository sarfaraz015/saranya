<?php
namespace App\Libraries;

class Lib_log 
{
    public $levels = array(
        E_ERROR             => 'Error',
        E_WARNING           => 'Warning',
        E_PARSE             => 'Parsing Error',
        E_NOTICE            => 'Notice',
        E_CORE_ERROR        => 'Core Error',
        E_CORE_WARNING      => 'Core Warning',
        E_COMPILE_ERROR     => 'Compile Error',
        E_COMPILE_WARNING   => 'Compile Warning',
        E_USER_ERROR        => 'User Error',
        E_USER_WARNING      => 'User Warning',
        E_USER_NOTICE       => 'User Notice',
        E_STRICT            => 'Runtime Notice',
        E_RECOVERABLE_ERROR => 'Catchable error',
        E_DEPRECATED        => 'Runtime Notice',
        E_USER_DEPRECATED   => 'User Warning'
    );

    public $dbmodel;
    public function __construct()
    {
        $this->dbmodel = \Config\Database::connect();

        set_error_handler(array($this, 'error_handler'));
        set_exception_handler(array($this, 'exception_handler'));
    }

    public function error_handler($severity, $message, $filepath, $line)
    {
        $data = array(
            'errno' => $severity,
            'errtype' => isset($this->levels[$severity]) ? $this->levels[$severity] : $severity,
            'errstr' => $message,
            'errfile' => $filepath,
            'errline' => $line,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'time' => date('Y-m-d H:i:s')
        );

        $this->dbmodel->table('error_logs')->insert($data); 
    }

    public function exception_handler($exception)
    {
        $data = array(
            'errno' => $exception->getCode(),
            'errtype' => isset($this->levels[$exception->getCode()]) ? $this->levels[$exception->getCode()] : $exception->getCode(),
            'errstr' => $exception->getMessage(),
            'errfile' => $exception->getFile(),
            'errline' => $exception->getLine(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'time' => date('Y-m-d H:i:s')
        );
        $this->dbmodel->table('error_logs')->insert($data);
    }
}
