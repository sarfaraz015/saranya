<?php


namespace Config;


use CodeIgniter\Config\BaseConfig;


class Email extends BaseConfig
{
    public string $fromEmail  = 'lambdainfinity.sk015@gmail.com';
    public string $fromName   = 'Lambda Infinity';
    public string $recipients = '';


    public string $userAgent = 'CodeIgniter';
    public string $protocol = 'smtp';
    public string $mailPath = '/usr/sbin/sendmail';
    public string $SMTPHost = 'smtp.gmail.com';
    public string $SMTPUser = 'lambdainfinity.sk015@gmail.com';
    public string $SMTPPass = 'ewtyuxnovafcefro';
    public int $SMTPPort = 25;
    public int $SMTPTimeout = 60;
    public bool $SMTPKeepAlive = false;
    public string $SMTPCrypto = 'tls';
    public bool $wordWrap = true;
    public int $wrapChars = 76;
    public string $mailType = 'html';
    public string $charset = 'UTF-8';
    public bool $validate = false;
    public int $priority = 3;
    public string $CRLF = "\r\n";
    public string $newline = "\r\n";
    public bool $BCCBatchMode = false;
    public int $BCCBatchSize = 200;
    public bool $DSN = false;


// public string $fromEmail = 'lambdainfinity.sk015@gmail.com';
// public string $fromName = 'Lambda Infinity';
// public string $SMTPHost = 'smtp.gmail.com';
// public string $SMTPUser = 'lambdainfinity.sk015@gmail.com';
// public string $SMTPPass = 'ewtyuxnovafcefro';
// public int $SMTPPort = 465;
// public string $SMTPCrypto = 'tls';
}
