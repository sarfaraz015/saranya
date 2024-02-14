<?php

use CodeIgniter\Router\RouteCollection;
use App\Controllers\UserController;

/**
 * @var RouteCollection $routes
 */
// $routes->get('/', 'Home::index');

$routes->get('/', 'UserController::index');

$routes->get('/test', 'UserController::test');

$routes->post('/register', 'UserController::register');

$routes->post('/login', 'UserController::login');

$routes->get('/logout', 'UserController::logout');

$routes->get('/get_user_data', 'UserController::get_user_data');

$routes->get('/testcode', 'UserController::testcode');

$routes->get('/blockUserMessage', 'UserController::blockUserMessage');

$routes->get('/testMessage', 'UserController::testMessage');

$routes->post('/forgot_password', 'UserController::forgot_password');

$routes->post('/reset_password', 'UserController::reset_password');

$routes->get('/otp_time_out', 'UserController::otp_time_out');
