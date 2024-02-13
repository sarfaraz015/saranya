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
