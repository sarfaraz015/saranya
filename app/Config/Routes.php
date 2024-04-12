<?php

use CodeIgniter\Router\RouteCollection;
use App\Controllers\UserController;
use App\Controllers\TestController;
use App\Controllers\ApiController;

/**
 * @var RouteCollection $routes
 */
// $routes->get('/', 'Home::index');

// echo "app-routes.php / ";

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
$routes->post('/generate_tester_token', 'UserController::generate_tester_token');
$routes->get('/storeLogs', 'UserController::storeLogs');
$routes->get('/contactLog', 'UserController::contactLog');
$routes->get('/aboutLog', 'UserController::aboutLog');
$routes->get('/settingLog', 'UserController::settingLog');
$routes->get('/testingCode', 'UserController::testingCode');
$routes->get('/testapi', 'UserController::testapi');
// $routes->post('/datetime', 'UserController::datetime');
$routes->get('/dashboard', 'UserController::dashboard');
$routes->get('/about', 'UserController::about');
$routes->get('/contact', 'UserController::contact');
$routes->get('/chekApiHitTimings', 'UserController::chekApiHitTimings');

$routes->post('/get_all_users', 'UserController::get_all_users');
$routes->post('/update_user', 'UserController::update_user');
$routes->post('/test_get_users', 'UserController::test_get_users');

// $routes->post('/get_all_filtered_users', 'UserController::get_all_filtered_users');
$routes->get('/checkQueryBuilder', 'UserController::checkQueryBuilder');
$routes->get('/getAllUsersForTest', 'UserController::getAllUsersForTest');

$routes->post('/get_main_menu', 'UserController::get_main_menu');
$routes->post('/get_main_menu_for_test', 'UserController::get_main_menu_for_test');
$routes->post('/upload_user_profile_img', 'UserController::upload_user_profile_img');
$routes->post('/get_user_profile_img', 'UserController::get_user_profile_img');
$routes->post('/create_user', 'UserController::create_user');
$routes->post('/create_auth_templete', 'UserController::create_auth_templete');
$routes->get('/get_all_users_auth_templates', 'UserController::get_all_users_auth_templates');
$routes->post('/get_main_menu_auth', 'UserController::get_main_menu_auth');
$routes->get('/get_users_list', 'UserController::get_users_list');
$routes->get('/get_templates_list', 'UserController::get_templates_list');
$routes->post('/get_template', 'UserController::get_template');
$routes->post('/save_user_menu_authentication', 'UserController::save_user_menu_authentication');
$routes->get('/get_active_users', 'UserController::get_active_users');

$routes->get('/get_all_visual_metrics', 'UserController::get_all_visual_metrics');
$routes->post('/update_user_analyticals', 'UserController::update_user_analyticals');
$routes->post('/get_user_analytical_view', 'UserController::get_user_analytical_view');
$routes->get('/get_main_menu_list', 'UserController::get_main_menu_list');
$routes->get('/get_user_dashboard', 'UserController::get_user_dashboard');
$routes->get('/get_himalaya_master_data_count', 'UserController::get_himalaya_master_data_count');
$routes->get('/get_user_types_list', 'UserController::get_user_types_list');
$routes->post('/get_user_auths', 'UserController::get_user_auths');
$routes->post('/get_user_all_analytical_views', 'UserController::get_user_all_analytical_views');
$routes->post('/change_users_visual_metric_status', 'UserController::change_users_visual_metric_status');

$routes->post('/generate_project_access_key', 'UserController::generate_project_access_key');
$routes->post('/generate_user_access_key', 'UserController::generate_user_access_key');
$routes->get('/get_all_projects_list', 'UserController::get_all_projects_list');

$routes->post('/create_project', 'UserController::create_project');

$routes->post('/user_assign_api', 'UserController::user_assign_api');

// #################### ApiController ###################

$routes->get('/testApiController', 'ApiController::testApiController');
$routes->post('/create_api', 'ApiController::create_api');
$routes->post('/get_all_apis', 'ApiController::get_all_apis');
$routes->post('/update_api', 'ApiController::update_api');
$routes->get('/get_address_book_list', 'ApiController::get_address_book_list');
$routes->get('/get_api_request_type_list', 'ApiController::get_api_request_type_list');
$routes->post('/get_api_by_id', 'ApiController::get_api_by_id');
$routes->post('/delete_api', 'ApiController::delete_api');
$routes->get('/total_api_count', 'ApiController::total_api_count');
$routes->get('/total_depreciated_api_count', 'ApiController::total_depreciated_api_count');




// ################## TESTING URLS ###########################

$routes->post('/testAbout', 'TestController::testAbout');

$routes->post('/testLogin', 'TestController::testLogin',['filter' => 'LoginFilter']);


$routes->get('/encryptTest', 'TestController::encryptTest');


$routes->get('/encrypt_all_tables', 'UserController::encrypt_all_tables');
$routes->get('/decrypt_all_tables', 'UserController::decrypt_all_tables');


$routes->get('/encrypt_menu_main_modules_table', 'UserController::encrypt_menu_main_modules_table');
$routes->get('/decrypt_menu_main_modules_table', 'UserController::decrypt_menu_main_modules_table');

$routes->get('/encrypt_menu_sub_modules_table', 'UserController::encrypt_menu_sub_modules_table');
$routes->get('/decrypt_menu_sub_modules_table', 'UserController::decrypt_menu_sub_modules_table');

$routes->get('/encrypt_user_types_table', 'UserController::encrypt_user_types_table');
$routes->get('/decrypt_user_types_table', 'UserController::decrypt_user_types_table');

$routes->get('/encrypt_visual_metrics_table', 'UserController::encrypt_visual_metrics_table');
$routes->get('/decrypt_visual_metrics_table', 'UserController::decrypt_visual_metrics_table');


$routes->get('/get_users_auth_template_list_test', 'UserController::get_users_auth_template_list_test');

$routes->get('/testBaseUrl', 'TestController::testBaseUrl');

$routes->get('/datetime', 'TestController::datetime');
$routes->get('/test_files', 'TestController::test_files');
$routes->get('/read_write', 'TestController::read_write');
$routes->get('/set_folder_permission_for_windows', 'TestController::set_folder_permission_for_windows');
$routes->get('/grant_write_permission_to_folder', 'TestController::grant_write_permission_to_folder');
$routes->get('/grant_write_permission_to_folder_php', 'TestController::grant_write_permission_to_folder_php');
$routes->get('/set_folder_permission_php', 'TestController::set_folder_permission_php');
$routes->get('/set_permissions_for_file', 'TestController::set_permissions_for_file');
$routes->get('/set_permissions_for_folder', 'TestController::set_permissions_for_folder');
$routes->get('/getUploadView', 'UserController::getUploadView');
$routes->post('/uploadImg', 'UserController::uploadImg');


