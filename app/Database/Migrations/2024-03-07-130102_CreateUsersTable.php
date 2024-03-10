<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateUsersTable extends Migration
{
    public function up()
    {
        $this->forge->addField([
            'id' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
                'auto_increment' => true,
            ],
            'uid' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
            ],
            'ip_address' => [
                'type' => 'VARCHAR',
                'constraint' => 45,
            ],
            'username' => [
                'type' => 'VARCHAR',
                'constraint' => 100,
                'null' => true,
            ],
            'password' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
            ],
            'email' => [
                'type' => 'VARCHAR',
                'constraint' => 254,
            ],
            'activation_selector' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'activation_code' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'forgotten_password_selector' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'forgotten_password_code' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'forgotten_password_time' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
                'null' => true,
            ],
            'remember_selector' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'remember_code' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'created_on' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
            ],
            'last_login' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
                'null' => true,
            ],
            'active' => [
                'type' => 'TINYINT',
                'constraint' => 1,
                'unsigned' => true,
                'null' => true,
            ],
            'first_name' => [
                'type' => 'VARCHAR',
                'constraint' => 50,
                'null' => true,
            ],
            'last_name' => [
                'type' => 'VARCHAR',
                'constraint' => 50,
                'null' => true,
            ],
            'company' => [
                'type' => 'VARCHAR',
                'constraint' => 100,
                'null' => true,
            ],
            'phone' => [
                'type' => 'VARCHAR',
                'constraint' => 225,
                'null' => true,
            ],
            'is_deleted' => [
                'type' => 'TINYINT',
                'constraint' => 1,
                'default' => 0,
            ],
            'updated_on' => [
                'type' => 'TIMESTAMP',
                'default' => $this->currentTimestamp(),
                'on update CURRENT_TIMESTAMP' => true,
            ],
            'updated_by' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
                'default' => 0,
            ],
            'created_by' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
                'default' => 0,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->addUniqueKey('email', 'users_email_uniq');
        $this->forge->addUniqueKey('uid', 'users_uid_uniq');
        $this->forge->addUniqueKey('activation_selector');
        $this->forge->addUniqueKey('forgotten_password_selector');
        $this->forge->addUniqueKey('remember_selector');
        $this->forge->addKey('updated_by', true);
        $this->forge->addKey('created_by', true);
        $this->forge->addKey('username');

        // Define primary key
        $this->forge->addPrimaryKey('id');

        $this->forge->createTable('users');

        // Modify id column to be auto-increment
        $this->db->query('ALTER TABLE users MODIFY id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT');
    }

    public function down()
    {
        $this->forge->dropTable('users');
    }
}
