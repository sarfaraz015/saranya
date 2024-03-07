<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateUsersOtpTable extends Migration
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
                'type' => 'BIGINT',
                'constraint' => 20,
                'unsigned' => true,
            ],
            'email' => [
                'type' => 'VARCHAR',
                'constraint' => 225,
            ],
            'otp' => [
                'type' => 'VARCHAR',
                'constraint' => 225,
            ],
            'otp_active_status' => [
                'type' => 'TINYINT',
                'constraint' => 1,
                'default' => 0,
            ],
            'created_on' => [
                'type' => 'TIMESTAMP',
                'null' => true,
                'default' => 'current_timestamp()',
            ],
            'updated_on' => [
                'type' => 'TIMESTAMP',
                'null' => true,
                'default' => 'current_timestamp() ON UPDATE current_timestamp()',
            ],
            'is_deleted' => [
                'type' => 'TINYINT',
                'constraint' => 1,
                'default' => 0,
            ],
            'created_by' => [
                'type' => 'INT',
                'constraint' => 10,
                'unsigned' => true,
                'default' => 0,
            ],
            'updated_by' => [
                'type' => 'INT',
                'constraint' => 10,
                'unsigned' => true,
                'default' => 0,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->addKey('uid');
        $this->forge->addKey('email');
        $this->forge->addKey('created_by');
        $this->forge->addKey('updated_by');

        $this->forge->createTable('users_otp');

        // Modify id column to be auto-increment
        $this->db->query('ALTER TABLE users_otp MODIFY id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT');

        // Additional Indexes
        $this->db->query('ALTER TABLE users_otp ADD PRIMARY KEY (id)');
        $this->db->query('ALTER TABLE users_otp ADD INDEX users_otp_uid_ind (uid) USING BTREE');
        $this->db->query('ALTER TABLE users_otp ADD INDEX users_otp_email_ind (email) USING BTREE');
        $this->db->query('ALTER TABLE users_otp ADD INDEX users_otp_created_by_ind (created_by) USING BTREE');
        $this->db->query('ALTER TABLE users_otp ADD INDEX users_otp_updated_by_ind (updated_by) USING BTREE');
    }

    public function down()
    {
        $this->forge->dropTable('users_otp');
    }
}
