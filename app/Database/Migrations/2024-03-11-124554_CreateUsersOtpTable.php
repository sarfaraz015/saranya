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
                'on update CURRENT_TIMESTAMP' => true,
            ],
            'updated_on' => [
                'type' => 'TIMESTAMP',
                'on update CURRENT_TIMESTAMP' => true,
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

        $this->forge->addPrimaryKey('id');
        $this->forge->createTable('users_otp');
    }

    public function down()
    {
        $this->forge->dropTable('users_otp');
    }
}
