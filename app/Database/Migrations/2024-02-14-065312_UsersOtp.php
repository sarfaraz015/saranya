<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class UsersOtp extends Migration
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
                'type' => 'BOOLEAN',
            ],
            'created_at' => [
                'type' => 'TIMESTAMP',
                'null' => true,
            ],
            'updated_at' => [
                'type' => 'TIMESTAMP',
                'null' => true,
                'default' => null,
                'on update CURRENT_TIMESTAMP' => true,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->createTable('users_otp', true);
    }

    public function down()
    {
        $this->forge->dropTable('users_otp', true);
    }
}
