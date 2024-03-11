<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateUsersSessionTokens extends Migration
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
            'token' => [
                'type' => 'VARCHAR',
                'constraint' => 500,
                'null' => true,
            ],
            'login_active_status' => [
                'type' => 'TINYINT',
                'constraint' => 1,
                'default' => 0,
            ],
            'hit_time' => [
                'type' => 'TIMESTAMP',
                'null' => true,
            ],
            'created_on' => [
                'type' => 'TIMESTAMP',
                'on update CURRENT_TIMESTAMP' => true,
            ],
            'created_by' => [
                'type' => 'INT',
                'constraint' => 11,
                'default' => 0,
            ],
            'updated_on' => [
                'type' => 'TIMESTAMP',
                'on update CURRENT_TIMESTAMP' => true,
            ],
            'updated_by' => [
                'type' => 'INT',
                'constraint' => 11,
                'default' => 0,
            ],
            'is_deleted' => [
                'type' => 'TINYINT',
                'constraint' => 1,
                'default' => 0,
            ],
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->createTable('users_session_tokens');

    }

    public function down()
    {
        $this->forge->dropTable('users_session_tokens');
    }
}
