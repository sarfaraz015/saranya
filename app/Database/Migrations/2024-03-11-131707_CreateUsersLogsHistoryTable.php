<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateUsersLogsHistoryTable extends Migration
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
                'null' => true,
            ],
            'called_api' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'called_class' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'called_method' => [
                'type' => 'VARCHAR',
                'constraint' => 254,
                'null' => true,
            ],
            'user_agent' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'user_input_data' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'user_response_data' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'hit_date_time' => [
                'type' => 'TIMESTAMP',
                'null' => true,
            ],
            'request_size' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'response_size' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'updated_on' => [
                'type' => 'TIMESTAMP',
                'on update CURRENT_TIMESTAMP' => true,
            ],
        ]);

        $this->forge->addKey('id', true);
        
        $this->forge->createTable('users_log_history');
    }

    public function down()
    {
        $this->forge->dropTable('users_log_history');
    }
}
