<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateTableApiLogs extends Migration
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
            'user_id' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
            ],
            'ip_address' => [
                'type' => 'VARCHAR',
                'constraint' => 45,
                'null' => true,
            ],
            'api_url' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'user_agent' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'null' => true,
            ],
            'last_hit' => [
                'type' => 'TIMESTAMP',
                'null' => true,
            ],
            'current_hit' => [
                'type' => 'TIMESTAMP',
                'null' => true,
            ],
            'hit_count' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
            ]
        ]);

        $this->forge->addKey('id', true);
        $this->forge->createTable('api_logs',true);
    }

    public function down()
    {
        $this->forge->dropTable('api_logs', true);
    }
}
