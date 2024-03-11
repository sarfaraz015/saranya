<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateApiLogsConcurrentRequestTable extends Migration
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
            ],
            'updated_on' => [
                'type' => 'TIMESTAMP',
                'on update CURRENT_TIMESTAMP' => true,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->createTable('api_concurrent_request_log');
    }

    public function down()
    {
        $this->forge->dropTable('api_concurrent_request_log');
    }
}
