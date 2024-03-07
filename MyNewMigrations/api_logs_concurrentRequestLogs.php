<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateApiLogsTable extends Migration
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
                'default' => 'current_timestamp() ON UPDATE current_timestamp()',
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->addKey('user_id');
        $this->forge->addKey('api_url');

        $this->forge->createTable('api_logs');

        // Modify id column to be auto-increment
        $this->db->query('ALTER TABLE api_logs MODIFY id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT');

        // Additional Indexes
        $this->db->query('ALTER TABLE api_logs ADD PRIMARY KEY (id)');
        $this->db->query('ALTER TABLE api_logs ADD INDEX api_logs_user_id_ind (user_id) USING BTREE');
        $this->db->query('ALTER TABLE api_logs ADD INDEX api_logs_api_url_ind (api_url) USING BTREE');
    }

    public function down()
    {
        $this->forge->dropTable('api_logs');
    }
}
