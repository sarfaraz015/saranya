<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateLogsTable extends Migration
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
            'errno' => [
                'type' => 'INT',
                'constraint' => 2,
            ],
            'errtype' => [
                'type' => 'VARCHAR',
                'constraint' => 32,
            ],
            'errstr' => [
                'type' => 'TEXT',
            ],
            'errfile' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
            ],
            'errline' => [
                'type' => 'INT',
                'constraint' => 4,
            ],
            'ip_address' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
            ],
            'user_agent' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
            ],
            'time' => [
                'type' => 'DATETIME',
            ],
            'is_deleted' => [
                'type' => 'TINYINT',
                'constraint' => 1,
                'default' => 0,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->createTable('logs');

        // Modify id column to be auto-increment
        $this->db->query('ALTER TABLE logs MODIFY id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT');

        // Additional Indexes
        $this->db->query('ALTER TABLE logs ADD PRIMARY KEY (id)');
    }

    public function down()
    {
        $this->forge->dropTable('logs');
    }
}
