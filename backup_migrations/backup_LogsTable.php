<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class LogsTable extends Migration
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
                'collate' => 'utf8_general_ci',
            ],
            'errstr' => [
                'type' => 'TEXT',
                'collate' => 'utf8_general_ci',
            ],
            'errfile' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'collate' => 'utf8_general_ci',
            ],
            'errline' => [
                'type' => 'INT',
                'constraint' => 4,
            ],
            'ip_address' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'collate' => 'utf8_general_ci',
            ],
            'user_agent' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
                'collate' => 'utf8_general_ci',
            ],
            'time' => [
                'type' => 'DATETIME',
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->createTable('logs', true);
    }

    public function down()
    {
        $this->forge->dropTable('logs', true);
    }
}
