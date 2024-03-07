<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateLoginAttemptsTable extends Migration
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
            'ip_address' => [
                'type' => 'VARCHAR',
                'constraint' => 45,
            ],
            'login' => [
                'type' => 'VARCHAR',
                'constraint' => 100,
            ],
            'time' => [
                'type' => 'INT',
                'constraint' => 10,
                'unsigned' => true,
                'null' => true,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->createTable('login_attempts');

        // Modify id column to be auto-increment
        $this->db->query('ALTER TABLE login_attempts MODIFY id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT');

        // Additional Index
        $this->db->query('ALTER TABLE login_attempts ADD PRIMARY KEY (id)');
    }

    public function down()
    {
        $this->forge->dropTable('login_attempts');
    }
}
