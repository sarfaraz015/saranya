<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateUsersLogHistoryTable extends Migration
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
                'default' => 'current_timestamp() ON UPDATE current_timestamp()',
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->addKey('uid');
        $this->forge->addKey('called_api');
        $this->forge->addKey('called_method');
        $this->forge->addKey('called_class');

        $this->forge->createTable('users_log_history');

        // Modify id column to be auto-increment
        $this->db->query('ALTER TABLE users_log_history MODIFY id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT');

        // Additional Indexes
        $this->db->query('ALTER TABLE users_log_history ADD PRIMARY KEY (id)');
        $this->db->query('ALTER TABLE users_log_history ADD INDEX users_log_history_uid_ind (uid) USING BTREE');
        $this->db->query('ALTER TABLE users_log_history ADD INDEX users_log_history_called_api_ind (called_api) USING BTREE');
        $this->db->query('ALTER TABLE users_log_history ADD INDEX users_log_history_called_method_ind (called_method) USING BTREE');
        $this->db->query('ALTER TABLE users_log_history ADD INDEX users_log_history_called_class_ind (called_class) USING BTREE');
    }

    public function down()
    {
        $this->forge->dropTable('users_log_history');
    }
}
