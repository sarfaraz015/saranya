<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateUsersTokensTable extends Migration
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
                'null' => true,
                'default' => 'current_timestamp()',
            ],
            'created_by' => [
                'type' => 'INT',
                'constraint' => 11,
                'default' => 0,
            ],
            'updated_on' => [
                'type' => 'TIMESTAMP',
                'null' => true,
                'default' => 'current_timestamp()',
                'on_update' => true,
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

        $this->forge->addKey('id', true);
        $this->forge->addUniqueKey('uid');
        $this->forge->addUniqueKey('token');
        $this->forge->addKey('created_by');
        $this->forge->addKey('updated_by');
        $this->forge->addKey('uid');

        $this->forge->createTable('users_tokens');

        // Modify id column to be auto-increment
        $this->db->query('ALTER TABLE users_tokens MODIFY id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT');

        // Additional Indexes
        $this->db->query('ALTER TABLE users_tokens ADD PRIMARY KEY (id)');
        $this->db->query('ALTER TABLE users_tokens ADD INDEX users_tokens_uid_uniq (uid) USING BTREE');
        $this->db->query('ALTER TABLE users_tokens ADD INDEX users_tokens_token_uniq (token) USING BTREE');
        $this->db->query('ALTER TABLE users_tokens ADD INDEX users_tokens_created_by_ind (created_by) USING BTREE');
        $this->db->query('ALTER TABLE users_tokens ADD INDEX users_tokens_updated_by_ind (updated_by) USING BTREE');
        $this->db->query('ALTER TABLE users_tokens ADD INDEX users_tokens_uid_ind (uid) USING BTREE');
    }

    public function down()
    {
        $this->forge->dropTable('users_tokens');
    }
}
