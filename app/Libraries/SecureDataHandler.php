<?php 

namespace App\Libraries;

class SecureDataHandler {
    private $encryptionKey;
    private $salt;

    public function __construct($encryptionKey, $salt) {
        $this->encryptionKey = $encryptionKey;
        $this->salt = $salt;
    }

    public function encryptAndStore($data) {
        // Generate a unique encryption key based on the user's data and the secret salt
        $uniqueKey = hash('sha256', $this->encryptionKey . $this->salt);

        // Use the unique key for encryption
        $encryptedData = openssl_encrypt($data, 'AES-256-CBC', $uniqueKey, 0, $this->salt);

        // Store the encrypted data in the database
        // Example: $this->storeInDatabase($encryptedData);
        return $encryptedData;
    }

    public function retrieveAndDecrypt($encryptedData) {
        // Generate a unique encryption key based on the secret salt
        $uniqueKey = hash('sha256', $this->encryptionKey . $this->salt);

        // Decrypt the data using the unique key
        $decryptedData = openssl_decrypt($encryptedData, 'AES-256-CBC', $uniqueKey, 0, $this->salt);

        return $decryptedData;
    }

    // Example method for storing in the database
    private function storeInDatabase($encryptedData) {}

    
}

// Example usage:
// $encryptionKey = "your_secret_key";
// $salt = "your_secret_salt";

// $dataHandler = new SecureDataHandler($encryptionKey, $salt);

// // Encrypt and store data in the database
// // $plainTextData = "Sensitive information";
// // $encryptedData = $dataHandler->encryptAndStore($plainTextData);

// // Store $encryptedData in the database

// // Retrieve the encrypted data from the database
// $encryptedDataFromDatabase = "your_retrieved_data_from_database";

// // Decrypt data when retrieving from the database
// $decryptedData = $dataHandler->retrieveAndDecrypt($encryptedDataFromDatabase);

// // Use $decryptedData as needed
// echo "Decrypted Data: $decryptedData";

// echo "SecureDataHandler included";


