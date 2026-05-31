-- Create challenges database
CREATE DATABASE IF NOT EXISTS challenges;
USE challenges;

-- Create a simple table for challenges database
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50)
);

INSERT INTO users (username, password) VALUES ('admin', 'admin123');
