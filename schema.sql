CREATE DATABASE IF NOT EXISTS essential_notices CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE essential_notices;

CREATE TABLE IF NOT EXISTS announcements (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  type ENUM('blood','missing','found') NOT NULL,
  title VARCHAR(180) NOT NULL,
  details TEXT NOT NULL,
  region VARCHAR(100) NOT NULL,
  blood_type ENUM('O+','O-','A+','A-','B+','B-','AB+','AB-') NULL,
  contact_name_enc TEXT NULL,
  contact_phone_enc TEXT NULL,
  latitude DECIMAL(10,7) NULL,
  longitude DECIMAL(10,7) NULL,
  status ENUM('pending','verified','rejected','resolved') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_public_feed (status, created_at),
  INDEX idx_type_region (type, region),
  INDEX idx_blood (blood_type)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS announcement_photos (
  announcement_id BIGINT UNSIGNED NOT NULL,
  photo_index TINYINT UNSIGNED NOT NULL,
  mime_type VARCHAR(32) NOT NULL,
  photo_data MEDIUMBLOB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (announcement_id, photo_index)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS admin_otps (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  phone VARCHAR(24) NOT NULL,
  otp_hash CHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_otp_phone (phone, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS admin_sessions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  token_hash CHAR(64) NOT NULL UNIQUE,
  phone VARCHAR(24) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_session_expiry (expires_at)
) ENGINE=InnoDB;

-- Create a dedicated DB user and grant only this database's required privileges in production.
