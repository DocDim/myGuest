# Event Guest Manager

This project provides a simple web-based application for managing event guest registrations and check-ins. It features a main registration page for event organizers, a check-in page for staff, and a dedicated page for guests to retrieve their unique QR codes using their email.

## Features

* **User Authentication:** Event organizers can register and log in to manage their events securely.

* **Guest Registration:** Add new guests manually with name, email, and place number.

* **CSV Import:** Bulk import guest lists from a CSV file.

* **Dynamic Guest List:** View a real-time updated list of registered guests with their current status (Pending/Checked-in).

* **QR Code Generation:** Each registered guest is assigned a unique QR code.

  * In the guest list (`index.html`), clicking a QR code navigates directly to the check-in page with the guest's ID pre-filled.

  * The QR code itself embeds the URL to the check-in page with the guest's ID, allowing for scanning with external devices.

* **Guest Check-in:**

  * Manual check-in by entering a guest ID.

  * Camera-based QR code scanning for quick check-in.

* **Guest QR Retrieval Page:** A public-facing page where guests can enter their email to retrieve and view their personal QR code.

## Technologies Used

* **Frontend:**

  * HTML5

  * CSS (Tailwind CSS for styling)

  * JavaScript

    * `qrcode.js`: For generating QR codes.

    * `html5-qrcode`: For scanning QR codes using the device camera.

* **Backend:**

  * PHP (for server-side logic and API endpoints)

  * MySQL (for database storage)

## Setup Instructions

To get this project up and running, you'll need a web server with PHP and MySQL installed (e.g., XAMPP, WAMP, MAMP, or a LAMP/LEMP stack).

### 1. Database Setup (MySQL)

First, create the database and the necessary tables.

```

\-- Create the database
CREATE DATABASE IF NOT EXISTS event\_manager\_db;

\-- Use the database
USE event\_manager\_db;

\-- Create the users table
CREATE TABLE IF NOT EXISTS users (
id VARCHAR(255) PRIMARY KEY,
name VARCHAR(255) NOT NULL,
email VARCHAR(255) NOT NULL UNIQUE, -- Email is now unique and used for login
password\_hash VARCHAR(255) NOT NULL,
session\_token VARCHAR(255) UNIQUE NULL,
session\_expiry DATETIME NULL,
created\_at DATETIME DEFAULT CURRENT\_TIMESTAMP
);

\-- Create the guests table
CREATE TABLE IF NOT EXISTS guests (
id VARCHAR(255) PRIMARY KEY,
user\_id VARCHAR(255) NOT NULL,
name VARCHAR(255) NOT NULL,
email VARCHAR(255) NOT NULL,
place\_number VARCHAR(255) NOT NULL,
status VARCHAR(50) NOT NULL DEFAULT 'Pending',
created\_at DATETIME DEFAULT CURRENT\_TIMESTAMP,
checked\_in\_at DATETIME NULL,
FOREIGN KEY (user\_id) REFERENCES users(id) ON DELETE CASCADE
);

```

**Important Note:** If you had previous versions of these tables, you might need to drop them first (`DROP TABLE IF EXISTS guests; DROP TABLE IF EXISTS users;`) before running the `CREATE TABLE` statements to ensure the schema, especially the `UNIQUE` constraint on `users.email`, is correctly applied. **Be cautious as this will delete all existing data.**

### 2. Backend Setup (PHP)

1. **Create `db_config.php`:**
   Create a file named `db_config.php` in the same directory as your `api.php`.

```

\<?php
// Database configuration
$servername = "localhost"; // Your database host (e.g., "localhost" or your hosting provider's host)
$username = "root"; // Your database username
$password = ""; // Your database password
$dbname = "event\_manager\_db"; // Your database name
?\>

```

**Crucial:** Update `$servername`, `$username`, `$password`, and `$dbname` to match your actual MySQL database credentials. If you're on a shared host, these will likely be different from `localhost` and `root`.

2. **Place `api.php`:**
Place the provided `api.php` file in your web server's document root (e.g., `htdocs` for Apache, `www` for Nginx, or a subdirectory within).

### 3. Frontend Setup (HTML/JavaScript)

Place the `index.html`, `checkin.html`, and `guest_qr.html` files in the same directory as your `api.php` file on your web server.

The HTML files include CDN links for Tailwind CSS, qrcode.js, and html5-qrcode, so no local installation of these libraries is required.

## Usage

### For Event Organizers/Staff

1. **Access the Registration Page:**
Open `index.html` in your web browser (e.g., `http://localhost/your_project/index.html`).

2. **Register/Login:**

* If you're a new organizer, register with your name, email, and a password.

* If you're already registered, log in using your email and password.

* Your login session will persist using `localStorage`.

3. **Manage Guests:**

* **Add New Guest:** Use the "Add New Guest" form to manually add attendees.

* **Import CSV:** Use the "Import Guest List (CSV)" section to upload a CSV file. The CSV should have columns for `Name`, `Email`, and `Place Number`. A header row is optional.

* **View Guest List:** The table will automatically populate with your registered guests. Each guest will have a QR code.

4. **Check-in Guests (via `index.html`):**

* Click on a QR code in the guest list on `index.html`. This will navigate you to `checkin.html` with the guest's ID pre-filled in the manual check-in field.

### For Check-in Staff

1. **Access the Check-in Page:**
Open `checkin.html` in your web browser (e.g., `http://localhost/your_project/checkin.html`).

2. **Login:**

* Staff members must log in using an organizer account created via `index.html`.

3. **Check-in Methods:**

* **QR Scan:** Click "Start QR Scan" to activate your device's camera and scan a guest's QR code. The system will automatically attempt to check them in.

* **Manual Check-in:** Enter the guest's unique ID (from their QR code or printed list) into the input field and click "Check In Manually".

### For Guests

1. **Retrieve Your QR Code:**
Share the link to `guest_qr.html` with your attendees (e.g., `http://localhost/your_project/guest_qr.html`).

2. **Enter Email:**
Guests will enter the email address they used for registration.

3. **View QR Code:**
If their email is found, their unique QR code will be displayed. They can then save this image or use it directly from their device for check-in. The QR code itself contains the link to the check-in page with their ID.

## Important Considerations

* **Security (HTTPS):** For production environments, it is **critical** to serve your application over HTTPS. Browsers often block camera access (`html5-qrcode`) and other sensitive features on insecure HTTP connections.

* **Database Credentials:** Never expose your `db_config.php` file or database credentials directly to the public web. Ensure it's outside the web-accessible directory if possible, or protected by web server configurations. In this simple setup, it's in the same directory, so ensure your web server is configured securely.

* **Error Handling:** The current error handling provides basic messages. For a production application, you would want more robust error logging and user-friendly feedback.

* **Scalability:** This is a basic application. For very large events, consider more advanced database solutions and backend architectures.

* **User IDs for Guests:** The `guest_qr.html` page does not require a user (organizer) login. It directly queries the `guests` table by email. Ensure that guest emails are unique if you want this feature to reliably return a single guest's QR code.
```
