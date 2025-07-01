<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Allow requests from any origin (for development)
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization'); // Added Authorization header

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Include database configuration
require_once 'db_config.php';

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed: ' . $conn->connect_error]);
    exit();
}

// Ensure the 'users' table exists with password_hash, session_token, session_expiry, and UNIQUE email
// IMPORTANT: If 'users' table already exists from previous versions, you might need to
// manually drop and recreate it (or alter its schema) to apply the new UNIQUE constraint on 'email'.
// Example SQL to drop (USE WITH CAUTION - DELETES ALL USER DATA):
// DROP TABLE IF EXISTS guests;
// DROP TABLE IF EXISTS users;
$sql_create_users_table = "
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE, -- Email is now unique and used for login
    password_hash VARCHAR(255) NOT NULL,
    session_token VARCHAR(255) UNIQUE NULL,
    session_expiry DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)";
if (!$conn->query($sql_create_users_table)) {
    echo json_encode(['success' => false, 'message' => 'Error creating users table: ' . $conn->error]);
    $conn->close();
    exit();
}

// Ensure the 'guests' table exists
$sql_create_guests_table = "
CREATE TABLE IF NOT EXISTS guests (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    place_number VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    checked_in_at DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)";
if (!$conn->query($sql_create_guests_table)) {
    error_log("Error creating guests table: " . $conn->error);
}

$input = json_decode(file_get_contents('php://input'), true);
$action = $_SERVER['REQUEST_METHOD'] === 'GET' ? ($_GET['action'] ?? '') : ($input['action'] ?? '');

// Function to authenticate session token and return user_id
function authenticateSession($conn) {
    // Check for Authorization header first (preferred for tokens)
    $headers = getallheaders();
    $sessionToken = $headers['Authorization'] ?? '';
    if (strpos($sessionToken, 'Bearer ') === 0) {
        $sessionToken = substr($sessionToken, 7); // Remove 'Bearer ' prefix
    } else {
        // Fallback to POST/GET body for session_token if header not found
        global $input; // Access global input for POST requests
        $sessionToken = $sessionToken ?: ($_GET['sessionToken'] ?? ($input['sessionToken'] ?? ''));
    }

    if (empty($sessionToken)) {
        return ['success' => false, 'message' => 'Authentication required: No session token provided.', 'status_code' => 401];
    }

    $stmt = $conn->prepare("SELECT id FROM users WHERE session_token = ? AND session_expiry > NOW()");
    $stmt->bind_param("s", $sessionToken);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();

    if ($user) {
        return ['success' => true, 'userId' => $user['id']];
    } else {
        return ['success' => false, 'message' => 'Invalid or expired session token. Please log in again.', 'status_code' => 401];
    }
}

// Actions that do NOT require prior authentication
// Added 'getGuestQrCodeByEmail' to public actions
$publicActions = ['register', 'login', 'getGuestQrCodeByEmail'];

// Authenticate session for protected actions
$userId = null;
if (!in_array($action, $publicActions)) {
    $authResult = authenticateSession($conn);
    if (!$authResult['success']) {
        http_response_code($authResult['status_code'] ?? 401); // Set HTTP status code for unauthorized
        echo json_encode($authResult); // Return authentication error
        $conn->close();
        exit();
    }
    $userId = $authResult['userId']; // Get userId (UUID) from authenticated session
}


switch ($action) {
    case 'register':
        $userId = $input['userId'] ?? ''; // This is the auto-generated UUID from frontend
        $userName = $input['userName'] ?? '';
        $userEmail = $input['userEmail'] ?? '';
        $password = $input['password'] ?? '';

        if (empty($userId) || empty($userName) || empty($userEmail) || empty($password)) {
            echo json_encode(['success' => false, 'message' => 'User ID, Name, Email, and Password are required for registration.']);
            break;
        }

        // Check if user email already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $userEmail);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            echo json_encode(['success' => false, 'message' => 'Email already registered. Please use a different email or log in.']);
            $stmt->close();
            break;
        }
        $stmt->close();

        // Hash the password
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $userId, $userName, $userEmail, $passwordHash);

        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'User registered successfully. You can now log in.']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to register user: ' . $stmt->error]);
        }
        $stmt->close();
        break;

    case 'login':
        $userEmail = $input['userEmail'] ?? ''; // Login by email
        $password = $input['password'] ?? '';

        if (empty($userEmail) || empty($password)) {
            echo json_encode(['success' => false, 'message' => 'Email and Password are required for login.']);
            break;
        }

        // Fetch user by email
        $stmt = $conn->prepare("SELECT id, name, email, password_hash FROM users WHERE email = ?");
        $stmt->bind_param("s", $userEmail);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if ($user && password_verify($password, $user['password_hash'])) {
            // Password is correct, generate and store session token
            $sessionToken = bin2hex(random_bytes(32)); // Generate a random 64-char hex string
            $sessionExpiry = date('Y-m-d H:i:s', strtotime('+1 hour')); // Token valid for 1 hour

            $stmt = $conn->prepare("UPDATE users SET session_token = ?, session_expiry = ? WHERE id = ?");
            $stmt->bind_param("sss", $sessionToken, $sessionExpiry, $user['id']);

            if ($stmt->execute()) {
                echo json_encode([
                    'success' => true,
                    'message' => 'Login successful.',
                    'userId' => $user['id'], // Return the UUID
                    'userName' => $user['name'],
                    'userEmail' => $user['email'],
                    'sessionToken' => $sessionToken
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to generate session token: ' . $stmt->error]);
            }
            $stmt->close();
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid email or password.']);
        }
        break;

    case 'logout':
        $sessionToken = $input['sessionToken'] ?? ''; // Expect token from client to invalidate

        if (empty($sessionToken)) {
            echo json_encode(['success' => false, 'message' => 'Session token is required for logout.']);
            break;
        }

        $stmt = $conn->prepare("UPDATE users SET session_token = NULL, session_expiry = NULL WHERE session_token = ?");
        $stmt->bind_param("s", $sessionToken);

        if ($stmt->execute()) {
            if ($stmt->affected_rows > 0) {
                echo json_encode(['success' => true, 'message' => 'Logged out successfully.']);
            } else {
                echo json_encode(['success' => false, 'message' => 'No active session found for this token.']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to logout: ' . $stmt->error]);
        }
        $stmt->close();
        break;

    case 'addGuest':
        // userId is already set by authenticateSession
        $name = $input['name'] ?? '';
        $email = $input['email'] ?? '';
        $placeNumber = $input['placeNumber'] ?? '';
        $status = $input['status'] ?? 'Pending';

        if (empty($name) || empty($email) || empty($placeNumber)) {
            echo json_encode(['success' => false, 'message' => 'Name, email, and place number are required.']);
            break;
        }

        // Generate a unique ID for the guest
        $guestId = 'guest_' . time() . '_' . substr(md5(mt_rand()), 0, 7);

        $stmt = $conn->prepare("INSERT INTO guests (id, user_id, name, email, place_number, status) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssss", $guestId, $userId, $name, $email, $placeNumber, $status);

        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'Guest added.', 'guestId' => $guestId]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to add guest: ' . $stmt->error]);
        }
        $stmt->close();
        break;

    case 'getGuests':
        // userId is already set by authenticateSession
        $stmt = $conn->prepare("SELECT id, name, email, place_number, status FROM guests WHERE user_id = ?");
        $stmt->bind_param("s", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $guests = [];
        while ($row = $result->fetch_assoc()) {
            $guests[] = $row;
        }
        echo json_encode(['success' => true, 'guests' => $guests]);
        $stmt->close();
        break;

    case 'getGuestDetails':
        // userId is already set by authenticateSession
        $guestId = $_GET['guestId'] ?? '';

        if (empty($guestId)) {
            echo json_encode(['success' => false, 'message' => 'Guest ID is required.']);
            break;
        }

        $stmt = $conn->prepare("SELECT id, name, email, place_number, status FROM guests WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ss", $guestId, $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $guest = $result->fetch_assoc();

        if ($guest) {
            echo json_encode(['success' => true, 'guest' => $guest]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Guest not found.']);
        }
        $stmt->close();
        break;

    case 'getGuestQrCodeByEmail': // New action for guests to retrieve their QR code
        $guestEmail = $input['guestEmail'] ?? '';

        if (empty($guestEmail)) {
            echo json_encode(['success' => false, 'message' => 'Email is required to retrieve QR code.']);
            break;
        }

        // Query the guests table to find the guest by email
        // Note: This action does NOT require user_id authentication as it's for guests
        $stmt = $conn->prepare("SELECT id, name, email, place_number, status FROM guests WHERE email = ?");
        $stmt->bind_param("s", $guestEmail);
        $stmt->execute();
        $result = $stmt->get_result();
        $guest = $result->fetch_assoc();
        $stmt->close();

        if ($guest) {
            echo json_encode(['success' => true, 'guest' => $guest]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Guest not found with that email address.']);
        }
        break;

    case 'checkInGuest':
        // userId is already set by authenticateSession
        $guestId = $input['guestId'] ?? '';

        if (empty($guestId)) {
            echo json_encode(['success' => false, 'message' => 'Guest ID is required for check-in.']);
            break;
        }

        $stmt = $conn->prepare("UPDATE guests SET status = 'Checked-in', checked_in_at = NOW() WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ss", $guestId, $userId);

        if ($stmt->execute()) {
            if ($stmt->affected_rows > 0) {
                echo json_encode(['success' => true, 'message' => 'Guest checked in.']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Guest not found or already checked in.']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to check in guest: ' . $stmt->error]);
        }
        $stmt->close();
        break;

    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action.']);
        break;
}

$conn->close();
?>
