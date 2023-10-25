<?php

if(empty($_POST["name"])){
    die("Name required");
}

if(!filter_var($_POST["email"],FILTER_VALIDATE_EMAIL)){
    die("Valid email required");
}

if(strlen($_POST["password"]) < 8){
    die("Password should at least be 8 characters");
}

if(!preg_match("/[a-z]/i", $_POST["password"])){
    die("Password should at least contain one letter");
}

if(!preg_match("/[0-9]/i", $_POST["password"])){
    die("Password should at least contain one number");
}

if($_POST["password"] !== $_POST["confirm_password"]){
    die("Password must match");
}

$password_hash = password_hash($_POST["password"],PASSWORD_DEFAULT);

$mysqli = require __DIR__."/database.php";

$sql = "INSERT INTO user (name, email, password_hash)
VALUES (?,?,?)";

$stmt = $mysqli->stmt_init();

if (! $stmt->prepare($sql)){
    die("SQL error: " .$mysqli->error);
}

$stmt->bind_param("sss",
$_POST["name"],
$_POST["email"],
$password_hash);

try {
    if ($stmt->execute()){
        echo "Sign up successful";
        header("Location: signup_success.html");
        exit;
    }
    
} catch (mysqli_sql_exception $e) {
    $errorCode = $e->getCode();
    if ($errorCode === 1062) {
        die("Email already taken");
    } else {
        die("An error occurred: " . $e->getMessage());
    }
}





