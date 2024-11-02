<?php
include_once 'config/db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = mysqli_real_escape_string($conn, $_POST['username']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    
    // Check if username exists
    $sql = "SELECT id FROM users WHERE username = ?";
    
    if($stmt = mysqli_prepare($conn, $sql)){
        mysqli_stmt_bind_param($stmt, "s", $username);
        
        if(mysqli_stmt_execute($stmt)){
            mysqli_stmt_store_result($stmt);
            
            if(mysqli_stmt_num_rows($stmt) == 1){
                echo "This username is already taken.";
            } else {
                // Insert new user
                $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
                
                if($stmt = mysqli_prepare($conn, $sql)){
                    mysqli_stmt_bind_param($stmt, "ss", $username, $password);
                    
                    if(mysqli_stmt_execute($stmt)){
                        header("location: index.php");
                    } else {
                        echo "Something went wrong. Please try again later.";
                    }
                }
            }
        }
        mysqli_stmt_close($stmt);
    }
}
mysqli_close($conn);
?>