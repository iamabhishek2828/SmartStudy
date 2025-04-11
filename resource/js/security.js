
function togglePassword(id) {
    const input = document.getElementById(id);
    if (input.type === "password") {
      input.type = "text";
    } else {
      input.type = "password";
    }
  }
  function validateForm() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
  
    if (!username || !password) {
      alert("Username and password are required.");
      return false;
    }
  
    if (password.length < 6) {
      alert("Password must be at least 6 characters.");
      return false;
    }
  
    return true;
  }
  