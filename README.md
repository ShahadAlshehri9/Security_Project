# Security_Project
# Vulnerable Web Application 


##  Project Overview

This is a simple user management system built with **Node.js**, **Express**, **SQLite**, and **EJS**. It was created for security project to demonstrate essential web security practices by implementing a simple application protected against five common vulnerabilities to show how secure coding techniques can be applied in real applications to reduce attack surfaces and improve overall system security


1. **SQL Injection (SQLi)** – in login and registration forms.
2. **Weak Password Storage** – passwords hashed with MD5 (broken & guessable).
3. **Cross‑Site Scripting (XSS)** – user comments are stored & rendered unsanitised.
4. **Broken Access Control** – any logged‑in user can access the admin panel.
5. **Missing Encryption** – the app runs on plain HTTP and uses an insecure session secret.


##Setup & Run Instructions
 - You must download **Node.js** (v14 or later) and **npm** – [Download](https://nodejs.org/)
 ### For macOS / Linux
1. **download the repository** and open a terminal in the project folder: cd ~/Desktop/vulnerable-webapp
2. **Install dependencies**: npm install
3. **Initialise the database**: npm run init-db
4. **Start the secure server**: npm start
5. *Open your browser and go to* **https://localhost:3000**

### For Windows 
1. Open Command Prompt or PowerShell as Administrator and **navigate to the project folder**: cd C:\Users\YourName\Desktop\vulnerable-webapp
2. **Uninstall dependencies**: npm uninstall sqlite3
3.  **Install dependencies**: npm install sqlite3 
5. **Start the secure server**: npm start
6. *Open your browser and go to* **https://localhost:3000**



 # Secure Web Application 


This is a **fully secured** user management system built with **Node.js**, **Express**, **SQLite**, and **EJS**. It was developed as a final project for a security course. All common vulnerabilities have been identified and fixed using industry‑standard techniques.

###  Security Features Implemented

| Vulnerability | Mitigation |
|---------------|-------------|
| **SQL Injection** | All database queries use **parameterized statements** (prepared statements) – no string concatenation. |
| **Weak Password Storage** | Passwords are hashed with **bcrypt** (salt rounds = 12), a slow, adaptive hash function. |
| **Cross‑Site Scripting (XSS)** | User input is **sanitized** (HTML tags stripped) before storage, and output is **escaped** (`<%= ... %>`) in templates. |
| **Broken Access Control** | **Role‑based middleware** (`requireAdmin`) restricts the `/admin` route to users with `role = 'admin'`. |
| **Missing Encryption** | The app is configured to run over **HTTPS** (TLS/SSL) with a self‑signed certificate for development; session cookies are marked `secure: true`. |

##Setup & Run Instructions
 - You must download **Node.js** (v14 or later) and **npm** – [Download](https://nodejs.org/)

### For macOS / Linux
1. **download the repository** and open a terminal in the project folder: cd ~/Desktop/secure-webapp
2. **Install dependencies**: npm install
3. **Initialise the database**: npm run init-db
4. **Start the secure server**: npm start
5. *Open your browser and go to* **https://localhost:3000**

### For Windows 
1. Open Command Prompt or PowerShell as Administrator and **navigate to the project folder**: cd C:\Users\YourName\Desktop\secure-webapp
2. **Uninstall dependencies**: npm uninstall sqlite3
3.  **Install dependencies**: npm install sqlite3 
4. **Start the secure server**: npm start
5. *Open your browser and go to* **https://localhost:3000**


# How to test:
1.  ## **SQL Injection Prevention**
Try entering SQL payloads in the login page such as: ' OR 1=1 --
### Expected result for a secure web application:
The system should not return all records
The query should be safely rejected or sanitized
2. ## **XSS Protection**
Try injecting a script in Commment section: <script>alert('XSS')</script>
### Expected result for a secure web application:
The script should not execute
The text should appear as plain text
3. ## **Authentication & Session Security**
### How to test:
Try logging in with invalid credentials repeatedly
Check that session cookies are regenerated after login
Ensure no sensitive data appears in URLs



> ### **NOTES:**
>  Port 3000 already in use? Change the port in app.js (last line) to something like 3443 and update the URL accordingly.
>  We recommend using google chorme rather than Safari on macOS for testing, as Safari enforces stricter certificate validation.


