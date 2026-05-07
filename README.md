# Security_Project
# Vulnerable Web Application – Security Project


##  Project Overview

This is a simple user management system built with **Node.js**, **Express**, **SQLite**, and **EJS**. It was created for security project to demonstrate five common vulnerabilities:

1. **SQL Injection (SQLi)** – in login and registration forms.
2. **Weak Password Storage** – passwords hashed with MD5 (broken & guessable).
3. **Cross‑Site Scripting (XSS)** – user comments are stored & rendered unsanitised.
4. **Broken Access Control** – any logged‑in user can access the admin panel.
5. **Missing Encryption** – the app runs on plain HTTP and uses an insecure session secret.
 # Secure Web Application – User Management System

> A production‑ready web application demonstrating **secure coding practices** including protection against SQL injection, XSS, weak password storage, broken access control, and missing encryption.

##  Project Overview

This is a **fully secured** user management system built with **Node.js**, **Express**, **SQLite**, and **EJS**. It was developed as a final project for a security course. All common vulnerabilities have been identified and fixed using industry‑standard techniques.

###  Security Features Implemented

| Vulnerability | Mitigation |
|---------------|-------------|
| **SQL Injection** | All database queries use **parameterized statements** (prepared statements) – no string concatenation. |
| **Weak Password Storage** | Passwords are hashed with **bcrypt** (salt rounds = 12), a slow, adaptive hash function. |
| **Cross‑Site Scripting (XSS)** | User input is **sanitized** (HTML tags stripped) before storage, and output is **escaped** (`<%= ... %>`) in templates. |
| **Broken Access Control** | **Role‑based middleware** (`requireAdmin`) restricts the `/admin` route to users with `role = 'admin'`. |
| **Missing Encryption** | The app is configured to run over **HTTPS** (TLS/SSL) with a self‑signed certificate for development; session cookies are marked `secure: true`. |

##  Project Structure

