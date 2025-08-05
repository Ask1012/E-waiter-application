# 🧾 E-Waiter Project

A smart restaurant management system designed to simplify order handling, menu management, and customer interaction through digital interfaces.

---

## 📌 Features

### 👨‍💼 Owner Panel
- **Owner Login**: Secure login to access the admin dashboard.
- **Menu Management**:
  - Add/Edit/Delete food items.
  - Organize items by categories (e.g., Fast Food, Beverages, Main Course).
- **Waiter Management**:
  - Add new waiters.
  - Assign waiter logins under the owner's ID.
- **Billing Dashboard**:
  - View and print all generated bills from waiter orders.
  - Track table-wise orders and daily sales.

---

### 🧑‍🍳 Waiter Panel
- **Waiter Login**:
  - Waiters can log in using their assigned credentials under the owner ID.
- **Order Taking**:
  - Select table number.
  - Choose food items from the menu (organized by category).
  - Generate and send order details to the kitchen and billing system.

---

### 👥 Customer View
- **QR Code Scanning**:
  - Customers can scan a QR code placed on the table to view the menu.
  - Fully digital menu display – no app or login required.
  - (Optional: Add “Order from Table” for future scope)

---

## 🖨️ Billing System
- Orders placed by waiters are:
  - Sent to the **counter for billing**.
  - Bills are **auto-calculated** based on quantity and price.
  - Final bill can be **printed or downloaded**.

---

## 🏗️ Technologies Used

- **Frontend**: HTML, CSS, JavaScript (QR integration)
- **Backend**:  Flask (customizable)
- **Database**: MySQL 
- **Optional**: QR Code Library python-qrcode

---



