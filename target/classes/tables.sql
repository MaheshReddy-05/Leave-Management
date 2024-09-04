-- CREDENTIALS TABLE
CREATE TABLE CREDENTIALS(
  USER_NAME varchar(100),
  PASSWORD varchar(100),
  EMPLOYEE_ID int NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (EMPLOYEE_ID)
);

-- EMPLOYEE TABLE
CREATE TABLE EMPLOYEE(
  EMPLOYEE_ID INT PRIMARY KEY,
  EMPLOYEE_NAME VARCHAR(100) NOT NULL,
  EMAIL_ID VARCHAR(100) NOT NULL,
  PHONE_NUMBER VARCHAR(15),
  DOB DATE,
 GENDER VARCHAR(10),
  MANAGER_ID INT,
  FOREIGN KEY (EMPLOYEE_ID) REFERENCES CREDENTIALS(EMPLOYEE_ID)
);

-- LEAVES TABLE
CREATE TABLE LEAVES(
  LEAVE_ID INT PRIMARY KEY AUTO_INCREMENT,
  EMPLOYEE_ID INT,
  MANAGER_ID INT,
  LEAVE_TYPE VARCHAR(20),
  REASON VARCHAR(225),
  CREATED_AT DATE,
  FROM_DATE DATE,
  TO_DATE DATE,
  LEAVE_COUNT INT,
  STATUS VARCHAR(20),
  FOREIGN KEY (EMPLOYEE_ID) REFERENCES EMPLOYEE(EMPLOYEE_ID),
  FOREIGN KEY (MANAGER_ID) REFERENCES EMPLOYEE(EMPLOYEE_ID)
);

CREATE TABLE HOLIDAYS(
  HOLIDAY_ID INT PRIMARY KEY AUTO_INCREMENT,
  HOLIDAY_NAME VARCHAR(100) NOT NULL,
  HOLIDAY_DATE DATE NOT NULL
 );

-- Inserting data into CREDENTIALS table
INSERT INTO CREDENTIALS (EMPLOYEE_ID, USER_NAME, PASSWORD) VALUES
(1, 'mahesh@gmail.com', 'mahesh@123'),
(2, 'kiran@gmail.com', 'kiran@123'),
(3, 'lokesh@gmail.com', 'lokesh@123'),
(4, 'harshini@gmail.com', 'harshini@123'),
(5, 'jayanth@gmail.com', 'jayanth@123'),
(6, 'gokul@gmail.com', 'gokul@123'),
(7, 'ruthvik@gmail.com', 'ruthvik@123'),
(8, 'bhavana@gmail.com', 'bhavana@123'),
(9, 'krishna@gmail.com', 'krishna@123'),
(10, 'pavan@gmail.com', 'pavan@123'),
(11, 'unni@gmail.com', 'unni@123'),
(12, 'preetam@gmail.com', 'preetam@123'),
(13, 'haricharan@gmail.com', 'haricharan@123'),
(14, 'babai@gmail.com', 'babai@123'),
(15, 'ramakrishna@gmail.com', 'ramakrishna@123'),
(16, 'vishal@gmail.com', 'vishal@123'),
(17, 'anusha@gmail.com', 'anusha@123'),
(18, 'vivek@gmail.com', 'vivek@123'),
(19, 'deepika@gmail.com', 'deepika@123'),
(20, 'dinesh@gmail.com', 'dinesh@123'),
(21, 'vaishnavi@gmail.com', 'vaishnavi@123'),
(22, 'suresh@gmail.com', 'suresh@123'),
(23, 'sindhu@gmail.com', 'sindhu@123'),
(24, 'manoj@gmail.com', 'manoj@123'),
(25, 'keerthi@gmail.com', 'keerthi@123'),
(26, 'vamsi@gmail.com', 'vamsi@123'),
(27, 'jyothi@gmail.com', 'jyothi@123'),
(28, 'tarun@gmail.com', 'tarun@123'),
(29, 'sakshi@gmail.com', 'sakshi@123'),
(30, 'sai@gmail.com', 'sai@123');


-- Inserting data into EMPLOYEE table
INSERT INTO EMPLOYEE (EMPLOYEE_ID, EMPLOYEE_NAME, EMAIL_ID, PHONE_NUMBER, DOB, GENDER, MANAGER_ID) VALUES
(1, 'Mahesh', 'mahesh@gmail.com', '1234567890', '1980-01-01', 'Male', 1),
(2, 'Kiran', 'kiran@gmail.com', '2345678901', '1985-05-15', 'Male', 1),
(3, 'Lokesh', 'lokesh@gmail.com', '3456789012', '1986-06-20', 'Male', 1),
(4, 'Harshini', 'harshini@gmail.com', '4567890123', '2001-02-14', 'Female', 2),
(5, 'Jayanth', 'jayanth@gmail.com', '5678901234', '2002-03-10', 'Male', 2),
(6, 'Gokul', 'gokul@gmail.com', '6789012345', '2001-07-25', 'Male', 3),
(7, 'Ruthvik', 'ruthvik@gmail.com', '7890123456', '2000-08-30', 'Male', 3),
(8, 'Bhavana', 'bhavana@gmail.com', '8901234567', '2003-11-12', 'Female', 4),
(9, 'Krishna', 'krishna@gmail.com', '9012345678', '2002-12-22', 'Male', 4),
(10, 'Pavan', 'pavan@gmail.com', '1123456789', '2000-09-18', 'Male', 5),
(11, 'Unni', 'unni@gmail.com', '2234567890', '2001-10-05', 'Male', 5),
(12, 'Preetam', 'preetam@gmail.com', '3345678901', '2000-04-07', 'Male', 6),
(13, 'Haricharan', 'haricharan@gmail.com', '4456789012', '2001-06-17', 'Male', 6),
(14, 'Babai', 'babai@gmail.com', '5567890123', '2002-01-30', 'Male', 7),
(15, 'Ramakrishna', 'ramakrishna@gmail.com', '6678901234', '2003-03-25', 'Male', 7),
(16, 'Vishal', 'vishal@gmail.com', '2345678910', '2000-01-15', 'Male', 1),
(17, 'Anusha', 'anusha@gmail.com', '3456789123', '2001-05-22', 'Female', 1),
(18, 'Vivek', 'vivek@gmail.com', '4567891234', '2000-09-12', 'Male', 2),
(19, 'Deepika', 'deepika@gmail.com', '5678912345', '2002-11-11', 'Female', 2),
(20, 'Dinesh', 'dinesh@gmail.com', '6789123456', '2001-02-20', 'Male', 3),
(21, 'Vaishnavi', 'vaishnavi@gmail.com', '7891234567', '2003-10-10', 'Female', 3),
(22, 'Suresh', 'suresh@gmail.com', '8901234568', '2000-08-25', 'Male', 4),
(23, 'Sindhu', 'sindhu@gmail.com', '9012345679', '2001-06-14', 'Female', 4),
(24, 'Manoj', 'manoj@gmail.com', '1234567891', '2002-04-05', 'Male', 5),
(25, 'Keerthi', 'keerthi@gmail.com', '2345678902', '2003-07-16', 'Female', 5),
(26, 'Vamsi', 'vamsi@gmail.com', '3456789012', '2001-03-23', 'Male', 6),
(27, 'Jyothi', 'jyothi@gmail.com', '4567890123', '2000-12-18', 'Female', 6),
(28, 'Tarun', 'tarun@gmail.com', '5678901234', '2002-09-28', 'Male', 7),
(29, 'Sakshi', 'sakshi@gmail.com', '6789012345', '2003-05-06', 'Female', 7),
(30, 'Sai', 'sai@gmail.com', '7890123456', '2000-11-23', 'Male', 8);

-- Inserting data into LEAVES table
INSERT INTO LEAVES (EMPLOYEE_ID, MANAGER_ID, LEAVE_TYPE, REASON, CREATED_AT, FROM_DATE, TO_DATE, LEAVE_COUNT, STATUS) VALUES
(4, 2, 'Personal Time Off', 'Family Function', '2024-08-01', '2024-08-01', '2024-08-02', 2, 'Approved'),
(4, 2, 'Maternity Leave', 'Childbirth', '2024-01-01', '2024-01-01', '2024-01-02', 2, 'Approved'),
(5, 2, 'Loss of Pay', 'Travel', '2024-07-15', '2024-07-18', '2024-07-18', 1, 'Pending'),
(5, 2, 'Personal Time Off', 'Family Event', '2024-02-20', '2024-02-20', '2024-02-21', 2, 'Approved'),
(6, 3, 'Compensatory Off', 'Overtime Work', '2024-09-01', '2024-09-01', '2024-09-02', 2, 'Approved'),
(6, 3, 'Loss of Pay', 'Medical Emergency', '2024-03-10', '2024-03-10', '2024-03-10', 1, 'Approved'),
(7, 3, 'Personal Time Off', 'Vacation', '2024-06-20', '2024-06-24', '2024-06-25', 2, 'Approved'),
(7, 3, 'Loss of Pay', 'Personal Reasons', '2024-08-10', '2024-08-15', '2024-08-15', 1, 'Pending'),
(8, 4, 'Maternity Leave', 'Pregnancy', '2024-05-01', '2024-07-01', '2024-07-02', 2, 'Approved'),
(8, 4, 'Personal Time Off', 'Family Event', '2024-03-01', '2024-03-03', '2024-03-03', 1, 'Approved'),
(9, 4, 'Paternity Leave', 'Newborn Care', '2024-06-15', '2024-06-17', '2024-06-18', 2, 'Approved'),
(9, 4, 'Compensatory Off', 'Overtime Work', '2024-08-20', '2024-08-20', '2024-08-21', 2, 'Approved'),
(10, 5, 'Loss of Pay', 'Extended Vacation', '2024-04-05', '2024-05-08', '2024-05-08', 1, 'Rejected'),
(10, 5, 'Personal Time Off', 'Marriage', '2024-09-01', '2024-09-02', '2024-09-02', 1, 'Approved'),
(11, 5, 'Compensatory Off', 'Project Work', '2024-03-15', '2024-03-16', '2024-03-16', 1, 'Approved'),
(11, 5, 'Loss of Pay', 'Medical Emergency', '2024-05-05', '2024-05-07', '2024-05-07', 1, 'Approved'),
(12, 6, 'Personal Time Off', 'Marriage', '2024-01-20', '2024-01-22', '2024-01-22', 1, 'Approved'),
(12, 6, 'Loss of Pay', 'Family Function', '2024-03-15', '2024-03-16', '2024-03-17', 2, 'Pending'),
(13, 6, 'Loss of Pay', 'Medical Emergency', '2024-07-01', '2024-07-02', '2024-07-02', 1, 'Approved'),
(13, 6, 'Personal Time Off', 'Holiday', '2024-06-10', '2024-06-11', '2024-06-12', 2, 'Approved'),
(14, 7, 'Compensatory Off', 'Work Deadline', '2024-08-01', '2024-08-04', '2024-08-05', 2, 'Pending'),
(14, 7, 'Personal Time Off', 'Travel', '2024-09-01', '2024-09-03', '2024-09-03', 1, 'Approved'),
(15, 7, 'Personal Time Off', 'Travel', '2024-09-15', '2024-09-16', '2024-09-16', 1, 'Approved'),
(15, 7, 'Loss of Pay', 'Medical Reasons', '2024-04-01', '2024-04-02', '2024-04-03', 2, 'Approved'),
(16, 1, 'Personal Time Off', 'Family Event', '2024-05-15', '2024-05-16', '2024-05-17', 2, 'Approved'),
(17, 1, 'Loss of Pay', 'Medical Emergency', '2024-03-01', '2024-03-01', '2024-03-01', 1, 'Approved'),
(18, 2, 'Compensatory Off', 'Overtime Work', '2024-04-05', '2024-04-06', '2024-04-07', 2, 'Approved'),
(19, 2, 'Personal Time Off', 'Vacation', '2024-07-10', '2024-07-12', '2024-07-13', 2, 'Pending'),
(20, 3, 'Loss of Pay', 'Personal Reasons', '2024-08-15', '2024-08-16', '2024-08-17', 2, 'Approved'),
(21, 3, 'Maternity Leave', 'Pregnancy', '2024-05-01', '2024-07-01', '2024-07-02', 2, 'Approved'),
(22, 4, 'Personal Time Off', 'Family Function', '2024-02-10', '2024-02-10', '2024-02-11', 2, 'Approved'),
(23, 4, 'Loss of Pay', 'Medical Emergency', '2024-03-10', '2024-03-10', '2024-03-10', 1, 'Approved'),
(24, 5, 'Compensatory Off', 'Overtime Work', '2024-06-01', '2024-06-01', '2024-06-02', 2, 'Approved'),
(25, 5, 'Personal Time Off', 'Vacation', '2024-08-05', '2024-08-06', '2024-08-07', 2, 'Pending'),
(26, 6, 'Loss of Pay', 'Medical Emergency', '2024-03-20', '2024-03-21', '2024-03-22', 2, 'Approved'),
(27, 6, 'Compensatory Off', 'Overtime Work', '2024-04-12', '2024-04-13', '2024-04-14', 2, 'Approved'),
(28, 7, 'Personal Time Off', 'Holiday', '2024-07-15', '2024-07-16', '2024-07-17', 2, 'Pending'),
(29, 7, 'Loss of Pay', 'Travel', '2024-06-20', '2024-06-20', '2024-06-21', 2, 'Approved'),
(30, 8, 'Compensatory Off', 'Overtime Work', '2024-05-10', '2024-05-11', '2024-05-12', 2, 'Approved');

-- Inserting data into HOLIDAYS table
INSERT INTO HOLIDAYS ( HOLIDAY_NAME, HOLIDAY_DATE) VALUES
('Gandhi Jayanti', '2024-10-02'),
('Diwali', '2024-10-31'),
('Diwali', '2024-11-01'),
('Christmas', '2024-12-25'),
('New Year', '2025-01-01');