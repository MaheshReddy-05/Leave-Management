package com.wavemaker.model;

import java.time.LocalDate;

public class Employee {
    private int employeeId;
    private String employeeName;
    private String emilId;
    private LocalDate DOB;
    private String phoneNumber;
    private int managerId;
    private String gender;

    public LocalDate getDOB() {
        return DOB;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public void setDOB(LocalDate DOB) {
        this.DOB = DOB;
    }

    public int getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(int employeeId) {
        this.employeeId = employeeId;
    }

    public String getEmployeeName() {
        return employeeName;
    }

    public void setEmployeeName(String employeeName) {
        this.employeeName = employeeName;
    }

    public String getEmilId() {
        return emilId;
    }

    public void setEmilId(String emilId) {
        this.emilId = emilId;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public int getManagerId() {
        return managerId;
    }

    public void setManagerId(int managerId) {
        this.managerId = managerId;
    }
}
