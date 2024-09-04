package com.wavemaker.model;

public class LeavesSummary {
    private int employeeId;
    private String employeeName;
    private int compensatoryOff;
    private int lossOffPay;
    private int maternityLeave;
    private int paternityLeave;
    private int personalTimeOff;
    private String gender;

    public int getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(int employeeId) {
        this.employeeId = employeeId;
    }


    public int getCompensatoryOff() {
        return compensatoryOff;
    }

    public void setCompensatoryOff(int compensatoryOff) {
        this.compensatoryOff = compensatoryOff;
    }

    public int getLossOffPay() {
        return lossOffPay;
    }

    public void setLossOffPay(int lossOffPay) {
        this.lossOffPay = lossOffPay;
    }

    public int getMaternityLeave() {
        return maternityLeave;
    }

    public void setMaternityLeave(int maternityLeave) {
        this.maternityLeave = maternityLeave;
    }

    public int getPaternityLeave() {
        return paternityLeave;
    }

    public void setPaternityLeave(int paternityLeave) {
        this.paternityLeave = paternityLeave;
    }

    public int getPersonalTimeOff() {
        return personalTimeOff;
    }

    public void setPersonalTimeOff(int personalTimeOff) {
        this.personalTimeOff = personalTimeOff;
    }

    public String getEmployeeName() {
        return employeeName;
    }

    public void setEmployeeName(String employeeName) {
        this.employeeName = employeeName;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }
}
