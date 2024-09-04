package com.wavemaker.repository;

import com.wavemaker.model.Holiday;
import com.wavemaker.model.Leave;
import com.wavemaker.model.LeavesSummary;

import java.util.List;

public interface DashboardRepository {
    public List<Holiday> getHolidays();

    public String getGenderByEmployeeId(int employeeId);

    public LeavesSummary getLeaveSummaryById(int employeeId);

    public List<Leave> getTopFourApprovedLeaveByEmployeeId(int employeeId);

    public boolean doEmployeeHadTeam(int employeeId);

    public List<LeavesSummary> getAllTeamMembersByManagerId(int managerId);
}
