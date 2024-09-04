package com.wavemaker.repository;

import com.wavemaker.model.Employee;
import com.wavemaker.model.Leave;
import com.wavemaker.model.LeavesSummary;
import com.wavemaker.model.RequestLeaves;

import java.util.List;

public interface LeaveRepository {
    public Leave applyLeave(Leave leave);

    public Leave updateLeave(Leave leave);

    public List<Leave> getAllLeavesByEmployeeId(int employeeId, String action);

    public List<RequestLeaves> getLeavesAsManager(int managerId, String action);
}
