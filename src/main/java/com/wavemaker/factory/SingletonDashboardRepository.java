package com.wavemaker.factory;

import com.wavemaker.repository.DashboardRepository;
import com.wavemaker.repository.impl.InDBDashboardRepository;

import java.sql.SQLException;

public class SingletonDashboardRepository {
    private static DashboardRepository dashboardRepository = null;

    public static DashboardRepository getInDBDashboardRepositoryInstance() throws SQLException {
        if (dashboardRepository != null) return dashboardRepository;
        dashboardRepository = new InDBDashboardRepository();
        return dashboardRepository;
    }
}
