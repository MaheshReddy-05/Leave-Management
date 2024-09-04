package com.wavemaker.servlet;

import com.google.gson.Gson;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.model.Leave;
import com.wavemaker.service.DashboardService;
import com.wavemaker.service.impl.DashboardServiceImpl;
import com.wavemaker.util.JsonResponse;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.List;

@WebServlet(urlPatterns = "/recent_leaves")
public class RecentLeavesServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(RecentLeavesServlet.class);
    private static Gson gson;
    private DashboardService dashboardService;

    @Override
    public void init(ServletConfig config) throws ServletException {
        gson = GsonConfig.createGson();
        try {
            dashboardService = new DashboardServiceImpl();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession(false);



        String jsonResponse = null;
        List<Leave> leaveList = null;
        try {
            int employeeId = (Integer) session.getAttribute("AuthCookie");
            leaveList = dashboardService.getTopFourApprovedLeaveByEmployeeId(employeeId);
            jsonResponse = gson.toJson(leaveList);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        } finally {
            JsonResponse.sendResponse(response, jsonResponse);
        }
    }
}
