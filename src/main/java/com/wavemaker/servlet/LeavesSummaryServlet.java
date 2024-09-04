package com.wavemaker.servlet;

import com.google.gson.Gson;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.model.LeavesSummary;
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

@WebServlet(urlPatterns = "/leaves_summary")
public class LeavesSummaryServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(LeavesSummaryServlet.class);
    private static Gson gson;
    private DashboardService dashboardService;

    @Override
    public void init(ServletConfig config) throws ServletException {
        gson = GsonConfig.createGson();
        try {
            dashboardService = new DashboardServiceImpl();
        } catch (SQLException e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        int employeeId = -1;
        String jsonResponse = null;
        try {
            employeeId = (Integer) session.getAttribute("AuthCookie");
            LeavesSummary leavesSummary = dashboardService.getLeaveSummaryById(employeeId);
            jsonResponse = gson.toJson(leavesSummary);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        } finally {
            JsonResponse.sendResponse(response, jsonResponse);
        }
    }

}
