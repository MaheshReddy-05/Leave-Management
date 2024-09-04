package com.wavemaker.servlet;

import com.google.gson.Gson;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.model.LeavesSummary;
import com.wavemaker.service.DashboardService;
import com.wavemaker.service.impl.DashboardServiceImpl;
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

@WebServlet(urlPatterns = "/team_leaves_summary")
public class TeamLeaveSummaryServlet extends HttpServlet {
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
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession();
        int employeeId = -1;
        String jsonResponse = null;
        try {
            employeeId = (Integer) session.getAttribute("AuthCookie");
            List<LeavesSummary> leavesSummary = dashboardService.getAllTeamMembersByManagerId(employeeId);
            jsonResponse = gson.toJson(leavesSummary);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        } finally {
            sendResponse(response, jsonResponse);
        }
    }
    private void sendResponse(HttpServletResponse httpServletResponse, String jsonResponse) {
        PrintWriter printWriter = null;
        try {
            httpServletResponse.setContentType("application/json");
            printWriter = httpServletResponse.getWriter();
            printWriter.print(jsonResponse);
            printWriter.flush();
        } catch (Exception e) {
            logger.error("Error while sending response");
        } finally {
            closePrintWriter(printWriter);
        }
    }
    private void closePrintWriter(PrintWriter printWriter) {
        if (printWriter != null) {
            printWriter.close();
        }
    }
}
