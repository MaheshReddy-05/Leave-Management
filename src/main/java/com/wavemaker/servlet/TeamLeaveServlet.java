package com.wavemaker.servlet;

import com.google.gson.Gson;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.model.RequestLeaves;
import com.wavemaker.service.LeaveService;
import com.wavemaker.service.impl.LeaveServiceImpl;
import com.wavemaker.util.JsonResponse;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.List;

@WebServlet(urlPatterns = "/leave_request")
public class TeamLeaveServlet extends HttpServlet {
    private static Gson gson;
    private static LeaveService leaveService;

    @Override
    public void init(ServletConfig config) throws ServletException {
        gson = GsonConfig.createGson();
        try {
            leaveService = new LeaveServiceImpl();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String jsonResponse = null;
        String action = req.getParameter("status");
        HttpSession session = req.getSession(false);
        int managerId = (Integer) session.getAttribute("AuthCookie");
        List<RequestLeaves> listRequestLeaves = leaveService.getLeavesAsManager(managerId, action);
        jsonResponse = gson.toJson(listRequestLeaves);
        JsonResponse.sendResponse(resp, jsonResponse);
    }
}
