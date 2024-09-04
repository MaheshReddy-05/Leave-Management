package com.wavemaker.filter;

import com.wavemaker.util.CookieStore;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.logging.Logger;

@WebFilter(urlPatterns = {"/employees", "/gender", "/leaves_summary", "/leave_request", "/logout", "/holidays",
        "/employee_had_team"})
public class AuthenticationFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(AuthenticationFilter.class.getName());

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession(false);

        if (session == null) {
            LOGGER.info("No session found, redirecting to login page.");
            LOGGER.info("Hello"+request.getContextPath() + "/index.html");
            response.sendRedirect(request.getContextPath() + "/index.html");
            return;
        }

        Integer employeeId = (Integer) session.getAttribute("AuthCookie");

        if (employeeId == null || employeeId == -1 || CookieStore.getCookieValue(employeeId) == null) {
            LOGGER.info("Failed authentication, redirecting to login page.");
            response.sendRedirect(request.getContextPath() + "/index.html");
            return;
        }

        filterChain.doFilter(request, response);
    }
}