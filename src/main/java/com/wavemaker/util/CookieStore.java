package com.wavemaker.util;

import java.util.HashMap;
import java.util.Map;

public class CookieStore {
    public static Map<Integer, String> cookiesMap = new HashMap<>();

    public static String getCookieValue(int employeeId) {
        return cookiesMap.get(employeeId);
    }

    public static void addUserCookie(int employeeId, String cookieValue) {
        cookiesMap.put(employeeId, cookieValue);
    }

}
