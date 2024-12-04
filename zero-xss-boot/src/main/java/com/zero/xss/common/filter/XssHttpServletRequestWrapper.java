package com.zero.xss.common.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {
    public XssHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }
    @Override
    public String[] getParameterValues(String name) {
        // Customize rules based on actual needs. Here, the content field is rich text and does not need to be filtered.
        if ("content".equals(name)) {
            return super.getParameterValues(name);
        }
        String[] values = super.getParameterValues(name);
        if (values != null) {
            int length = values.length;
            String[] escapseValues = new String[length];
            for (int i = 0; i < length; i++) {
                // Prevent xss attacks and filter leading and trailing spaces
                // 旧版本
//                escapseValues[i] = Jsoup.clean(values[i], Whitelist.relaxed()).trim();
                escapseValues[i] = Jsoup.clean(values[i], Safelist.relaxed()).trim();
            }
            return escapseValues;
        }
        return super.getParameterValues(name);
    }
}