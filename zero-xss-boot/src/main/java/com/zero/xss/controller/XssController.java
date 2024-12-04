package com.zero.xss.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/xss")
public class XssController {

    @RequestMapping("/hello")
    public Map<String, Object> showHelloWorld(){
        Map<String, Object> map = new HashMap<>();
        map.put("msg", "HelloWorld");
        return map;
    }

    @RequestMapping("/api/xss")
    public void xssApiTest(String name, String content) {
        System.out.println("api->name:"+name);
        System.out.println("api->content:"+content);
    }

    @RequestMapping("/ui/xss")
    public void xssUiTest(String name, String content) {
        System.out.println("ui->name:"+name);
        System.out.println("ui->content:"+content);
    }
}