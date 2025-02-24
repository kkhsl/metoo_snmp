package com.metoo.controller;

import com.alibaba.fastjson.JSONObject;
import com.metoo.utils.SnmpManager;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class SNMPController {

    private static final Logger logger = LoggerFactory.getLogger(SNMPController.class);

    private Properties snmpConfig;

    /**
     * 初始化加载配置文件
     */
    @PostConstruct
    public void init() {
        try {
            snmpConfig = new Properties();
            // 从类路径加载配置文件
            InputStream inputStream = SNMPController.class.getClassLoader()
                    .getResourceAsStream("application.properties");
            if (inputStream == null) {
                throw new IOException("SNMP配置文件 application.properties 未找到");
            }
            snmpConfig.load(inputStream);
            logger.info("SNMP配置加载成功，共加载{}条规则", snmpConfig.size());
        } catch (IOException e) {
            logger.error("初始化SNMP配置失败", e);
            throw new RuntimeException("系统配置初始化失败", e);
        }
    }

    /**
     * 根据厂商和指令获取对应方法名
     * @param vendor 设备厂商
     * @param command 操作指令
     * @return 方法名，未找到返回null
     */
    public String getMethodName(String vendor, String command) {
        String key = String.format("%s.%s", vendor, command);
        String methodConfig = snmpConfig.getProperty(key);
        if (methodConfig != null) {
            return methodConfig;
        }
        return null;
    }

    /**
     * SNMP操作统一入口
     * @param host 目标主机
     * @param community SNMP社区名
     * @param ip 目标IP（可选）
     * @param oid 请求OID
     * @param vendor 设备厂商
     * @param command 操作指令
     * @return 标准化JSON响应
     */
    @GetMapping("/operate")
    public ResponseEntity<?> snmpOperation(
            @RequestParam String host,
            @RequestParam String community,
            @RequestParam(required = false) String ip,
            @RequestParam String oid,
            @RequestParam String vendor,
            @RequestParam String command
    ) {
        try {
            // 参数校验
            if (host == null || host.isEmpty() || community == null || community.isEmpty()) {
                return ResponseEntity.badRequest().body("缺少必要参数: host或community");
            }

            logger.info("收到SNMP请求: vendor={}, command={}, host={}", vendor, command, host);

            // 获取方法名
            String methodName = getMethodName(vendor, command);
            if (methodName == null) {
                logger.warn("未找到厂商[{}]指令[{}]对应方法", vendor, command);
                return ResponseEntity.notFound().build();
            }

            // 反射调用方法
            SnmpManager manager = new SnmpManager(host, community);
            Method targetMethod = SnmpManager.class.getMethod(methodName, String.class,String.class);
            Object result = targetMethod.invoke(manager, ip,oid);
            // 构造响应
            return ResponseEntity.ok()
                    .header("Content-Type", "application/json;charset=UTF-8")
                    .body(JSONObject.toJSONString(result));

        } catch (NoSuchMethodException e) {
            logger.error("方法不存在: {}", e.getMessage());
            return ResponseEntity.badRequest().body("无效的操作指令配置");
        } catch (InvocationTargetException | IllegalAccessException e) {
            logger.error("方法调用失败: {}", e.getCause().getMessage());
            return ResponseEntity.badRequest().body("方法调用失败");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}