package com.metoo.sdk;

import com.metoo.utils.SNMPException;
import com.metoo.utils.SnmpManager;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Properties;

public class SNMPSDK {
    private final Properties snmpConfig;

    public SNMPSDK() throws SNMPException {
        this("snmp.properties");
    }

    public SNMPSDK(String configPath) throws SNMPException {
        this.snmpConfig = loadConfig(configPath);
    }

    public SNMPSDK(Properties customConfig) {
        this.snmpConfig = customConfig;
    }

    private Properties loadConfig(String configPath) throws SNMPException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(configPath)) {
            if (inputStream == null) {
                throw new SNMPException("Config file not found: " + configPath);
            }
            Properties config = new Properties();
            config.load(inputStream);
            return config;
        } catch (IOException e) {
            throw new SNMPException("Failed to load config: " + configPath, e);
        }
    }


    private String getMethodName(String type, String vendor, String command) throws SNMPException {
        String key = String.format("%s.%s.%s", type, vendor, command);
        String methodName = snmpConfig.getProperty(key);

        if (methodName == null) {
            throw new SNMPException("No method mapping found for: " + key);
        }
        return methodName;
    }

    public Object operateV2C(
            String type,
            String host,
            String community,
            String ip,
            String oid,
            String vendor,
            String command
    ) throws SNMPException {
        validateParams(host, community, oid, vendor, command);
        SnmpManager manager = null;
        try {
            String methodName = getMethodName(type, vendor, command);
            manager = new SnmpManager(host, community);
            return invokeSnmpMethod(manager, methodName, ip, oid);
        } catch (Exception e) {
            handleException(e);
            return null;
        } finally {
            if (manager != null) {
                try {
                    manager.close();
                } catch (IOException e) {
                    return null;
                }
            }
        }
    }

    public Object operateV3(
            String type,
            String host,
            String ip,
            String oid,
            String vendor,
            String command,
            String securityName,
            int securityLevel,
            String authProtocol,
            String authPassword,
            String privProtocol,
            String privPassword
    ) throws SNMPException {
        validateParams(host, oid, vendor, command);
        SnmpManager manager = null;
        try {
            String methodName = getMethodName(type, vendor, command);
            manager = new SnmpManager(
                    host, securityName, securityLevel,
                    authProtocol, authPassword, privProtocol, privPassword);
            return invokeSnmpMethod(manager, methodName, ip, oid);
        } catch (Exception e) {
            handleException(e);
            return null;
        } finally {
            if (manager != null) {
                try {
                    manager.close();
                } catch (IOException e) {
                    return null;
                }
            }
        }
    }


    private void validateParams(String... params) throws SNMPException {
        if (params[0] == null || params[0].isEmpty() ||
                params[1] == null || params[1].isEmpty()) {
            throw new SNMPException("Missing required parameters");
        }
    }


    private Object invokeSnmpMethod(
            SnmpManager manager,
            String methodName,
            String ip,
            String oid
    ) throws Exception {
        Method method = SnmpManager.class.getMethod(methodName, String.class, String.class);
        return method.invoke(manager, ip, oid);
    }

    private void handleException(Exception e) throws SNMPException {
        if (e instanceof InvocationTargetException) {
            Throwable cause = e.getCause();
            throw new SNMPException("SNMP operation failed: " + cause.getMessage(), cause);
        }
        throw new SNMPException("SNMP operation error: " + e.getMessage(), e);
    }
}