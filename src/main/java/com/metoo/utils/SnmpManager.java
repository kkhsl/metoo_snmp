package com.metoo.utils;

import com.alibaba.fastjson.JSONObject;
import com.google.gson.GsonBuilder;
import com.metoo.sdk.SNMPSDK;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import com.google.gson.Gson;
import java.io.IOException;
import java.util.*;

public class SnmpManager {

    private Snmp snmp;
    private final String community;
    private final String host;
    private final int port;
    private final int version;
    private final String securityName;
    private final int securityLevel;
    private final String authProtocol;
    private final String authPassword;
    private final String privProtocol;
    private final String privPassword;

    public static class Result {
        public int code;
        public Object data;
        public String msg;

        public Result(int code, Object data, String msg) {
            this.code = code;
            this.data = data;
            this.msg = msg;
        }
    }

    // 构造函数重载
    public SnmpManager(String host, String community) throws IOException {
        this(host, SnmpConstants.version2c, community, null,
                SecurityLevel.NOAUTH_NOPRIV, null, null, null, null);
    }

    public SnmpManager(String host, String securityName, int securityLevel,
                       String authProtocol, String authPassword,
                       String privProtocol, String privPassword) throws IOException {
        this(host, SnmpConstants.version3, null, securityName,
                securityLevel, authProtocol, authPassword, privProtocol, privPassword);
    }

    private SnmpManager(String host, int version, String community, String securityName,
                        int securityLevel, String authProtocol, String authPassword,
                        String privProtocol, String privPassword) throws IOException {
        String privPassword1;
        String privProtocol1;
        String authPassword1;
        String authProtocol1;
        this.host = host;
        this.port = 161;
        this.version = version;
        this.community = community;
        this.securityName = securityName;
        this.securityLevel = securityLevel;
        authProtocol1 = authProtocol;
        authPassword1 = authPassword;
        privProtocol1 = privProtocol;
        privPassword1 = privPassword;

        // 根据安全级别设置参数
        if (version == SnmpConstants.version3) {
            if (securityLevel == SecurityLevel.NOAUTH_NOPRIV) {
                // 不需要认证和隐私
                authProtocol1 = null;
                authPassword1 = null;
                privProtocol1 = null;
                privPassword1 = null;
            } else if (securityLevel == SecurityLevel.AUTH_NOPRIV) {
                // 需要认证但不需要隐私
                if (authProtocol == null || authPassword == null) {
                    throw new IllegalArgumentException("Auth parameters cannot be null for authNoPriv");
                }
            } else if (securityLevel == SecurityLevel.AUTH_PRIV) {
                // 需要认证和隐私
                if (authProtocol == null || authPassword == null || privProtocol == null || privPassword == null) {
                    throw new IllegalArgumentException("All security parameters must be provided for authPriv");
                }
            }
        }

        this.privPassword = privPassword1;
        this.privProtocol = privProtocol1;
        this.authPassword = authPassword1;
        this.authProtocol = authProtocol1;
        initialize();
    }

    private void initialize() throws IOException {
        TransportMapping transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);

        if (version == SnmpConstants.version3) {
            USM usm = new USM(SecurityProtocols.getInstance(),
                    new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);

            OID authOID = getAuthOID(authProtocol);
            OID privOID = getPrivOID(privProtocol);

            // 根据安全级别设置用户
            if (securityLevel == SecurityLevel.NOAUTH_NOPRIV) {
                // 不需要认证和隐私
                UsmUser user = new UsmUser(
                        new OctetString(securityName),
                        null, // authOID 为 null
                        null, // authPassword 为 null
                        null, // privOID 为 null
                        null  // privPassword 为 null
                );
                snmp.getUSM().addUser(new OctetString(securityName), user);
            } else if (securityLevel == SecurityLevel.AUTH_NOPRIV) {
                // 需要认证但不需要隐私
                if (authOID == null) {
                    throw new IllegalArgumentException("AuthOID cannot be null for auth protocol");
                }
                UsmUser user = new UsmUser(
                        new OctetString(securityName),
                        authOID,
                        new OctetString(authPassword != null ? authPassword : ""),
                        null, // privOID 为 null
                        null  // privPassword 为 null
                );
                snmp.getUSM().addUser(new OctetString(securityName), user);
            } else if (securityLevel == SecurityLevel.AUTH_PRIV) {
                // 需要认证和隐私
                if (authOID == null || privOID == null) {
                    throw new IllegalArgumentException("AuthOID and PrivOID cannot be null for authPriv");
                }
                UsmUser user = new UsmUser(
                        new OctetString(securityName),
                        authOID,
                        new OctetString(authPassword != null ? authPassword : ""),
                        privOID,
                        new OctetString(privPassword != null ? privPassword : "")
                );
                snmp.getUSM().addUser(new OctetString(securityName), user);
            }
        }

        transport.listen();
    }

    private OID getAuthOID(String authProtocol) {
        if (authProtocol == null) return null;
        switch (authProtocol.toUpperCase()) {
            case "SHA": return AuthSHA.ID;
            case "MD5": return AuthMD5.ID;
            default: throw new IllegalArgumentException("Unsupported auth protocol");
        }
    }

    private OID getPrivOID(String privProtocol) {
        if (privProtocol == null) return null;
        switch (privProtocol.toUpperCase()) {
            case "DES": return PrivDES.ID;
            case "AES": return PrivAES128.ID;
            default: throw new IllegalArgumentException("Unsupported priv protocol");
        }
    }

    private Target createTarget() {
        Target target;
        if (version == SnmpConstants.version3) {
            UserTarget userTarget = new UserTarget();
            userTarget.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
            userTarget.setSecurityLevel(securityLevel);
            userTarget.setSecurityName(new OctetString(securityName));
            userTarget.setTimeout(3000);
            userTarget.setRetries(1);
            target = userTarget;
        } else {
            CommunityTarget communityTarget = new CommunityTarget();
            communityTarget.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
            communityTarget.setCommunity(new OctetString(community));
            communityTarget.setVersion(version);
            communityTarget.setTimeout(3000);
            communityTarget.setRetries(1);
            target = communityTarget;
        }

        return target;
    }

    private ResponseEvent snmpGet(OID oid) throws IOException {
        PDU pdu;
        if (version == SnmpConstants.version3) {
            pdu = new ScopedPDU();
        } else {
            pdu = new PDU();
        }
        pdu.add(new VariableBinding(oid));
        pdu.setType(PDU.GET);
        return snmp.send(pdu, createTarget());
    }


    public void close() throws IOException {
        if (snmp != null) {
            snmp.close();
        }
    }


    // IPv6地址扩展（与Python逻辑一致）
    public static String expandIPv6(String ipv6) {
        if (ipv6.contains("::")) {
            String[] parts = ipv6.split("::", -1);
            List<String> left = new ArrayList<>(Arrays.asList(parts[0].split(":")));
            List<String> right = new ArrayList<>(Arrays.asList(parts[1].split(":")));
            int total = left.size() + right.size();
            int missing = 8 - total;

            List<String> full = new ArrayList<>(left);
            for (int i = 0; i < missing; i++) {
                full.add("0000");
            }
            full.addAll(right);

            return String.join(":", full.stream()
                    .map(s -> String.format("%4s", s).replace(' ', '0'))
                    .toArray(String[]::new));
        } else {
            String[] parts = ipv6.split(":");
            return String.join(":", Arrays.stream(parts)
                    .map(s -> String.format("%4s", s).replace(' ', '0'))
                    .toArray(String[]::new));
        }
    }


    public Result getHostname(String ipStr,String oidStr) {
        try {
            ResponseEvent event = snmpGet(new OID(oidStr));
            if (event.getResponse() == null) {
                return new Result(500, null, "No response");
            }
            String value = event.getResponse().get(0).getVariable().toString();
            return new Result(200, value.replace("STRING: ", "").replace("\"", ""), "");
        } catch (IOException e) {
            return new Result(500, null, e.getMessage());
        }
    }


    /**
     * 获取所有IPv4地址及其端口索引的映射
     * @param oidStr 目标OID（如 "1.3.6.1.2.1.4.20.1.2"）
     * @return 结构：{ "192.168.4.2": "195", ... }
     */
    public Result getIPv4PortMap(String ipStr,String oidStr) {
        Map<String, String> ipPortMap = new LinkedHashMap<>();
        try {
            List<VariableBinding> vbs = snmpWalk(new OID(oidStr));

            for (VariableBinding vb : vbs) {
                // 1. 从OID中提取IP地址（最后4个节点）
                int[] oidValues = vb.getOid().getValue();
                if (oidValues.length < 4) continue; // 跳过无效条目

                String ip = String.format("%d.%d.%d.%d",
                        oidValues[oidValues.length - 4],
                        oidValues[oidValues.length - 3],
                        oidValues[oidValues.length - 2],
                        oidValues[oidValues.length - 1]
                );

                // 2. 保存到Map：IP -> 端口索引
                ipPortMap.put(ip, vb.getVariable().toString());
            }

            return new Result(200, ipPortMap, "");
        } catch (IOException e) {
            return new Result(500, null, "SNMP操作失败: " + e.getMessage());
        }
    }


    public Result getIPv4Port(String ip, String oidStr) {
        try {
            List<VariableBinding> vbs = snmpWalk(new OID(oidStr));
            for (VariableBinding vb : vbs) {
                String oid = vb.getOid().toString();
                String value = vb.getVariable().toString();

                if (oid.endsWith(ip)) {
                    return new Result(200, value, "");
                }
            }
            return new Result(200, "", "Not found");
        } catch (IOException e) {
            return new Result(500, null, e.getMessage());
        }
    }

    /**
     * 获取所有IPv6地址及其端口索引的映射
     * @param oidStr 目标OID（如 "1.3.6.1.2.1.55.1.8.1.2"）
     * @return 结构：{ "2001:db8::1": "128", ... }
     */
    public Result getIPv6PortMap(String Str,String oidStr) {
        Map<String, String> ipv6PortMap = new LinkedHashMap<>();
        try {
            OID baseOid = new OID(oidStr);
            List<VariableBinding> vbs = snmpWalk(baseOid);

            for (VariableBinding vb : vbs) {
                // 1. 提取完整的OID（保留原始格式）
                OID oid = vb.getOid();
                String oidStrRepresentation = oid.toString(); // 使用原始OID字符串表示
                // 修改这一行，截取oidStrRepresentation里面oidStr后面的一个数字
                String[] parts = oidStrRepresentation.split("\\.");

                // 找到oidStr在parts中的索引
                int index = Arrays.asList(parts).indexOf(oidStr.split("\\.")[oidStr.split("\\.").length - 1]);

                // 确保索引有效并提取下一个数字作为port
                String port = (index + 1 < parts.length) ? parts[index + 1] : null; // 获取下一个部分作为port的值

                // 2. 如果需要，可以在此处处理 OID 格式（例如，提取IPv6或其他字段）
                if (port != null) {
                    ipv6PortMap.put(oidStrRepresentation, port);
                }
            }

            return new Result(200, ipv6PortMap, ""); // 返回提取的键值对
        } catch (IOException e) {
            return new Result(500, null, "SNMP操作失败: " + e.getMessage());
        }
    }




    public Result getIPv6Port(String ipv6, String oidStr) {
        try {
            String normalizedIPv6 = expandIPv6(ipv6);
            List<VariableBinding> vbs = snmpWalk(new OID(oidStr));

            // 计算基础 OID 的节点数
            int baseOidLength = new OID(oidStr).size();

            for (VariableBinding vb : vbs) {
                String fullOid = vb.getOid().toString();
                String[] oidParts = fullOid.split("\\.");

                if (oidParts.length > baseOidLength) {
                    // 直接取基础 OID 后的第一个节点
                    String key = oidParts[baseOidLength];

                    // 转换网段和匹配逻辑（保持不变）
                    String[] last17Parts = Arrays.copyOfRange(oidParts, oidParts.length - 17, oidParts.length);
                    String ipv6Segment = convertOidToIPv6Segment(last17Parts);

                    if (isInSubnet(normalizedIPv6, ipv6Segment)) {
                        return new Result(200, key, "");
                    }
                }
            }
            return new Result(200, "", "Not found");
        } catch (Exception e) {
            return new Result(500, null, e.getMessage());
        }
    }

    /**
     *安博通
     * @param
     * @return
     */
    public Result getAbtIPv6Port(String ipv6, String oidStr) {
        try {
            String normalizedIPv6 = expandIPv6(ipv6);
            List<VariableBinding> vbs = snmpWalk(new OID(oidStr));
            // 计算基础 OID 的节点数
            int baseOidLength = new OID(oidStr).size();

            for (VariableBinding vb : vbs) {
                String fullOid = vb.getOid().toString();
                String key = vb.getVariable().toString();
                String[] oidParts = fullOid.split("\\.");

                if (oidParts.length > baseOidLength) {
                    // 转换网段和匹配逻辑（保持不变）
                    String[] last16Parts = Arrays.copyOfRange(oidParts, oidParts.length - 16, oidParts.length);
                    String iPv6Address = convertOidToIPv6Address(last16Parts);
                    if (iPv6Address.toUpperCase().equalsIgnoreCase(normalizedIPv6)) {
                        return new Result(200, key, "");
                    }
                }
            }
            return new Result(200, "", "Not found");
        } catch (Exception e) {
            return new Result(500, "", e.getMessage());
        }
    }
    public Result getInspurIPv6Port(String ipv6, String oidStr) {
        try {
            String normalizedIPv6 = expandIPv6(ipv6);
            List<VariableBinding> vbs = snmpWalk(new OID(oidStr));
            // 计算基础 OID 的节点数
            int baseOidLength = new OID(oidStr).size();

            for (VariableBinding vb : vbs) {
                String fullOid = vb.getOid().toString();
                String key = vb.getVariable().toString();
                String[] oidParts = fullOid.split("\\.");

                // 检查 oidParts 长度是否满足要求
                if (oidParts.length > baseOidLength + 16) {
                    // 转换网段和匹配逻辑
                    String[] last16Parts = Arrays.copyOfRange(oidParts, oidParts.length - 16, oidParts.length);
                    String iPv6Address = convertOidToIPv6Address(last16Parts);
                    // 匹配逻辑
                    if (iPv6Address.equalsIgnoreCase(normalizedIPv6)) {
                        return new Result(200, key, "");
                    }
                }
            }
            return new Result(200, "", "Not found");
        } catch (Exception e) {
            return new Result(500, "", e.getMessage());
        }
    }

    private String convertOidToIPv6Address(String[] oidParts) {
        if (oidParts.length != 16) {
            throw new IllegalArgumentException("需要16个OID节点");
        }

        // 解析前16组（每组2字节）
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            int val = Integer.parseInt(oidParts[i]);
            hex.append(String.format("%02x", val & 0xFF));
        }

        // 格式化为IPv6地址
        return formatIPv6(hex.toString().toUpperCase());
    }


    // 将最后17个OID节点转换为IPv6网段
    private String convertOidToIPv6Segment(String[] oidParts) {
        if (oidParts.length != 17) {
            throw new IllegalArgumentException("需要17个OID节点");
        }

        // 解析前8组（每组2字节）
        StringBuilder hex = new StringBuilder();
        for (int i =0; i<16; i++) {
            int val = Integer.parseInt(oidParts[i]);
            hex.append(String.format("%02x", val & 0xFF));
        }

        // 格式化为IPv6地址并添加前缀长度
        String ipv6 = formatIPv6(hex.toString());
        int prefixLen = Integer.parseInt(oidParts[16]);
        return ipv6 + "/" + prefixLen;
    }

    // IPv6地址格式化和压缩
    private String formatIPv6(String hexStr) {
        // 添加冒号分隔
        String raw = hexStr.replaceAll("(.{4})", "$1:").replaceAll(":$", "");

        // 压缩连续的零段
        return raw.replaceAll("(:0){2,}", "::");
    }

    // 检查IPv6地址是否在网段内
    private boolean isInSubnet(String ipv6, String subnet) {
        try {
            String[] parts = subnet.split("/");
            int prefixLen = Integer.parseInt(parts[1]);
            String network = expandIPv6(parts[0]);
            String target = expandIPv6(ipv6);

            // 比较前prefixLen位
            return target.startsWith(network.substring(0, prefixLen/4));
        } catch (Exception e) {
            return false;
        }
    }



    /**
     * 获取 Hillstone 设备的 IPv6 端口信息
     * @param ipv6     IPv6 地址（压缩格式，如 "2001:db8::1"）
     * @param oidStr   厂商私有 OID（如 "1.3.6.1.4.1.2011.5.25.42"）
     * @return 结构：{ "code": 200, "data": "端口索引", "msg": "" }
     */
    public Result getIPv6PortHillstone(String ipv6, String oidStr) {
        try {
            String normalizedIPv6 = expandIPv6(ipv6);
            List<VariableBinding> vbs = snmpWalk(new OID(oidStr));

            // 计算基础 OID 的节点数
            int baseOidLength = new OID(oidStr).size();

            for (VariableBinding vb : vbs) {
                String fullOid = vb.getOid().toString();
                String[] oidParts = fullOid.split("\\.");

                if (oidParts.length > baseOidLength) {
                    // 直接取基础 OID 后的第一个节点
                    String key = oidParts[baseOidLength];

                    // 转换网段和匹配逻辑（保持不变）
                    String[] last17Parts = Arrays.copyOfRange(oidParts, oidParts.length - 17, oidParts.length);
                    String ipv6Segment = convertOidToIPv6Segment(last17Parts);

                    if (isInSubnet(normalizedIPv6, ipv6Segment)) {
                        return new Result(200, key, "");
                    }
                }
            }
            return new Result(200, "", "Not found");
        } catch (Exception e) {
            return new Result(500, null, e.getMessage());
        }
    }

    private List<VariableBinding> snmpWalk(OID baseOid) throws IOException {
        List<VariableBinding> results = new ArrayList<>();
        OID currentOid = baseOid;
        while (true) {
            PDU pdu; // 声明 PDU 变量
            if (version == SnmpConstants.version3) {
                pdu = new ScopedPDU(); // 使用 ScopedPDU
            } else {
                pdu = new PDU(); // 使用普通的 PDU
            }

            pdu.add(new VariableBinding(currentOid));
            ResponseEvent event = snmp.getNext(pdu, createTarget());
            PDU response = event.getResponse();

            // 检查响应是否有效
            if (response == null || response.size() == 0) {
                break;
            }

            VariableBinding vb = response.get(0);
            if (!vb.getOid().startsWith(baseOid)) {
                break;
            }

            results.add(vb);
            currentOid = vb.getOid();
        }
        return results;
    }

    public Result getTraffic(String ipStr,String oidStr) {
        try {
            List<VariableBinding> vbs = snmpWalk(new OID(oidStr));
            if (vbs.isEmpty()) {
                return new Result(200, "", "No traffic data found");
            }

            Map<String, String> trafficData = new HashMap<>();
            for (VariableBinding vb : vbs) {
                String oid = vb.getOid().toString();
                String value = vb.getVariable().toString();
                trafficData.put(oid, value); // 将 OID 和流量值存入 Map
            }

            return new Result(200, trafficData, "");
        } catch (IOException e) {
            return new Result(500, null, e.getMessage());
        }
    }


    public Result getTrafficByPort(String ipStr,String oidStr) {
        try {
            // 去掉最后一个部分
            String baseOidStr = oidStr.substring(0, oidStr.lastIndexOf('.')); // 去掉最后一个数字
            List<VariableBinding> vbs = snmpWalk(new OID(baseOidStr)); // 执行 SNMP 查询
            if (vbs.isEmpty()) {
                return new Result(200, "", "No traffic data found"); // 如果没有数据，返回null
            }

            // 获取传入 OID 的最后一个部分
            String[] oidParts = oidStr.split("\\.");
            String lastPart = oidParts[oidParts.length - 1];

            // 遍历 VariableBinding 列表
            for (VariableBinding vb : vbs) {
                String oid = vb.getOid().toString(); // 获取 OID
                if (oid.endsWith("." + lastPart)) { // 检查 OID 的最后一个部分是否匹配
                    String value = vb.getVariable().toString(); // 获取对应的值
                    return new Result(200, value, ""); // 返回结果
                }
            }

            return new Result(200,"", "Traffic data not found for port: " + lastPart); // 如果没有找到匹配的 OID
        } catch (IOException e) {
            return new Result(500, null, e.getMessage()); // 处理异常
        }
    }




    public Map<String, String> getPortNameMap(String Str,String oidStr) {
        Map<String, String> portNameMap = new LinkedHashMap<>();
        try {
            OID baseOid = new OID(oidStr);
            List<VariableBinding> vbs = snmpWalk(baseOid);

            for (VariableBinding vb : vbs) {
                // 1. 提取完整的OID（保留原始格式）
                OID oid = vb.getOid();
                String portName = vb.getVariable().toString();
                String oidStrRepresentation = oid.toString(); // 使用原始OID字符串表示
                // 2. 如果需要，可以在此处处理 OID 格式（）
                String[] oidParts = oidStrRepresentation.split("\\.");
                String lastPart = oidParts[oidParts.length - 1]; // 取最后一位

                if (lastPart != null) {
                    portNameMap.put(lastPart, portName);
                }
            }

            return portNameMap; // 返回提取的键值对
        } catch (IOException e) {
            return null;
        }
    }
    public Map<String, String> getPortStatusMap(String Str,String oidStr) {
        Map<String, String> portStatusMap = new LinkedHashMap<>();
        try {
            OID baseOid = new OID(oidStr);
            List<VariableBinding> vbs = snmpWalk(baseOid);

            for (VariableBinding vb : vbs) {
                // 1. 提取完整的OID（保留原始格式）
                OID oid = vb.getOid();
                String portStatus = vb.getVariable().toString();
                String oidStrRepresentation = oid.toString(); // 使用原始OID字符串表示
                // 2. 如果需要，可以在此处处理 OID 格式（）
                String[] oidParts = oidStrRepresentation.split("\\.");
                String lastPart = oidParts[oidParts.length - 1]; // 取最后一位

                if (lastPart != null) {
                    portStatusMap.put(lastPart, portStatus);
                }
            }

            return portStatusMap; // 返回提取的键值对
        } catch (IOException e) {
            return null;
        }
    }

    public Result getPortInfo(String Str, String oidStr) {
        Map<String, String> portNameMap;
        Map<String, String> portStatusMap;
        List<Map<String, String>> mergedList = new ArrayList<>();

        try {
            // 获取端口名称
            portNameMap = getPortNameMap(Str, "1.3.6.1.2.1.2.2.1.2");
            if (portNameMap == null) {
                return new Result(500, null, "Failed to retrieve port names.");
            }

            // 获取端口状态
            portStatusMap = getPortStatusMap(Str, "1.3.6.1.2.1.2.2.1.8");
            if (portStatusMap == null) {
                return new Result(500, null, "Failed to retrieve port statuses.");
            }

            // 合并端口信息
            for (String index : portNameMap.keySet()) {
                Map<String, String> portInfo = new LinkedHashMap<>();
                String portName = portNameMap.get(index);
                String portStatus = portStatusMap.get(index);

                portInfo.put("portName", portName != null ? portName : "null");
                portInfo.put("index", index);
                portInfo.put("status", portStatus != null ? portStatus : "null");

                mergedList.add(portInfo);
            }

            return new Result(200, mergedList, ""); // 返回合并的结果
        } catch (Exception e) {
            // 处理其他异常
            return new Result(500, null, "An unexpected error occurred: " + e.getMessage());
        }
    }


    public static void main(String[] args) {
        try {
            // 初始化SNMP管理器（目标设备IP和社区字符串）
            //
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

//            Object object1 = new SNMPSDK().operateV2C("fw", "192.168.6.1", "public@123", "", "1.3.6.1.2.1.1.5.0", "h3c", "test");
//            System.out.println(JSONObject.toJSON(object1));
//
//            Object object = new SNMPSDK().operateV2C("global", "192.168.6.1", "public@123", "", "1.3.6.1.2.1.2.2.1.2", "all", "get_port_info");
//            System.out.println(JSONObject.toJSON(object));

//            Object object = new SNMPSDK().operateV2C("fw", "192.168.6.1", "public@123", "192.168.4.2", "1.3.6.1.2.1.4.20.1.2", "stone", "get_ipv4_port");
//            System.out.println(JSONObject.toJSON(object));

//            SnmpManager manager18 = new SnmpManager("192.168.6.1", "public@123");
//            Map<String, String> hostnameResult18 = manager18.getPortNameMap("", "1.3.6.1.2.1.2.2.1.2");
//            System.out.println("\n=== 测试1. 获取所有portName ===");
//            System.out.println(hostnameResult18);
//
//
//            SnmpManager manager19 = new SnmpManager("192.168.6.1", "public@123");
//            Map<String, String> hostnameResult19 = manager19.getPortStatusMap("", "1.3.6.1.2.1.2.2.1.8");
//            System.out.println("\n=== 测试2. 获取所有portStatus ===");
//            System.out.println(hostnameResult19);

//            SnmpManager manager30 = new SnmpManager("192.168.6.1", "public@123");
//            Result hostnameResult30 = manager30.getPortInfo("", "1.3.6.1.2.1.2.2.1.2");
//            System.out.println("\n=== 测试2. 获取所有portInfo ===");
//            System.out.println(gson.toJson(hostnameResult30));

                        // snmpwalk -v 3 -u user_test -l noAuthNoPriv 192.168.6.1
//            SnmpManager manager =  new SnmpManager(
//                    "192.168.6.1",
//                    "user_test",
//                    SecurityLevel.NOAUTH_NOPRIV,
//                    null, null, null, null
//            );
//            Result result = manager.getPortInfo("", "1.3.6.1.2.1.2.2.1.2");
//            System.out.println("=== noAuthNoPriv 测试结果 ===");
//            System.out.println(gson.toJson(result));
            // --------------------------

//            SnmpManager manager1 = new SnmpManager(
//                    "192.168.6.1",
//                    "user-test2",
//                    SecurityLevel.AUTH_NOPRIV,
//                    "MD5", "metoo8974500",
//                    null, null
//            );
//            Result result1 = manager1.getPortInfo("", "1.3.6.1.2.1.2.2.1.2");
//            System.out.println("=== AUTH_NOPRIV 测试结果 ===");
//            System.out.println(gson.toJson(result1));

            // --------------------------

//            SnmpManager manager2 = new SnmpManager(
//                    "192.168.6.1",
//                    "user_test3",
//                    SecurityLevel.AUTH_PRIV,
//                    "MD5", "metoo8974500",
//                    "DES", "Metoo89745000"
//            );
//            Result result2 = manager2.getPortInfo("", "1.3.6.1.2.1.2.2.1.2");
//            System.out.println("=== AUTH_PRIV 测试结果 ===");
//            System.out.println(gson.toJson(result2));



//            // --------------------------
//            // 测试1. 获取设备主机名
//            //v2c
//            // OID: 1.3.6.1.2.1.1.5.0 (sysName)
//            SnmpManager manager11 = new SnmpManager("192.168.6.1", "public@123");
//            Result hostnameResult = manager11.getHostname("", "1.3.6.1.2.1.1.5.0");
//            System.out.println("\n=== 测试1. 主机名 ===");
//            System.out.println(gson.toJson(hostnameResult));
//
//            // snmpwalk -v 3 -u user_test -l noAuthNoPriv 192.168.6.1
//            SnmpManager manager =  new SnmpManager(
//                    "192.168.6.1",
//                    "user_test",
//                    SecurityLevel.NOAUTH_NOPRIV,
//                    null, null, null, null
//            );
//            Result result = manager.getHostname("", "1.3.6.1.2.1.1.5.0");
//            System.out.println("=== noAuthNoPriv 测试结果 ===");
//            System.out.println(gson.toJson(result));
//            // --------------------------
//
//            SnmpManager manager1 = new SnmpManager(
//                    "192.168.6.1",
//                    "user-test2",
//                    SecurityLevel.AUTH_NOPRIV,
//                    "MD5", "metoo8974500",
//                    null, null
//            );
//            Result result1 = manager1.getHostname("", "1.3.6.1.2.1.1.5.0");
//            System.out.println("=== AUTH_NOPRIV 测试结果 ===");
//            System.out.println(gson.toJson(result1));
//
//            // --------------------------
//
//            SnmpManager manager2 = new SnmpManager(
//                    "192.168.6.1",
//                    "user_test3",
//                    SecurityLevel.AUTH_PRIV,
//                    "MD5", "metoo8974500",
//                    "DES", "Metoo89745000"
//            );
//            Result result2 = manager2.getHostname("", "1.3.6.1.2.1.1.5.0");
//            System.out.println("=== AUTH_PRIV 测试结果 ===");
//            System.out.println(gson.toJson(result2));


//            // 测试获取IPv4端口映射
//            SnmpManager manager01 = new SnmpManager("192.168.6.1", "public@123");
//            Result result01 = manager01.getIPv4PortMap("","1.3.6.1.2.1.4.20.1.2");
//            System.out.println("=== IPv4地址-全部端口映射 ===");
//            System.out.println(gson.toJson(result01));



//            // --------------------------
//            // 测试2. 获取IPv4端口信息
//            //v2c
//            // OID: 1.3.6.1.2.1.4.20.1.2 (ipAddressIfIndex)
//            // 测试IP: 192.168.4.2
//            // --------------------------
//            SnmpManager manager12 = new SnmpManager("192.168.6.1", "public@123");
//            Result ipv4PortResult = manager12.getIPv4Port("192.168.4.2", "1.3.6.1.2.1.4.20.1.2");
//            System.out.println("\n=== 测试2. IPv4地址指定映射 ===");
//            System.out.println(gson.toJson(ipv4PortResult));
//
//            // snmpwalk -v 3 -u user_test -l noAuthNoPriv 192.168.6.1
//            SnmpManager manager6 =  new SnmpManager(
//                    "192.168.6.1",
//                    "user_test",
//                    SecurityLevel.NOAUTH_NOPRIV,
//                    null, null, null, null
//            );
//            Result result6 = manager6.getIPv4Port("192.168.4.2", "1.3.6.1.2.1.4.20.1.2");
//            System.out.println("=== noAuthNoPriv 测试结果 ===");
//            System.out.println(gson.toJson(result6));
//            // --------------------------
//
//            SnmpManager manager7 = new SnmpManager(
//                    "192.168.6.1",
//                    "user-test2",
//                    SecurityLevel.AUTH_NOPRIV,
//                    "MD5", "metoo8974500",
//                    null, null
//            );
//            Result result7 = manager7.getIPv4Port("192.168.4.2", "1.3.6.1.2.1.4.20.1.2");
//            System.out.println("=== AUTH_NOPRIV 测试结果 ===");
//            System.out.println(gson.toJson(result7));
//
//            // --------------------------
//
//            SnmpManager manager9 = new SnmpManager(
//                    "192.168.6.1",
//                    "user_test3",
//                    SecurityLevel.AUTH_PRIV,
//                    "MD5", "metoo8974500",
//                    "DES", "Metoo89745000"
//            );
//            Result result9 = manager9.getIPv4Port("192.168.4.2", "1.3.6.1.2.1.4.20.1.2");
//            System.out.println("=== AUTH_PRIV 测试结果 ===");
//            System.out.println(gson.toJson(result9));
//
//

//            // 测试获取IPv6全部端口映射
//            SnmpManager manager02 = new SnmpManager("192.168.6.1", "public@123");
//            Result IPv6Portresult02 = manager02.getIPv6PortMap("","1.3.6.1.2.1.4.32.1.5");
//            System.out.println("=== IPv6地址-全部端口映射 ===");
//            System.out.println(gson.toJson(IPv6Portresult02));

            //--------------------------
            // 测试3. 获取指定IPv6端口信息
            // OID: 1.3.6.1.2.1.4.32.1.5 (ipv6IfIndex)
            // --------------------------
//            SnmpManager manager16 = new SnmpManager("192.168.6.1", "public@123");
//            Result ipv6PortResult16 = manager16.getIPv6Port("2400:3030:aa12:1978::1", "1.3.6.1.2.1.4.32.1.5");
//            System.out.println("\n=== 测试3. 指定IPv6端口映射 ===");
//            System.out.println(gson.toJson(ipv6PortResult16));



            SnmpManager manager89 = new SnmpManager("117.40.252.175", "gaslj");
            Result ipv6PortResult89 = manager89.getInspurIPv6Port("240e:670:7200::7", "1.3.6.1.2.1.4.34.1.3");// 1.3.6.1.2.1.4.34.1.3.2
            System.out.println("\n=== 测试abt 指定IPv6端口映射 ===");
            System.out.println(gson.toJson(ipv6PortResult89));

//                        SnmpManager manager89 = new SnmpManager("240e:380:2:42ba:5a48:496c:5a29:bc10", "read@public");
//            Result ipv6PortResult89 = manager89.getAbtIPv6Port("240E:380:2:3E6C:5A48:4944:EB29:BC10", "1.3.6.1.2.1.4.34.1.3.2");// 1.3.6.1.2.1.4.34.1.3.2
//            System.out.println("\n=== 测试abt 指定IPv6端口映射 ===");
//            System.out.println(gson.toJson(ipv6PortResult89));



            // snmpwalk -v 3 -u user_test -l noAuthNoPriv 192.168.6.1
//            SnmpManager manager17 =  new SnmpManager(
//                    "192.168.6.1",
//                    "user_test",
//                    SecurityLevel.NOAUTH_NOPRIV,
//                    null, null, null, null
//            );
//            Result result17 = manager17.getIPv6Port("2400:3030:aa12:1978::1", "1.3.6.1.2.1.4.32.1.5");
//            System.out.println("=== noAuthNoPriv 测试结果 ===");
//            System.out.println(gson.toJson(result17));
//            // --------------------------
//
//            SnmpManager manager18 = new SnmpManager(
//                    "192.168.6.1",
//                    "user-test2",
//                    SecurityLevel.AUTH_NOPRIV,
//                    "MD5", "metoo8974500",
//                    null, null
//            );
//            Result result18 = manager18.getIPv6Port("2400:3030:aa12:1978::1", "1.3.6.1.2.1.4.32.1.5");
//            System.out.println("=== AUTH_NOPRIV 测试结果 ===");
//            System.out.println(gson.toJson(result18));
//
//            // --------------------------
//
//            SnmpManager manager19 = new SnmpManager(
//                    "192.168.6.1",
//                    "user_test3",
//                    SecurityLevel.AUTH_PRIV,
//                    "MD5", "metoo8974500",
//                    "DES", "Metoo89745000"
//            );
//            Result result19 = manager19.getIPv6Port("2400:3030:aa12:1978::1", "1.3.6.1.2.1.4.32.1.5");
//            System.out.println("=== AUTH_PRIV 测试结果 ===");
//            System.out.println(gson.toJson(result19));





            // --------------------------
            // 测试4. Hillstone设备IPv6端口
            // OID: 1.3.6.1.4.1.2011.5.25.42 (厂商私有OID)
            // 测试IP: 2001:db8::c0a8:6401
            // --------------------------
//            Result hillstonePortResult = manager.getIPv6PortHillstone("2001:db8::c0a8:6401", "1.3.6.1.4.1.2011.5.25.42");
//            System.out.println("\n=== 测试4. Hillstone IPv6端口 ===");
//            System.out.println(gson.toJson(hillstonePortResult));

            // --------------------------
            // 测试5. 获取全部流量统计
            // OID: 1.3.6.1.2.1.31.1.1.1.10 (ifHCInOctets)
            // --------------------------
//            SnmpManager manager03 = new SnmpManager("192.168.6.1", "public@123");
//            Result trafficResult03 = manager03.getTraffic("","1.3.6.1.2.1.2.2.1.10");
//            System.out.println("\n=== 测试5. 全部流量统计 ===");
//            System.out.println(gson.toJson(trafficResult03));


//            SnmpManager manager21 = new SnmpManager("192.168.6.1", "public@123");
//            Result trafficByOidResult = manager21.getTrafficByPort("","1.3.6.1.2.1.2.2.1.10.195");
//            System.out.println("\n=== 测试5. 指定流量统计 ===");
//            System.out.println(gson.toJson(trafficByOidResult));

            // snmpwalk -v 3 -u user_test -l noAuthNoPriv 192.168.6.1
//            SnmpManager manager27 =  new SnmpManager(
//                    "192.168.6.1",
//                    "user_test",
//                    SecurityLevel.NOAUTH_NOPRIV,
//                    null, null, null, null
//            );
//            Result result27 = manager27.getTrafficByPort("2400:3030:aa12:1978::1", "1.3.6.1.2.1.2.2.1.10.195");
//            System.out.println("=== noAuthNoPriv 测试结果 ===");
//            System.out.println(gson.toJson(result27));
//            // --------------------------
//
//            SnmpManager manager28 = new SnmpManager(
//                    "192.168.6.1",
//                    "user-test2",
//                    SecurityLevel.AUTH_NOPRIV,
//                    "MD5", "metoo8974500",
//                    null, null
//            );
//            Result result28 = manager28.getTrafficByPort("2400:3030:aa12:1978::1", "1.3.6.1.2.1.2.2.1.10.195");
//            System.out.println("=== AUTH_NOPRIV 测试结果 ===");
//            System.out.println(gson.toJson(result28));
//
//            // --------------------------
//
//            SnmpManager manager29 = new SnmpManager(
//                    "192.168.6.1",
//                    "user_test3",
//                    SecurityLevel.AUTH_PRIV,
//                    "MD5", "metoo8974500",
//                    "DES", "Metoo89745000"
//            );
//            Result result29 = manager29.getTrafficByPort("2400:3030:aa12:1978::1", "1.3.6.1.2.1.2.2.1.10.195");
//            System.out.println("=== AUTH_PRIV 测试结果 ===");
//            System.out.println(gson.toJson(result29));


        } catch (IOException e) {
            System.err.println("【严重错误】SNMP连接失败:");
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("【运行时错误】:");
            e.printStackTrace();
        }
    }
}
