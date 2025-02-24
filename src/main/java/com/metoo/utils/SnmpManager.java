package com.metoo.utils;

import com.google.gson.GsonBuilder;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
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

    public SnmpManager(String host, String community) throws IOException {
        this.host = host;
        this.community = community;
        this.port = 161;
        this.version = SnmpConstants.version2c;
        initialize();
    }

    private void initialize() throws IOException {
        TransportMapping transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        transport.listen();
    }

    private Target createTarget() {
        CommunityTarget target = new CommunityTarget();
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setCommunity(new OctetString(community));
        target.setVersion(version);
        target.setTimeout(3000);
        target.setRetries(1);
        return target;
    }

    private ResponseEvent snmpGet(OID oid) throws IOException {
        PDU pdu = new PDU();
        pdu.add(new VariableBinding(oid));
        pdu.setType(PDU.GET);
        return snmp.send(pdu, createTarget());
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
            return new Result(404, null, "Not found");
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
            return new Result(404, null, "Not found");
        } catch (Exception e) {
            return new Result(500, null, e.getMessage());
        }
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
            return new Result(404, null, "Not found");
        } catch (Exception e) {
            return new Result(500, null, e.getMessage());
        }
    }

    private List<VariableBinding> snmpWalk(OID baseOid) throws IOException {
        List<VariableBinding> results = new ArrayList<>();
        OID currentOid = baseOid;
        while (true) {
            PDU pdu = new PDU();
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
                return new Result(404, null, "No traffic data found");
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
                return new Result(404, null, "No traffic data found"); // 如果没有数据，返回404
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

            return new Result(404, null, "Traffic data not found for port: " + lastPart); // 如果没有找到匹配的 OID
        } catch (IOException e) {
            return new Result(500, null, e.getMessage()); // 处理异常
        }
    }

    public static void main(String[] args) {
        try {
            // 初始化SNMP管理器（目标设备IP和社区字符串）
            SnmpManager manager = new SnmpManager("192.168.6.1", "public@123");
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            // --------------------------
            // 测试1. 获取设备主机名
            // OID: 1.3.6.1.2.1.1.5.0 (sysName)
            // --------------------------
            Result hostnameResult = manager.getHostname("","1.3.6.1.2.1.1.5.0");
            System.out.println("\n=== 测试1. 主机名 ===");
            System.out.println(gson.toJson(hostnameResult));


            // 测试获取IPv4端口映射
            Result result = manager.getIPv4PortMap("","1.3.6.1.2.1.4.20.1.2");
            System.out.println("=== IPv4地址-端口映射 ===");
            System.out.println(gson.toJson(result));


            // --------------------------
            // 测试2. 获取IPv4端口信息
            // OID: 1.3.6.1.2.1.4.20.1.2 (ipAddressIfIndex)
            // 测试IP: 192.168.4.2
            // --------------------------
            Result ipv4PortResult = manager.getIPv4Port("192.168.4.2", "1.3.6.1.2.1.4.20.1.2");
            System.out.println("\n=== 测试2. IPv4地址指定映射 ===");
            System.out.println(gson.toJson(ipv4PortResult));


            // 测试获取IPv6全部端口映射
            Result IPv6Portresult = manager.getIPv6PortMap("","1.3.6.1.2.1.4.32.1.5");
            System.out.println("=== IPv6地址-端口映射 ===");
            System.out.println(gson.toJson(IPv6Portresult));
            //--------------------------
            // 测试3. 获取指定IPv6端口信息
            // OID: 1.3.6.1.2.1.4.32.1.5 (ipv6IfIndex)
            // --------------------------
            Result ipv6PortResult = manager.getIPv6Port("2400:3030:aa12:1978::1", "1.3.6.1.2.1.4.32.1.5");
            System.out.println("\n=== 测试3. 指定IPv6端口映射 ===");
            System.out.println(gson.toJson(ipv6PortResult));

            // --------------------------
            // 测试4. Hillstone设备IPv6端口
            // OID: 1.3.6.1.4.1.2011.5.25.42 (厂商私有OID)
            // 测试IP: 2001:db8::c0a8:6401
            // --------------------------
//            Result hillstonePortResult = manager.getIPv6PortHillstone("2001:db8::c0a8:6401", "1.3.6.1.4.1.2011.5.25.42");
//            System.out.println("\n=== 测试4. Hillstone IPv6端口 ===");
//            System.out.println(gson.toJson(hillstonePortResult));

            // --------------------------
            // 测试5. 获取流量统计
            // OID: 1.3.6.1.2.1.31.1.1.1.10 (ifHCInOctets)
            // --------------------------
            Result trafficResult = manager.getTraffic("","1.3.6.1.2.1.2.2.1.10");
            System.out.println("\n=== 测试5. 全部流量统计 ===");
            System.out.println(gson.toJson(trafficResult));


            Result trafficByOidResult = manager.getTrafficByPort("","1.3.6.1.2.1.2.2.1.10.195");
            System.out.println("\n=== 测试5. 指定流量统计 ===");
            System.out.println(gson.toJson(trafficByOidResult));

//            Result portStatusResult = manager.getPortStatus("1.3.6.1.2.1.2.2.1.8.10101");
//            System.out.println("\n=== 测试6. 端口状态 ===");
//            System.out.println(gson.toJson(portStatusResult));

        } catch (IOException e) {
            System.err.println("【严重错误】SNMP连接失败:");
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("【运行时错误】:");
            e.printStackTrace();
        }
    }
}
