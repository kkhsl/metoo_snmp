package com.metoo.controller;

import com.alibaba.fastjson.JSONObject;
import com.metoo.sdk.SNMPSDK;
import com.metoo.utils.SNMPException;

public class ExampleUsage {
    public static void main(String[] args) throws SNMPException {
        try {
            SNMPSDK sdk = new SNMPSDK();

            // V2C示例
            Object resultV2C = sdk.operateV2C(
                    "gw",
                    "192.168.6.1",
                    "public@123",
                    null,
                    "1.3.6.1.2.1.1.5.0",
                    "h3c",
                    "get_traffic"
            );
            System.out.println(JSONObject.toJSONString(resultV2C));

//            // V2C示例
//            Object get_traffic = sdk.operateV2C(
//                    "gw",
//                    "192.168.6.1",
//                    "public@123",
//                    null,
//                    "1.3.6.1.2.1.2.2.1.10.195",
//                    "h3c",
//                    "get_traffic"
//            );
//            System.out.println(JSONObject.toJSONString(get_traffic));

            // V2C示例
            Object get_ipv4_port = sdk.operateV2C(
                    "gw",
                    "192.168.6.1",
                    "public@123",
                    "192.168.4.2",
                    "1.3.6.1.2.1.4.20.1.2",
                    "h3c",
                    "get_ipv4_port"
            );
            System.out.println(JSONObject.toJSONString(get_ipv4_port));

            // V2C示例
            Object result = sdk.operateV2C(
                    "gw",
                    "192.168.6.1",
                    "public@123",
                    "2400:3030:aa12:1978::1",
                    "1.3.6.1.2.1.4.32.1.5",
                    "h3c",
                    "get_ipv6_port"
            );
            System.out.println(JSONObject.toJSONString(result));




            // V3示例
            /*Object resultV3 = sdk.operateV3(
                    "switch",
                    "192.168.1.2",
                    null,
                    "1.3.6.1.2.1.1.1",
                    "huawei",
                    "getPortStatus",
                    "admin",
                    3,
                    "SHA",
                    "authPassword",
                    "AES",
                    "privPassword"
            );*/
        } catch (SNMPException e) {
            System.err.println("SNMP Error: " + e.getMessage());
        }
    }
}