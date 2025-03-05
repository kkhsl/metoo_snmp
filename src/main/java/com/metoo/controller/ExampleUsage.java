package com.metoo.controller;

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
                    "test"
            );


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