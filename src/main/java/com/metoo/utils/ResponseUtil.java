package com.metoo.utils;

import com.metoo.domain.Result;

import java.util.HashMap;
import java.util.Map;

public class ResponseUtil {



    public static Object unlogin() {
        return result(401, "Log in");
    }

    public static Object unauthz() {
        return result(403, "Insufficient authority");
    }

    public static Object expired() {
        return result(4011, "Login expired");
    }

    public static Object badArgumentValue() {
        return result(402, "Parameter error");
    }

    public static Object nullPointException() {
        return result(402, "Data does not exist");
    }

    public static Object arithmeticException() {
        return result(402, "Data exception");
    }

    public static Object serious() {
        return result(502, "SystemTest error");
    }

    public static Object httpRequestMethodNotSupportedException() {
        return new Result(405, "Method Not Allowed");
    }

    public static Object fileNotFoundException() {
        return new Result(1, "fileNotFound");
    }

    public static Object add() {
        return new Result(200, "Successfully added");
    }

    public static Result badArgument() { return fail(400, "参数错误");}

    public static Result badArgument(String message) { return fail(400, message);} //未找到指定资源

    public static Object badArgument(int code, String message) { return fail(code, message);} //未找到指定资源

    public static Object update() {
        return new Result(200, "Modify successfully");
    }

    public static Object delete() {
        return new Result(200, "Successfully delete");
    }

    public static Object query(Map data) {
        return new Result(200, "Successfully query", data);
    }
    public static Object query() {
        return new Result(200, "Successfully query");
    }

    public static Object prohibitDel() {
        return new Result(501, "Cannot delete, delete the associated item first");
    }

    public static Result error() { return new Result(500, "保存失败");  }

    public static Result error(String message) { return new Result(500, message);  }

    public static Result fail(String data) {
        return new Result(500, data);
    }

    public static Result ok(){return new Result(200, "Successfully");}

    public static Result ok(Object data){return new Result(200, "Successfully", data);}

    public static Result ok(Integer code, String msg, Object data){return new Result(code, msg, data);}

    public static Result ok(String msg, Object data){return new Result(200, msg, data);}

    public static Object notFound(){return new Result(404, "请求的资源不存在");}

    public static Object ok(boolean flag){
        if(flag){
            return new Result(200, "保存成功");
        }
        return new Result(500, "保存失败");
    }

    public static Object noContent(){return new Result(204, "Successfully");}

    public static Result fail(int errno, String errmsg) {
        Result obj = new Result(errno, errmsg);
        return obj;
    }

    public static Object result(int errno, String errmsg) {
        Result obj = new Result(errno, errmsg);
        return obj;
    }
}
