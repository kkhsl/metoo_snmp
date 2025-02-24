package com.metoo.domain;

import java.io.Serializable;

/**
 * <p>
 *     Title: Result.java
 * </p>
 *
 * <p>
 *     Description:响应结果集对象，实现Serializable接口，方便序列化结果
 *     Serializable:作用
 *      启用其序列化功能的接口
 *     序列化的作用
 *      序列化是将对象状态转换为可保持或传输的格式的过程。与序列化相对的是反序列化，它将流转换为对象。这两个过程结合起来，可以轻松地存储和传输数据
 * </p>
 */
public class Result implements Serializable {


    private static final long serialVersionUID = 4267799476339238113L;
    /** 状态码 */
    private Integer code;

    /** 提示信息 */
    private String msg;

    /** 响应数据 */
    private Object data;

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public Result() {
    }

    public Result(String msg) {
        this.msg = msg;
    }

    public Result(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public Result(String msg, Object data) {
        this.msg = msg;
        this.data = data;
    }

    public Result(Integer code, String msg, Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
}
