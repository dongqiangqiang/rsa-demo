package com.partner;

import com.RsaService;
import com.alibaba.fastjson.JSONObject;
import com.utils.RSAUtil;
import okhttp3.*;

import java.io.IOException;

/**
 * Hello world!
 */
public class CoopDemo {

    private static RsaService rsaService = new RsaService();

    private final static String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaglR4wSka+Eqn/QsD+sWGGxKbIt6fhMbUfJc0\n" +
            "nvFp9Xu/M2hS+Yim0EqMpKsOX8ZcFjZinkxDpbJ1YvmOCmgJatn9C/DQoNfS+PqVCD1NvwgjjqMk\n" +
            "R0HGn5OYIp+Na4OwSzfAZhf+dQ1LPJ5u7t9SAi07QDakZTstDMAqaWXN5QIDAQAB";


    private final static String CUSTOMER_PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAI5ZNwF2bnr6NHzZUq1mJzhQpWWS\n" +
            "GCzCIe7rgANM6+jTOf4JWQopPQH8BCFsqZnhCquplG7GlAYrYR4m9dOUCVV80XtQXC2BFVhKzKzr\n" +
            "Pyc9kct0Vu7N/zuPGb+rgf/gs6/cqUX58ETBZR8Cg7H5xS0aDfrDmPtGHf7byRS3ZLTZAgMBAAEC\n" +
            "gYAtf+7JFOXzgQ5N6dk3e7OFmKGFedEoXVUjXTsp0uiFHx8mSC6hxNSvUbKwTF9ZxEj43deIIQkn\n" +
            "f64nSSTCYEsq/SfBJWcFCd6O+iIQ7E4tzwFZh3p++I/6UmbWDvbnPAs/EElcy2bBtDMS5KfDRrMe\n" +
            "WHCHYkc+xEjAgDFCWltH0QJBAP1mn2n1VbkpBJDHhNuaQukZqlg2tih+8O+g3dLWErmDqoGoTmWb\n" +
            "NzM9/BE94K7zKoJFr16ZtVWZYQSpRPLXtSsCQQCPzv31EIjffVo4OSFu1IbmcauVy5MwcHeQ8JdH\n" +
            "IqLdJgLFOKGuyIzC79xoXjYCisZf38Ku+Uv1N3g84IakwcQLAkEA9af9N01900kugeTKqdI8t5oI\n" +
            "CAjSQyP9E3HSWkjqUiqQq62sgtgchXK74UMphLF8Llq8DmvY3akZ4tjuXLY9jQJAZXi140zGd4P4\n" +
            "vAE74PsfMM12OB1L/3rsMx5AcBY1evwOKmE6XJzwDcC38gC/9W08anv14AbSHPYF5la7StfaXwJB\n" +
            "ANPdpfMSoC2dumYzqY6qp2DS+MoblFTuf4XOvXgUxrWuVaE/k6HBW9EqkgmsL+iAhzqKRmWAz+Rz\n" +
            "6s8lUFkMZdc=";

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");


    private static final String DATA_URL = "http://localhost:8086/cooperation/data/gjj";

    /**
     * RSAUtil.initKey();
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
//        RSAUtil.initKey();
        Long start = System.currentTimeMillis();
        String source = "13333";
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("userId", "10001");

        String data = rsaService.encrypt(PUBLIC_KEY, JSONObject.toJSONString(jsonObject));
        String signnature = RSAUtil.sign(CUSTOMER_PRIVATE_KEY, "ccb", data);

        JSONObject object = new JSONObject();
        object.put("data", data);
        object.put("signature", signnature);
        object.put("source", source);

        String requestJson = JSONObject.toJSONString(object);
        System.out.println("requestJson-->" + requestJson);


        OkHttpClient okHttpClient = new OkHttpClient();
        RequestBody requestBody = RequestBody.create(JSON, requestJson);
        Request request = new Request.Builder()
                .url(DATA_URL)
                .post(requestBody)
                .build();
        try {
            Response response = okHttpClient.newCall(request).execute();
            if (response.isSuccessful()) {

                String responseData = response.body().string();
                System.out.println(responseData);
                JSONObject jsonObject1 = JSONObject.parseObject(responseData);
                if (jsonObject1 != null && jsonObject1.getInteger("code") == 1) {
                    responseData = jsonObject1.getString("results");
                    System.out.println(rsaService.decrypt(CUSTOMER_PRIVATE_KEY, responseData));
                }
            }

            System.out.println("time-->:" + (System.currentTimeMillis() - start));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


