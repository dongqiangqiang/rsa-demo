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


    private final static String CUSTOMER_PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMYhZMIPTLx9ohQ6iSoFbiBFj6TC\n" +
            "o5/LO5dKzkrXQlHM/lnaVBL43PFxVF37HOfqfivgcYUqDAgJObUZMYF4Q06oiM0QDvFJuXcv+2YU\n" +
            "H5K/ikV6U2BgP+XJfa6UXkTgL7WEUFW1MS4qhgOL1vZZRYG4mPleN525vygZw5RNfx5/AgMBAAEC\n" +
            "gYAXLokPe6LK2xg/ramm1QPRmtH3wR5L8AeE6CfC8fS8hXOtJ7J2lc+kIFJyvJLhP7qLf7NIlWba\n" +
            "+dlaqxvzvhKByL7OZo0ki3RwJKX7jsrRbwKu+rSOUSVKEX15A3htCc0inJ1zmR2N6myxUlk14Yqe\n" +
            "B5ExKKeUj7YgRgai4KCkwQJBAPAlR67EsDWtkfAdfVrOaeIj0lABXKQoNkE20ZKBPR/2bwEPFesz\n" +
            "vAVmoqHjTLJFFcrW62BL7JvWwO1vCRxX8akCQQDTNgL/a0TuWtUN/BUq4ccvQe0tI+iRo6n23WpD\n" +
            "Ymv3cAOMu/eXNKGNmU+V3o4vMqXQIz+9y7wXRkiWQ/RQavfnAkBiATTh9E9deLqIXeCcwIShz7Cz\n" +
            "Cfs+21JZBwA8ZBYIB1CCBCAT3wcqxRo2K0dPsbYVE+T3ZcToTJpry9bSBGoRAkEAjsZ+NEdBK5c/\n" +
            "WtrDPF+vlCSOver+NiVaqcR3JuILdhLEc4hFEHPFmcC/aeIuX31vVUnetuBYX6tlOh7pssr8lQJB\n" +
            "AN4DAnQ1f5THUC608DK4rNPtvkEM8cLyKo7K9hMVOWeRK7Iq1GZCq4SkKZ8NGnP3Qwwobxz39EeE\n" +
            "jQ9usydYMn4=";

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");


    private static final String DATA_URL = "http://localhost:8086/cooperation/data/gjj";

    /**
     * RSAUtil.initKey() 生产rsa 私钥，公钥;
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        Long start = System.currentTimeMillis();
        String source = "13333";
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("unionId", "10001");

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


