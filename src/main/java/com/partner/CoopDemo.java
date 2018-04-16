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

    private final static String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCObdeTV5Pga3BhQjglwl23xJGuBw50ElfwHIPP\n" +
            "MKXDYqmm9mmrKpzUnw4TqybiRnmxCTif0gmZmxodcSBRYGiGU0fQRafhxbU8Uph6y0s1m+9TICBq\n" +
            "LJUN9vXzL1FXoxIXP6pmCJ41CqfEiBmGQ3NfYuO291c3WUUv29USkDJlSwIDAQAB";


    private final static String PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAI5t15NXk+BrcGFCOCXCXbfEka4H\n" +
            "DnQSV/Acg88wpcNiqab2aasqnNSfDhOrJuJGebEJOJ/SCZmbGh1xIFFgaIZTR9BFp+HFtTxSmHrL\n" +
            "SzWb71MgIGoslQ329fMvUVejEhc/qmYInjUKp8SIGYZDc19i47b3VzdZRS/b1RKQMmVLAgMBAAEC\n" +
            "gYAKWetP9w51Qfmx59kizWR4RZ380uB3CRpBBiGCPlvdvl7sFn6JhRhOz5x7S3YQ/eQ8PJpT6zTt\n" +
            "Z/tW5nDd2S7fcIPdYk69hHAgCH1Tp27COGFPjjiu1QlpWSqdegsPmviGUI96MgbvIHMNZdjsqYA3\n" +
            "Iai6SYRuTfyBWlywhSWrgQJBAMm+lskMc770xjlC+mYz85y1XBvDEF6nTizAvQ2+VmKZHXHjBfoA\n" +
            "+kYt5zQG7lE3nuVHwvG5ykCvc/yVUzxjvEECQQC0u5dtqJt8v0Do1ZMO6US7C77SeVm2REMeN6Y2\n" +
            "nUohxpJxSlFNmXV+N97kead02MS+VDP37KjlDRbR+JeCV66LAkEAvYeY3t4c6zvH8cmztkp+Ri23\n" +
            "j7lM6q+g6LhVo9C6FT0lhXWzirBab432VFFimNh5JYuqYC+cC/MJMzUSEnzcQQJAZ7cTYkmU2RTE\n" +
            "Ahm2J6Nz3scRvaUH95Ha1ndm+gZvaUyT81GLsLV0+HbFgWXS1DolRXf6zrbQAYnuY5Z+E72PmwJB\n" +
            "AMeTZAx1/xu30QFoDMqCxUUJ1wbRgOcHUWqedeCXyBz65N3tmSsoM6N8F9cnIBjWRyX+re5DlEP1\n" +
            "JRBFCsG2xD4=";


    private final static String CUSTOMER_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCL7dWHO3efNv1t1qGR407nbzYBu07QY7EmzJy9\n" +
            "Ayo1Th0UZBSiqM0pvv3ENoWmSMHgtNt9UzpbTol88hQh9J4CcQNGPcTh37onaPDB++yCPWEKid6l\n" +
            "QMj5No3ijFpiEatPwxYcuguZ+O0VpVUftEu5qUa/0sMN29P/GUh6KyHQUQIDAQAB";

    private final static String CUSTOMER_PRIVATE_KEY = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIvt1Yc7d582/W3WoZHjTudvNgG7\n" +
            "TtBjsSbMnL0DKjVOHRRkFKKozSm+/cQ2haZIweC0231TOltOiXzyFCH0ngJxA0Y9xOHfuido8MH7\n" +
            "7II9YQqJ3qVAyPk2jeKMWmIRq0/DFhy6C5n47RWlVR+0S7mpRr/Sww3b0/8ZSHorIdBRAgMBAAEC\n" +
            "gYBCuxt3sH5tqXXWqeLHhhWc/UZOMRt2+fQDwtSEtzurzCLGFKxanhGpdPHkXvQBxvTeyqFZ9RUB\n" +
            "ckTTF0dOoi+v15nZGWX7LaxncaVs7O3RgW41By1SyaC77y+3Gdm8WM3AnUtCq6b11+EQcAUYg8V1\n" +
            "QWFzJAmbXGluXy5tP23QmQJBAN2pZgUsMN8MLCh6wsKKui1aLmddEFn6m/lUeC//jq692Rb2Astn\n" +
            "nVhxKTcVuRwzO7YMBn+3aA9I5GdQnVTsr7cCQQChmxpVeAmdfZi22IeI+byJMJCBLKAZWSOPIvx9\n" +
            "qzGYJs4T333J7odTWcPDC1F8tJIC1efJpPRVbI/es13L2HA3AkBVwNVRJvl5MPJcbrGuJZFFPmA5\n" +
            "aM2MoeF5oe4lU47Vl2jG80G9g0ZiEtVJFERa3o85LInPGxtM3nxOY+eaFT8dAkAqN9vkUiyo4SPh\n" +
            "OKYHyb5QVMibhm340Umx3iD6L5wQNKsHlA5Hj7H4u22h6bYLDx1J8lnQWvCd1HOtaUxqsYt3AkA3\n" +
            "3wWHnptXgDPzqfVg46h7haarbYymni8dRd8cKTQHpxZBfJR0luaAs2boBUatmOUKzJk3gGMTcNQe\n" +
            "bB3oaoI0";

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");


    private static final String DATA_URL = "http://localhost:8086/cooperation/data/gjj";

    /**
     * RSAUtil.initKey();
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

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


