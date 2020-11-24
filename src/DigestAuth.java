import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;
import java.util.stream.Collectors;

public class DigestAuth {
    private static String getAuthHeader(String pUrl, String pUser, String pPassword) throws Exception {
        String initHeader = getInitheader(pUrl);
        Properties properties = new Properties();
        properties.putAll(Arrays.stream(initHeader.split("\\s*,\\s*"))
                .map(s -> s.split("=", 2))
                .collect(Collectors.toMap(s -> s[0].toLowerCase(), s -> s[1])));

        String realm = properties.getProperty("digest realm").replaceAll("\"", "");
        String nonce = properties.getProperty("nonce").replaceAll("\"", "");
        String algorithm = properties.getProperty("algorithm").replaceAll("\"", "");
        String opaque = properties.getProperty("opaque").replaceAll("\"", "");
        String qop = properties.getProperty("qop").replaceAll("\"", "");
        String nc = "00000001";
        String cnonce = getCNonce();

        String ha1 = getMD5(pUser, realm, pPassword);
        String ha2 = getMD5("POST", pUrl);
        String response = getMD5(ha1, nonce, nc, cnonce, qop, ha2);

        String result = "Digest" +
                " username=\""   + pUser     + "\"," +
                " realm=\""      + realm     + "\"," +
                " nonce=\""      + nonce     + "\"," +
                " uri=\""        + pUrl      + "\"," +
                " algorithm=\""  + algorithm + "\"," +
                " response=\""   + response  + "\"," +
                " opaque=\""     + opaque    + "\"," +
                " qop=\""        + qop       + "\"," +
                " nc=\""         + nc        + "\"," +
                " cnonce=\""     + cnonce    + "\"";

        return result;
    }

    private static String getCNonce() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++)
            sb.append(Integer.toHexString(new Random().nextInt(16)));

        return sb.toString();
    }

    private static String getMD5(String ... args) {
        String result;
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        String input = String.join(":", args);
        md.update(input.getBytes());

//        result = DatatypeConverter.printHexBinary(md.digest()).toLowerCase();

        StringBuilder sb = new StringBuilder();
        for(byte b: md.digest())
            sb.append(String.format("%02x", b));
        result = sb.toString();

        return result;
    }

    private static String getInitheader(String pUrl) throws Exception {
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(pUrl))
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.headers().map().get("www-authenticate").get(0);
    }

    private static String printHexBinary(byte[] arr) {
        StringBuilder sb = new StringBuilder();
        for(byte b: arr)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}