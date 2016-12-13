import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.util.EntityUtils;
import spark.Response;
import spark.Route;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static spark.Spark.post;

class Credentials {
    String user;
    String password;

    public Boolean filled() {
        return this.user != null && !this.user.isEmpty() && this.password != null&& !this.password.isEmpty();
    }
}

class Session {
    String mybb_user;
    String sid;
}

public class Application {
    private static final String DOMAIN = System.getenv("DOMAIN");
    private static final String LOGIN_URL = DOMAIN + "/forum/member.php";

    private static Route login = (spark.Request request, Response response) -> {
        Credentials credentials;
        try {
            credentials = new GsonBuilder().create().fromJson(request.body(), Credentials.class);
        } catch (JsonSyntaxException e) {
            return Application.error(response, 400, "Could not parse JSON");
        }

        if (!credentials.filled()) {
            return Application.error(response, 400, "Provide parameters user & password as JSON");
        }

        // Send request to myPHP
        HttpResponse myBBResp = Request.Post(LOGIN_URL)
                .bodyForm(Form.form()
                        .add("action", "do_login")
                        .add("remember", "yes")
                        .add("username", credentials.user)
                        .add("password", credentials.password)
                        .build()
                )
                .execute().returnResponse();

        // myBB always sends 200 so if that's not the case something's odd.
        if (myBBResp.getStatusLine().getStatusCode() != 200) {
            return Application.error(response, 500, "Could not deal with myBB");
        }

        // If there are too many attempts we need to manually enter the captcha…
        if (EntityUtils.toString(myBBResp.getEntity()).contains("Verifizierungscode")) {
            return Application.error(response,429, "Enter captcha manually for this user.");
        }


        Stream<Header> cookieHeaders = Arrays.stream(myBBResp.getHeaders("set-cookie"));
        List<HttpCookie> cookies = cookieHeaders.map(cookie -> HttpCookie.parse(cookie.getValue()).get(0)).collect(Collectors.toList());

        // Login is only valid if we get back a user cookie
        HttpCookie userCookie = cookies.stream().filter(cookie -> cookie.getName().equals("mybbuser"))
                .findFirst()
                .orElse(null);
        if (userCookie == null) {
            Application.error(response, 401, "Invalid login credentials.");
        }

        // Finally find the session id
        HttpCookie sid =  cookies.stream().filter(cookie -> cookie.getName().equals("sid"))
                .findFirst()
                .orElse(null);

        if (sid == null) {
            return Application.error(response, 500, "No session ID found from myBB");
        }

        Session ses = new Session();
        ses.sid = sid.getValue();
        ses.mybb_user = userCookie.getValue();
        return new GsonBuilder().create().toJson(ses);
    };

    private static String error(Response response, Integer code, String message) {
        response.status(code);
        response.type("application/json");

        JsonObject errorJson = new JsonObject();
        errorJson.addProperty("error", message);

        return errorJson.toString();

    };

    public static void main(String[] args) {
        post("/", login);
    }
}
