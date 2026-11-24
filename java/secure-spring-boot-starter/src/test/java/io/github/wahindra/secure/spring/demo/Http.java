package io.github.wahindra.secure.spring.demo;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** Plain HTTP client for the tests; avoids test helpers that differ between Spring Boot 3 and 4. */
final class Http {

    private static final HttpClient CLIENT = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private Http() {
    }

    static HttpResponse<String> send(String method, String url, String body, String... headers) throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        return CLIENT.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static HttpResponse<String> get(String url, String... headers) throws IOException, InterruptedException {
        return send("GET", url, null, headers);
    }
}
