package main;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public final class RestAuthEntryPoint
    implements AuthenticationEntryPoint {

    @Override
    public void commence(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final AuthenticationException authException){
        System.out.println("Inside AuthenticationEntryPoint.commence");
        try {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Unauthorized");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
